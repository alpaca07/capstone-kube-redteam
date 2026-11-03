"""관측 레이어 — 감사로그 + Falco + 앱 감사 로그를 구조화해 증분 수집.

방어자의 '눈' 1단: 원시 로그 → 구조화된 Observation(이번 라운드에 새로 생긴 것만).
시간 파싱은 common.k8s_logs 공유. 로그 읽기(I/O)는 LineReader 주입 → fake로 테스트.
[Phase A] 앱 감사 로그(서비스 after_request JSON)도 수집 → 웹 공격(SQLi·SSRF·cmdi·cred-leak)
관측. 분류는 filter 에서 common.app_signals 로(god-view 와 같은 키).
상태 diff(클러스터 현재 상태 vs baseline)는 ClusterClient 필요 → triage 파이프라인 단계에서 합류.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from common.k8s_logs import audit_ts, falco_ts, parse_rfc3339

LineReader = Callable[[], Iterable[str]]


@dataclass
class AuditEntry:
    timestamp: float
    user: str
    verb: str
    resource: str
    namespace: str = ""
    name: str = ""
    decision: str = ""          # allow / forbid (authorization.k8s.io/decision)
    reason: str = ""            # RBAC 허용 사유(authorization.k8s.io/reason)


@dataclass
class FalcoEvent:
    timestamp: float
    rule: str
    priority: str = ""
    output: str = ""
    fields: dict = field(default_factory=dict)


@dataclass
class AppEntry:
    """서비스 앱 감사 로그 1줄(after_request JSON)."""
    timestamp: float
    svc: str
    path: str
    query: str = ""
    url: str = ""
    status: int = 0


@dataclass
class Observation:
    since_ts: float
    until_ts: float
    audit: list[AuditEntry] = field(default_factory=list)
    falco: list[FalcoEvent] = field(default_factory=list)
    app: list[AppEntry] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not self.audit and not self.falco and not self.app


def _loads(line: str) -> Optional[dict]:
    try:
        obj = json.loads(line)
        return obj if isinstance(obj, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def parse_audit_line(line: str) -> Optional[AuditEntry]:
    """k3s 감사 JSON 한 줄 → AuditEntry. 파싱 불가/타임스탬프 없음이면 None."""
    ev = _loads(line)
    if ev is None:
        return None
    ts = audit_ts(ev)
    if ts is None:
        return None
    ann = ev.get("annotations") or {}
    obj_ref = ev.get("objectRef") or {}
    return AuditEntry(
        timestamp=ts,
        user=(ev.get("user") or {}).get("username", ""),
        verb=ev.get("verb", ""),
        resource=obj_ref.get("resource", ""),
        namespace=obj_ref.get("namespace", ""),
        name=obj_ref.get("name", ""),
        decision=ann.get("authorization.k8s.io/decision", ""),
        reason=ann.get("authorization.k8s.io/reason", ""))


def parse_falco_line(line: str) -> Optional[FalcoEvent]:
    """Falco JSON 한 줄 → FalcoEvent. 파싱 불가/타임스탬프 없음이면 None."""
    ev = _loads(line)
    if ev is None:
        return None
    ts = falco_ts(ev)
    if ts is None:
        return None
    return FalcoEvent(
        timestamp=ts,
        rule=ev.get("rule", ""),
        priority=ev.get("priority", ""),
        output=ev.get("output", ""),
        fields=ev.get("output_fields") or {})


def parse_app_line(line: str) -> Optional[AppEntry]:
    """서비스 앱 감사 JSON 한 줄 → AppEntry. src!=app·타임스탬프 없음이면 None."""
    ev = _loads(line)
    if ev is None or ev.get("src") != "app":
        return None
    ts = parse_rfc3339(ev.get("ts", ""))
    if ts is None:
        return None
    return AppEntry(
        timestamp=ts, svc=ev.get("svc", ""), path=ev.get("path", ""),
        query=ev.get("query", "") or "", url=ev.get("url", "") or "",
        status=int(ev.get("status", 0) or 0))


class Observer:
    """감사/Falco/앱 로그를 증분 수집. since_ts 이후 ~ until_ts 이하만. app_reader 없으면 앱 생략."""

    def __init__(self, audit_reader: LineReader, falco_reader: LineReader,
                 app_reader: Optional[LineReader] = None) -> None:
        self.audit_reader = audit_reader
        self.falco_reader = falco_reader
        self.app_reader = app_reader

    def collect(self, *, since_ts: float, until_ts: Optional[float] = None) -> Observation:
        hi = until_ts if until_ts is not None else float("inf")
        audit: list[AuditEntry] = []
        for line in self.audit_reader():
            e = parse_audit_line(line)
            if e is not None and since_ts < e.timestamp <= hi:
                audit.append(e)
        falco: list[FalcoEvent] = []
        for line in self.falco_reader():
            f = parse_falco_line(line)
            if f is not None and since_ts < f.timestamp <= hi:
                falco.append(f)
        app: list[AppEntry] = []
        if self.app_reader is not None:
            for line in self.app_reader():
                a = parse_app_line(line)
                if a is not None and since_ts < a.timestamp <= hi:
                    app.append(a)

        if until_ts is not None:
            end = until_ts
        else:                              # 윗경계 미지정 → 관측된 최대 ts(없으면 since_ts)
            seen = ([e.timestamp for e in audit] + [f.timestamp for f in falco]
                    + [a.timestamp for a in app])
            end = max(seen) if seen else since_ts
        return Observation(since_ts=since_ts, until_ts=end, audit=audit, falco=falco, app=app)


__all__ = ["AuditEntry", "FalcoEvent", "AppEntry", "Observation",
           "parse_audit_line", "parse_falco_line", "parse_app_line", "Observer"]
