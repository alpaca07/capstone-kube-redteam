"""실 어댑터 — k3s 감사로그 + Falco 로그를 god-view로 읽어 MITRE 기법을 뽑는 LogSource.

Protocol(logs.py) 뒤에 끼우는 실제 층. 설계 핵심: '로그 줄 → 기법 매핑'의 순수 로직과
'파일 읽기 I/O'를 분리한다. line reader(주입 가능)만 교체하면 샘플 로그로 매핑을 테스트할
수 있고, 실전에선 파일에서 읽는다. VM C는 공격받는 VM B를 안 거치고 로그를 직접 읽는다
(위조·누락 방지). 탐지는 의도적으로 불완전 — 여기 매핑되는 기법만 '관측 가능'(나머지는 사각).

관측 매핑(환경 구축 observability 문서와 일치):
  ② 감사로그: admin-sa 가 secret get/list → T1078 (가장 선명)
  Falco:      컨테이너 셸 → T1059
  ①(wiki HTTP 열람)·③(pod-to-pod)는 기본 관측 사각 → 로그로는 안 잡힘(설계 의도).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Callable, Iterable, Optional

# 로그 줄(JSON)을 순서대로 내놓는 콜백. 호출마다 새로 순회 가능해야 함.
LineReader = Callable[[], Iterable[str]]

_ADMIN_SA = "system:serviceaccount:internal:admin-sa"
_SECRET_VERBS = {"get", "list", "watch"}


# ───────────── 시간 파싱 ─────────────
def parse_rfc3339(s: str) -> Optional[float]:
    """RFC3339(…Z, 나노초 포함)를 epoch 초로. 파싱 실패 시 None."""
    if not s:
        return None
    t = s.strip().replace("Z", "+00:00")
    # 소수부가 7자리 이상(Falco 나노초)이면 6자리로 절단(fromisoformat 한계)
    if "." in t:
        head, _, tail = t.partition(".")
        frac = ""
        tzpart = ""
        for i, ch in enumerate(tail):
            if ch.isdigit():
                frac += ch
            else:
                tzpart = tail[i:]
                break
        frac = frac[:6]
        t = f"{head}.{frac}{tzpart}" if frac else head + tzpart
    try:
        dt = datetime.fromisoformat(t)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


# ───────────── 순수 매핑 ─────────────
def map_audit_event(ev: dict) -> Optional[str]:
    """k3s 감사 이벤트 → MITRE 기법. 현재 ②(admin-sa secret 접근)만 매핑."""
    user = (ev.get("user") or {}).get("username", "")
    verb = ev.get("verb", "")
    resource = (ev.get("objectRef") or {}).get("resource", "")
    if user == _ADMIN_SA and resource == "secrets" and verb in _SECRET_VERBS:
        return "T1078"   # ② 과권한 SA
    return None


def map_falco_event(ev: dict) -> Optional[str]:
    """Falco 이벤트 → MITRE 기법. 현재 컨테이너 셸만 매핑."""
    rule = ev.get("rule", "")
    if rule == "Terminal shell in container":
        return "T1059"   # 명령/스크립트 실행
    return None


def _audit_ts(ev: dict) -> Optional[float]:
    return parse_rfc3339(ev.get("requestReceivedTimestamp")
                         or ev.get("stageTimestamp") or "")


def _falco_ts(ev: dict) -> Optional[float]:
    return parse_rfc3339(ev.get("time", ""))


def _loads(line: str) -> Optional[dict]:
    try:
        obj = json.loads(line)
        return obj if isinstance(obj, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


# ───────────── reader ─────────────
def file_line_reader(path: str) -> LineReader:
    """파일에서 줄 단위로 읽는 기본 reader. 파일 없으면 빈 순회."""
    def _r() -> Iterable[str]:
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    yield line
        except FileNotFoundError:
            return
    return _r


class AuditFalcoLogSource:
    """감사 + Falco 로그를 god-view로 조회. 시간창 내 관측 기법 집합을 반환."""

    def __init__(self, audit_reader: LineReader, falco_reader: LineReader) -> None:
        self.audit_reader = audit_reader
        self.falco_reader = falco_reader

    def techniques_in_window(self, *, since_ts: float, until_ts: float) -> set[str]:
        out: set[str] = set()
        for line in self.audit_reader():
            ev = _loads(line)
            if ev is None:
                continue
            ts = _audit_ts(ev)
            if ts is None or not (since_ts <= ts <= until_ts):
                continue
            t = map_audit_event(ev)
            if t:
                out.add(t)
        for line in self.falco_reader():
            ev = _loads(line)
            if ev is None:
                continue
            ts = _falco_ts(ev)
            if ts is None or not (since_ts <= ts <= until_ts):
                continue
            t = map_falco_event(ev)
            if t:
                out.add(t)
        return out


__all__ = [
    "LineReader", "parse_rfc3339", "map_audit_event", "map_falco_event",
    "file_line_reader", "AuditFalcoLogSource",
]
