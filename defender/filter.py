"""1차 필터 — baseline/룰로 노이즈를 걷어 '상황 보고서'를 만든다 (기계적, LLM 아님).

방어자의 '눈' 2단: 넓은 로그 바다에서 의심 후보만 추려 LLM이 볼 간추린 JSON으로 압축.
- 감사: 인프라 시스템 액터(apiserver·kube-*·node) 노이즈 제거 → (user,verb,resource,ns)로
  묶어 횟수 집계. (감사 정책이 소스에서 이미 secrets·exec·RBAC만 남기므로 남은 건 대체로 의미 有)
- Falco: rule로 묶어 집계, 우선순위 순.
- [Phase A] 앱: common.app_signals 로 요청을 웹 공격 기법으로 분류(god-view 와 같은 키) → (svc,
  technique)로 집계. LLM 이 그 technique 를 detected[].mitre 로 그대로 보고하면 truth 와 맞물린다.
LLM 트리아지는 이 보고서만 본다(원시 로그 전체 아님) → 로컬 모델 부담·노이즈 축소.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from common.app_signals import classify
from .observer import Observation

# 인프라 시스템 액터(공격자 아님) — 접두 일치 시 감사 노이즈로 간주해 제거.
# 주의: serviceaccount(admin-sa 등)·일반 유저는 남긴다(공격 신호일 수 있음).
_SYSTEM_PREFIXES = (
    "system:apiserver",
    "system:kube-scheduler",
    "system:kube-controller-manager",
    "system:kube-proxy",
    "system:node:",
    "system:serviceaccount:kube-system",
    "system:serviceaccount:kube-node-lease",
)

_PRIORITY_RANK = {
    "emergency": 7, "alert": 6, "critical": 5, "error": 4,
    "warning": 3, "notice": 2, "informational": 1, "info": 1, "debug": 0,
}


@dataclass
class AuditHighlight:
    user: str
    verb: str
    resource: str
    namespace: str
    count: int
    sample_reason: str = ""


@dataclass
class FalcoHighlight:
    rule: str
    priority: str
    count: int
    sample_output: str = ""


@dataclass
class AppHighlight:
    svc: str
    technique: str      # WEB_SQLI 등 — 방어자가 detected[].mitre 로 그대로 보고(truth 와 키 일치)
    count: int
    sample_path: str = ""


@dataclass
class SituationReport:
    since_ts: float
    until_ts: float
    audit_highlights: list[AuditHighlight] = field(default_factory=list)
    falco_highlights: list[FalcoHighlight] = field(default_factory=list)
    app_highlights: list[AppHighlight] = field(default_factory=list)
    total_audit: int = 0        # 노이즈 제거 후 감사 이벤트 총수
    total_falco: int = 0
    total_app: int = 0          # 웹 공격으로 분류된 앱 요청 총수

    def is_quiet(self) -> bool:
        return (not self.audit_highlights and not self.falco_highlights
                and not self.app_highlights)

    def to_prompt_dict(self) -> dict:
        """LLM 프롬프트에 넣을 간추린 형태(원시 로그 대신 이것만 준다)."""
        return {
            "window_sec": round(self.until_ts - self.since_ts, 1),
            "audit": [{"user": h.user, "verb": h.verb, "resource": h.resource,
                       "namespace": h.namespace, "count": h.count,
                       "reason": h.sample_reason} for h in self.audit_highlights],
            "falco": [{"rule": h.rule, "priority": h.priority, "count": h.count,
                       "sample": h.sample_output} for h in self.falco_highlights],
            "app": [{"svc": h.svc, "technique": h.technique, "count": h.count,
                     "sample_path": h.sample_path} for h in self.app_highlights],
        }


def _is_system_user(user: str) -> bool:
    return any(user.startswith(p) for p in _SYSTEM_PREFIXES)


def filter_observations(obs: Observation) -> SituationReport:
    """Observation → SituationReport. 노이즈 제거 + 집계(결정적 정렬)."""
    # ── 감사: 시스템 액터 제거 후 (user,verb,resource,ns)로 집계 ──
    agg: dict[tuple, dict] = {}
    kept = 0
    for e in obs.audit:
        if _is_system_user(e.user):
            continue
        kept += 1
        key = (e.user, e.verb, e.resource, e.namespace)
        slot = agg.setdefault(key, {"count": 0, "reason": e.reason})
        slot["count"] += 1
        if not slot["reason"] and e.reason:
            slot["reason"] = e.reason
    audit_h = [AuditHighlight(user=k[0], verb=k[1], resource=k[2], namespace=k[3],
                              count=v["count"], sample_reason=v["reason"])
               for k, v in agg.items()]
    audit_h.sort(key=lambda h: (-h.count, h.user, h.verb, h.resource))

    # ── Falco: rule로 집계 ──
    fagg: dict[str, dict] = {}
    for f in obs.falco:
        slot = fagg.setdefault(f.rule, {"count": 0, "priority": f.priority, "output": f.output})
        slot["count"] += 1
    falco_h = [FalcoHighlight(rule=r, priority=v["priority"], count=v["count"],
                              sample_output=v["output"])
               for r, v in fagg.items()]
    falco_h.sort(key=lambda h: (-_PRIORITY_RANK.get(h.priority.lower(), 0), -h.count, h.rule))

    # ── [Phase A] 앱: 웹 공격 기법으로 분류 후 (svc,technique)로 집계 ──
    aapp: dict[tuple, dict] = {}
    app_kept = 0
    for a in obs.app:
        tech = classify(a.path, a.query, a.url or None)
        if tech is None:
            continue
        app_kept += 1
        key = (a.svc, tech)
        slot = aapp.setdefault(key, {"count": 0, "path": a.path})
        slot["count"] += 1
    app_h = [AppHighlight(svc=k[0], technique=k[1], count=v["count"], sample_path=v["path"])
             for k, v in aapp.items()]
    app_h.sort(key=lambda h: (-h.count, h.svc, h.technique))

    return SituationReport(
        since_ts=obs.since_ts, until_ts=obs.until_ts,
        audit_highlights=audit_h, falco_highlights=falco_h, app_highlights=app_h,
        total_audit=kept, total_falco=len(obs.falco), total_app=app_kept)


__all__ = ["AuditHighlight", "FalcoHighlight", "AppHighlight", "SituationReport",
           "filter_observations"]
