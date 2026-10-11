"""1차 필터 — baseline/룰로 노이즈를 걷어 '상황 보고서'를 만든다 (기계적, LLM 아님).

방어자의 '눈' 2단: 넓은 로그 바다에서 의심 후보만 추려 LLM이 볼 간추린 JSON으로 압축.
- 감사: 인프라 시스템 액터(apiserver·kube-*·node) 노이즈 제거 → (user,verb,resource,ns)로
  묶어 횟수 집계. (감사 정책이 소스에서 이미 secrets·exec·RBAC만 남기므로 남은 건 대체로 의미 有)
- Falco: rule로 묶어 집계, 우선순위 순.
LLM 트리아지는 이 보고서만 본다(원시 로그 전체 아님) → 로컬 모델 부담·노이즈 축소.
"""
from __future__ import annotations

from dataclasses import dataclass, field

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
class SituationReport:
    since_ts: float
    until_ts: float
    audit_highlights: list[AuditHighlight] = field(default_factory=list)
    falco_highlights: list[FalcoHighlight] = field(default_factory=list)
    total_audit: int = 0        # 노이즈 제거 후 감사 이벤트 총수
    total_falco: int = 0

    def is_quiet(self) -> bool:
        return not self.audit_highlights and not self.falco_highlights

    def to_prompt_dict(self) -> dict:
        """LLM 프롬프트에 넣을 간추린 형태(원시 로그 대신 이것만 준다)."""
        return {
            "window_sec": round(self.until_ts - self.since_ts, 1),
            "audit": [{"user": h.user, "verb": h.verb, "resource": h.resource,
                       "namespace": h.namespace, "count": h.count,
                       "reason": h.sample_reason} for h in self.audit_highlights],
            "falco": [{"rule": h.rule, "priority": h.priority, "count": h.count,
                       "sample": h.sample_output} for h in self.falco_highlights],
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

    return SituationReport(
        since_ts=obs.since_ts, until_ts=obs.until_ts,
        audit_highlights=audit_h, falco_highlights=falco_h,
        total_audit=kept, total_falco=len(obs.falco))


__all__ = ["AuditHighlight", "FalcoHighlight", "SituationReport", "filter_observations"]
