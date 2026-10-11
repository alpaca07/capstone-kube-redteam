"""VM B 방어 하네스 — 턴 로직 배선(DefenseHarness). HTTP(FastAPI) 바인딩은 배포 층에서.

관측→필터→triage→패치 파이프라인을 묶어 VM C의 4개 메시지에 응답:
  defense_turn_start → defense_turn_result (관측·추론·패치, 공격정보 0으로 자력 추론)
  state_query        → state_query_result  (사실만)
  health_check       → health_result       (서비스 가용성)
  status             → agent_status        (하트비트)

컴포넌트(observer/triager/patcher/state_handler/cluster)를 주입받는다 → fake로 전체 테스트.
실제 LLM·kubectl 배선과 FastAPI 라우트(create_app)는 다음 단계(실 어댑터)에서.
"""
from __future__ import annotations

import time
from typing import Optional

from common.messages import (
    AgentRole, AgentState, AgentStatus,
    DefenseEndReason, DefenseTurnResult, DefenseTurnStart, Detection,
    HealthCheck, HealthResult, PatchItem, StateQuery, StateQueryResult,
)

from .filter import filter_observations
from .observer import Observer
from .patcher import Patcher
from .state_query import StateQueryHandler
from .triage import Triager


def _patch_kind(action: str) -> str:
    a = action.lower()
    if "network" in a or "netpol" in a:
        return "networkpolicy"
    if "rbac" in a or "role" in a:
        return "rbac"
    if "pod" in a:
        return "pod"
    if "secret" in a:
        return "secret"
    return action or "patch"


class DefenseHarness:
    """방어 턴 로직. 상태는 증분 로그 커서만 보유(에이전트는 stateless 지향)."""

    def __init__(self, *, observer: Observer, triager: Triager, patcher: Patcher,
                 state_handler: StateQueryHandler, cluster, service: str = "all") -> None:
        self.observer = observer
        self.triager = triager
        self.patcher = patcher
        self.state_handler = state_handler
        self.cluster = cluster              # health_check용(healthcheck())
        self.service = service
        self._cursor: float = 0.0           # 마지막으로 본 로그 시각(증분 관측)

    # ── defense_turn_start → defense_turn_result ──
    def defense_turn(self, start: DefenseTurnStart, *, episode: int, round: int) -> DefenseTurnResult:
        t0 = time.time()
        try:
            obs = self.observer.collect(since_ts=self._cursor)
            self._cursor = max(self._cursor, obs.until_ts)          # 커서 전진(다음 라운드 증분)
            report = filter_observations(obs)
            triage = self.triager.triage(report)                   # LLM(공격정보 없이 자력 추론)
            outcome = self.patcher.apply_plan(triage.patch_plan)

            detected = [Detection(technique=d.mitre, evidence=d.evidence) for d in triage.detected]
            patch_set = [PatchItem(kind=_patch_kind(a.action), target=a.target, summary=a.detail)
                         for a in outcome.applied if a.ok]
            end = DefenseEndReason.PATCHED if outcome.patch_applied else DefenseEndReason.NOOP
            return DefenseTurnResult(
                patch_applied=outcome.patch_applied, end_reason=end,
                detected=detected, patch_set=patch_set,
                healthcheck_passed=outcome.healthcheck_passed,
                elapsed_sec=time.time() - t0)
        except Exception as e:              # noqa: BLE001 — 하네스 오류는 ERROR로 보고(루프 보호)
            return DefenseTurnResult(
                patch_applied=False, end_reason=DefenseEndReason.ERROR,
                detected=[], patch_set=[], healthcheck_passed=True,
                elapsed_sec=time.time() - t0)

    # ── state_query → state_query_result ──
    def state_query(self, query: StateQuery, *, episode: int, round: int) -> StateQueryResult:
        return self.state_handler.handle(query)

    # ── health_check → health_result ──
    def health_check(self, hc: HealthCheck, *, episode: int, round: int) -> HealthResult:
        t0 = time.time()
        try:
            r = self.cluster.healthcheck()
            healthy = bool(getattr(r, "ok", False))
        except Exception:                   # noqa: BLE001
            healthy = False
        return HealthResult(service=hc.service, healthy=healthy,
                            response_time_ms=(time.time() - t0) * 1000.0)

    def status(self) -> AgentStatus:
        return AgentStatus(agent=AgentRole.DEFENDER, state=AgentState.IDLE)


__all__ = ["DefenseHarness"]
