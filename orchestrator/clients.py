"""에이전트 클라이언트 이음새(seam) — VM C가 VM A/B와 대화하는 인터페이스.

VM A(공격자)와 VM B(방어자)는 다른 서버·다른 메시지 집합이라 두 Protocol로 분리.
이 파일은 '계약'만 정의한다(작은 인터페이스). 실제 구현은 두 가지가 이 계약을 만족:
  - 실 어댑터: requests로 HTTP POST (orchestrator/http_clients.py, 다음 단계)
  - 인메모리 fake: 테스트·오프라인 드라이런 (orchestrator/fakes.py)

메서드는 payload 모델을 받아 응답 payload 모델을 돌려준다(봉투 wrap/parse는 어댑터 내부).
episode·round는 봉투 메타라 호출 시 함께 넘긴다.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from common.messages import (
    AgentStatus,
    AttackTurnResult, AttackTurnStart,
    DefenseTurnResult, DefenseTurnStart,
    HealthCheck, HealthResult,
    ReplayRequest, ReplayResult,
    StateQuery, StateQueryResult,
)


@runtime_checkable
class AttackerClient(Protocol):
    """VM A(공격 하네스)와의 계약. 공격 턴 지시 + 리플레이 재생 위임 + 상태 조회."""

    def attack_turn(self, start: AttackTurnStart, *, episode: int, round: int) -> AttackTurnResult:
        """공격 턴을 돌리고(탈옥 LLM ReAct) 결과+리플레이 대본을 받는다."""
        ...

    def replay(self, req: ReplayRequest, *, episode: int, round: int) -> ReplayResult:
        """저장된 대본을 LLM 없이 결정론적으로 재생(검증용). pre/post phase 포함."""
        ...

    def status(self) -> AgentStatus:
        """하트비트·에러 상태(에이전트 장애 감지용)."""
        ...


@runtime_checkable
class DefenderClient(Protocol):
    """VM B(방어 하네스)와의 계약. 방어 턴 지시 + 상태검증 질의 + 가용성 확인."""

    def defense_turn(self, start: DefenseTurnStart, *, episode: int, round: int) -> DefenseTurnResult:
        """방어 턴을 돌리고(관측→트리아지→패치) 결과를 받는다. 공격 정보는 안 줌."""
        ...

    def state_query(self, query: StateQuery, *, episode: int, round: int) -> StateQueryResult:
        """클러스터 내부 관점 상태 조회(예: 특정 SA 권한). 사실만, 판정은 VM C."""
        ...

    def health_check(self, hc: HealthCheck, *, episode: int, round: int) -> HealthResult:
        """패치 후 서비스 가용성 확인(과잉 차단으로 서비스 죽었나)."""
        ...

    def status(self) -> AgentStatus:
        ...


__all__ = ["AttackerClient", "DefenderClient"]
