"""인메모리 fake 어댑터 — 세 이음새(스냅샷·공격자·방어자)의 테스트/드라이런용 구현.

실제 VM·하이퍼바이저 없이 검증 엔진과 시퀀서를 돌려보기 위한 '큰 어댑터·작은 구현'.
프로그래머블: 테스트가 재생 결과·상태취약 여부를 미리 심어두고, 호출 순서를 검사한다.
"""
from __future__ import annotations

from typing import Optional

from common.messages import (
    AgentRole, AgentState, AgentStatus,
    AttackTurnResult, AttackTurnStart,
    DefenseTurnResult, DefenseTurnStart,
    HealthCheck, HealthResult,
    ReplayPhase, ReplayRequest, ReplayResult,
    StateCheckResult, StateQuery, StateQueryResult,
)


class FakeSnapshotManager:
    """스냅샷 호출 순서와 '현재 상태'만 추적. 실제 되돌림은 없음."""

    def __init__(self, existing: Optional[list[str]] = None) -> None:
        self._snaps: set[str] = set(existing or [])
        self.calls: list[tuple[str, str]] = []   # (op, name) 순서 기록
        self.current: Optional[str] = None

    def save(self, name: str) -> None:
        self._snaps.add(name)
        self.calls.append(("save", name))

    def revert_to(self, name: str) -> None:
        self.calls.append(("revert_to", name))
        self.current = name

    def delete(self, name: str) -> None:
        self._snaps.discard(name)
        self.calls.append(("delete", name))

    def list(self) -> list[str]:
        return sorted(self._snaps)

    @property
    def ops(self) -> list[str]:
        """연산 순서만(이름 제외) — 춤사위 검사용."""
        return [op for op, _ in self.calls]


class FakeBaseline:
    """k8s 네이티브 리셋 fake(A2). reset_to_clean 횟수 + (op,name) 순서를 추적(실제 리셋 없음).
    SnapshotManager 자리에도 끼우게 revert_to/save/delete/list 어댑터 제공(에피소드 init 호환).
    calls 는 스냅샷 스타일 튜플 — 기존 'revert_to' 단언과 호환."""

    def __init__(self, existing: Optional[list[str]] = None) -> None:
        self.reset_calls = 0
        self.calls: list[tuple[str, str]] = []

    def reset_to_clean(self) -> None:
        self.reset_calls += 1

    def revert_to(self, name: str) -> None:       # 시퀀서 에피소드 init → 클린 리셋과 동일
        self.calls.append(("revert_to", name))
        self.reset_to_clean()

    def save(self, name: str) -> None:            # A2 엔 불필요(no-op, 호환용)
        self.calls.append(("save", name))

    def delete(self, name: str) -> None:
        self.calls.append(("delete", name))

    def list(self) -> list[str]:
        return ["clean-baseline"]


class FakeAttackerClient:
    """공격자 fake. replay 결과를 phase별로 미리 심어둔다."""

    def __init__(self, replay_by_phase: Optional[dict[ReplayPhase, ReplayResult]] = None,
                 attack_result: Optional[AttackTurnResult] = None,
                 status: Optional[AgentStatus] = None) -> None:
        self.replay_by_phase: dict[ReplayPhase, ReplayResult] = replay_by_phase or {}
        self._attack_result = attack_result
        self._status = status or AgentStatus(agent=AgentRole.ATTACKER, state=AgentState.IDLE)
        self.replay_calls: list[tuple[ReplayPhase, int, int]] = []
        self.attack_calls: list[tuple[int, int, AttackTurnStart]] = []

    def attack_turn(self, start: AttackTurnStart, *, episode: int, round: int) -> AttackTurnResult:
        self.attack_calls.append((episode, round, start))
        if self._attack_result is None:
            raise RuntimeError("FakeAttackerClient: attack_result 미설정")
        return self._attack_result

    def replay(self, req: ReplayRequest, *, episode: int, round: int) -> ReplayResult:
        self.replay_calls.append((req.phase, episode, round))
        res = self.replay_by_phase.get(req.phase)
        if res is None:
            raise RuntimeError(f"FakeAttackerClient: {req.phase} 재생 결과 미설정")
        return res

    def status(self) -> AgentStatus:
        return self._status


class FakeDefenderClient:
    """방어자 fake. state_query의 check_id별 취약 여부를 미리 심어둔다."""

    def __init__(self, vulnerable_by_check: Optional[dict[str, bool]] = None,
                 defense_result: Optional[DefenseTurnResult] = None,
                 healthy: bool = True, status: Optional[AgentStatus] = None,
                 missing_checks: Optional[list[str]] = None) -> None:
        self.vulnerable_by_check: dict[str, bool] = vulnerable_by_check or {}
        self._defense_result = defense_result
        self._healthy = healthy
        self._status = status or AgentStatus(agent=AgentRole.DEFENDER, state=AgentState.IDLE)
        self.missing_checks: set[str] = set(missing_checks or [])  # 응답 누락 시뮬
        self.state_calls: list[list[str]] = []
        self.defense_calls: list[tuple[int, int]] = []

    def defense_turn(self, start: DefenseTurnStart, *, episode: int, round: int) -> DefenseTurnResult:
        self.defense_calls.append((episode, round))
        if self._defense_result is None:
            raise RuntimeError("FakeDefenderClient: defense_result 미설정")
        return self._defense_result

    def state_query(self, query: StateQuery, *, episode: int, round: int) -> StateQueryResult:
        self.state_calls.append([c.check_id for c in query.checks])
        results: list[StateCheckResult] = []
        for c in query.checks:
            if c.check_id in self.missing_checks:
                continue
            vuln = self.vulnerable_by_check.get(c.check_id, False)
            results.append(StateCheckResult(check_id=c.check_id, vulnerable=vuln, detail="fake"))
        return StateQueryResult(results=results)

    def health_check(self, hc: HealthCheck, *, episode: int, round: int) -> HealthResult:
        return HealthResult(service=hc.service, healthy=self._healthy, response_time_ms=1.0)

    def status(self) -> AgentStatus:
        return self._status


class FakeLogSource:
    """god-view 로그 fake. 라운드 순서대로 관측 기법 집합을 돌려준다.

    windows: 호출 순서별 기법 집합(한 라운드 = 한 호출). 소진되면 constant 반환.
    """

    def __init__(self, windows: Optional[list[set[str]]] = None,
                 constant: Optional[set[str]] = None) -> None:
        self._queue: list[set[str]] = list(windows or [])
        self._constant = constant if constant is not None else set()
        self.calls: list[tuple[float, float]] = []

    def techniques_in_window(self, *, since_ts: float, until_ts: float) -> set[str]:
        self.calls.append((since_ts, until_ts))
        if self._queue:
            return set(self._queue.pop(0))
        return set(self._constant)


__all__ = [
    "FakeSnapshotManager", "FakeBaseline", "FakeAttackerClient", "FakeDefenderClient",
    "FakeLogSource",
]
