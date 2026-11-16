"""시험실행 어댑터 — 후보 하네스를 고정 스냅샷에 실제 공격시켜 점수를 낸다.

ProbeRunner 이음새의 실 구현. 한 번의 probe():
  1) 대상(VM B)을 basis 스냅샷으로 되돌림(clean=베이스라인 | patched=직전 패치 상태).
  2) 후보 하네스의 effective_prompt() 를 system_prompt_override 로 실어 공격 턴 1회(탈옥 모델).
     round=1 로 보내 공격자 서버의 라운드 간 기억을 리셋 → 매 시험실행이 독립(누수 없음).
  3) god-view 채점 함수(주입)로 공격 결과를 스칼라 점수로 환산.

의존은 전부 이음새 주입:
  - snapshot : orchestrator.snapshot.SnapshotManager (revert_to)  — 기존 이음새 재사용
  - attacker : orchestrator.clients.AttackerClient (attack_turn)   — 기존 이음새 재사용
  - score_turn: (AttackTurnResult) -> (점수 float, 상세 dict) — god-view 채점(다음 단계 실 배선)

탈옥 엔드포인트 시간분리(라이브 유휴 때만 호출)는 상위 메타 프로세스(에피소드 경계)가
책임진다. 이 어댑터는 '되돌림→공격→채점' 한 번만 담당(작은 인터페이스).
"""
from __future__ import annotations

from typing import Callable, Optional

from common.messages import AttackTurnResult, AttackTurnStart, Foothold
from refiner.models import Harness, ProbeScore

# god-view 채점 이음새: 공격 결과 → (점수, 상세). 높을수록 좋은 공격.
ScoreTurn = Callable[[AttackTurnResult], tuple[float, dict]]
# patched 스냅샷 이름: 고정 문자열이거나, '직전 패치 스냅샷'을 돌려주는 호출가능.
SnapshotRef = "str | Callable[[], str]"


class HarnessProbe:
    """ProbeRunner 구현 — 되돌림→공격→채점으로 ProbeScore 생성."""

    def __init__(
        self,
        *,
        snapshot,
        attacker,
        score_turn: ScoreTurn,
        clean_snapshot: str = "clean-baseline",
        patched_snapshot=None,
        time_limit_sec: int = 300,
        max_tokens: Optional[int] = None,
        foothold: Optional[Foothold] = None,
        goal: Optional[str] = None,
        probe_episode: int = 9000,
        log: Optional[Callable[[str], None]] = None,
    ) -> None:
        self.snapshot = snapshot                 # SnapshotManager 이음새
        self.attacker = attacker                 # AttackerClient 이음새
        self.score_turn = score_turn             # god-view 채점(주입)
        self.clean_snapshot = clean_snapshot
        self.patched_snapshot = patched_snapshot  # str | callable | None
        self.time_limit_sec = time_limit_sec
        self.max_tokens = max_tokens
        self.foothold = foothold
        self.goal = goal
        self.probe_episode = probe_episode       # 라이브 회차와 안 겹치게 높은 번호
        self._log = log or (lambda m: None)

    def _resolve_snapshot(self, basis: str) -> str:
        if basis == "clean":
            return self.clean_snapshot
        if basis == "patched":
            ref = self.patched_snapshot
            if ref is None:
                # 패치 스냅샷이 아직 없으면 clean 으로 폴백(첫 라운드 등) — 조용히 통제 안정 쪽으로.
                self._log("patched 스냅샷 없음 → clean 으로 폴백")
                return self.clean_snapshot
            return ref() if callable(ref) else ref
        raise ValueError(f"알 수 없는 basis: {basis!r} (clean|patched)")

    def probe(self, harness: Harness, *, basis: str) -> ProbeScore:
        snap = self._resolve_snapshot(basis)
        self.snapshot.revert_to(snap)            # 1) 대상 고정

        start_kwargs = dict(
            time_limit_sec=self.time_limit_sec,
            system_prompt_override=harness.effective_prompt(),  # 2) 후보 프롬프트 주입
            max_tokens=self.max_tokens,
            foothold=self.foothold,
        )
        if self.goal is not None:
            start_kwargs["goal"] = self.goal
        start = AttackTurnStart(**start_kwargs)

        result = self.attacker.attack_turn(start, episode=self.probe_episode, round=1)
        score, detail = self.score_turn(result)  # 3) god-view 채점
        return ProbeScore(edit_id=None, score=float(score), basis=basis, detail=dict(detail))


__all__ = ["HarnessProbe", "ScoreTurn"]
