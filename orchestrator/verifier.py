"""③ 검증 엔진 — pre/post 리플레이 + 상태검증 + 판정 (VM C의 심장).

작은 인터페이스(verify 하나) 뒤에 '방어가 진짜 먹혔나'를 가리는 전 과정을 숨긴다.
판정은 순수 코드(LLM 아님)라 fake 이음새로 완전히 테스트된다.

판정 우선순위 (해시 노이즈 대응):
  ① success 지표(스텝 성공 불린) → ② 정규화 해시(matched_baseline) 보조 → ③ 상태검증 안전망.

pre/post 흐름 (스냅샷 전환 최대 3회):
  현재(패치후) 저장 → 패치전 revert → pre 재생 → 패치후 복귀 → post 재생.
  pre 재현 실패면 post 생략하고 상태검증으로(재현 불가한 공격은 재생으로 판정 못 하므로).

판정표:
  pre 성공 + post 성공 = FAKE_PATCH (막은 척, 방어 실패)
  pre 성공 + post 실패 = BLOCKED    (진짜 차단, 방어 성공)
  pre 실패 → 상태검증:  취약 True → NOT_BLOCKED / 전부 False → BLOCKED / 불가 → INCONCLUSIVE
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from common.messages import (
    ReplayPhase, ReplayRequest, ReplayResult, StateQuery, StateQueryResult,
)
from common.replay_schema import ReplayScript

from .clients import AttackerClient, DefenderClient
from .flags import FlagRegistry
from .snapshot import SnapshotManager


class Verdict(str, Enum):
    BLOCKED = "blocked"            # 진짜 차단 — 방어 성공
    FAKE_PATCH = "fake_patch"      # 가짜 패치(리플레이 여전히 성공) — 방어 실패
    NOT_BLOCKED = "not_blocked"    # 상태상 여전히 취약 — 방어 실패
    INCONCLUSIVE = "inconclusive"  # 검증 불능 — 판정 보류


@dataclass
class VerificationResult:
    verdict: Verdict
    method: str                                    # "replay" | "state"
    pre: Optional[ReplayResult] = None
    post: Optional[ReplayResult] = None
    state: Optional[StateQueryResult] = None
    flags_still_reachable: list[str] = field(default_factory=list)
    detail: str = ""

    def defense_succeeded(self) -> bool:
        """방어 성공 = 공격 경로가 실제로 닫힘(BLOCKED). 나머지는 실패/보류."""
        return self.verdict == Verdict.BLOCKED

    def is_inconclusive(self) -> bool:
        return self.verdict == Verdict.INCONCLUSIVE


class VerificationEngine:
    """의존성을 주입받아(이음새) pre/post + 상태검증을 돌리고 Verdict를 낸다.

    attacker : 리플레이 재생 위임(VM A가 execute_action 엔진 보유)
    defender : 상태검증 질의(클러스터 내부 관점)
    snapshots: pre↔post 상태 전환(원자적)
    flags    : god-view 답안지(상태검증 쿼리 생성·값 대조)
    """

    def __init__(self, attacker: AttackerClient, defender: DefenderClient,
                 snapshots: SnapshotManager, flags: FlagRegistry) -> None:
        self.attacker = attacker
        self.defender = defender
        self.snapshots = snapshots
        self.flags = flags

    # ───────────── public 인터페이스 ─────────────
    def verify(self, script: ReplayScript, *, episode: int, round: int,
               pre_snapshot: str, post_patch_snapshot: str,
               target: Optional[str] = None) -> VerificationResult:
        """공격 대본을 패치 전/후 상태에 재생해 방어 효과를 판정.

        pre_snapshot        : 패치 전(공격이 원래 통하던) 상태 스냅샷 — 재현 관문.
        post_patch_snapshot : 현재(패치 후) 상태를 임시 저장할 이름 — 재생 뒤 복귀용.
        끝나면 VM B는 항상 패치 후 상태로 복귀(다음 라운드 연속성).
        """
        # 1) 현재(패치후) 상태 보존 → 2) 패치 전으로 되돌려 pre 재생
        self.snapshots.save(post_patch_snapshot)
        self.snapshots.revert_to(pre_snapshot)
        pre = self.attacker.replay(
            ReplayRequest(replay_script=script, phase=ReplayPhase.PRE, target=target),
            episode=episode, round=round)
        pre_ok, pre_reason, _ = self._reproduced(pre, script)

        if not pre_ok:
            # 관문 실패: 재현 자체 불가 → 패치후 복귀 후 상태검증 안전망으로
            self.snapshots.revert_to(post_patch_snapshot)
            return self._state_branch(
                episode=episode, round=round, pre=pre,
                detail=f"pre 재현 실패({pre_reason}) → 상태검증")

        # 관문 통과: 패치 후 상태로 복귀해 post 재생
        self.snapshots.revert_to(post_patch_snapshot)
        post = self.attacker.replay(
            ReplayRequest(replay_script=script, phase=ReplayPhase.POST, target=target),
            episode=episode, round=round)
        post_ok, post_reason, post_reached = self._reproduced(post, script)

        if post_ok:
            return VerificationResult(
                verdict=Verdict.FAKE_PATCH, method="replay", pre=pre, post=post,
                flags_still_reachable=post_reached,
                detail=f"pre 성공 + post 성공({post_reason}) → 가짜 패치")
        return VerificationResult(
            verdict=Verdict.BLOCKED, method="replay", pre=pre, post=post,
            detail=f"pre 성공({pre_reason}) + post 실패 → 진짜 차단")

    # ───────────── 재현 판정(success-first → hash) ─────────────
    def _reproduced(self, result: ReplayResult,
                    script: ReplayScript) -> tuple[bool, str, list[str]]:
        """대본이 재현됐나. 플래그 스텝 성공 우선, 안 되면 정규화 해시 일치로 보조.

        반환: (재현여부, 근거["success"|"hash"|"no-reproduce"], 도달한 flag_id들)
        """
        smap = {r.step: r for r in result.steps_result}
        flag_steps = [s for s in script.steps if s.flag_check is not None]
        reached: list[str] = []

        if flag_steps:
            all_ok = True
            used_hash = False
            for s in flag_steps:
                rec = smap.get(s.step)
                if rec is None:
                    all_ok = False
                    continue
                ok = rec.success
                if not ok and rec.matched_baseline is True:   # ② 해시 폴백
                    ok = True
                    used_hash = True
                if ok:
                    assert s.flag_check is not None
                    reached.append(s.flag_check.flag_id)
                else:
                    all_ok = False
            reason = ("hash" if used_hash else "success") if all_ok else "no-reproduce"
            return all_ok, reason, reached

        # 플래그 스텝이 없는 대본: overall 신뢰 + 전스텝 해시 일치 폴백
        if result.overall_success:
            return True, "success", []
        if result.steps_result and all(r.matched_baseline is True for r in result.steps_result):
            return True, "hash", []
        return False, "no-reproduce", []

    # ───────────── 상태검증 안전망 ─────────────
    def _state_branch(self, *, episode: int, round: int,
                      pre: ReplayResult, detail: str) -> VerificationResult:
        """재생으로 판정 못 할 때. 킬체인 상태(①②③)가 아직 열렸나 god-view로 확인.

        공격자 자기보고가 아니라 답안지 전체의 상태검증을 질의한다 — 경로가 열렸는지는
        공격자가 뭘 찍었는지와 무관한 god-view 사실이므로.
        """
        checks = self.flags.checks_for(self.flags.all_ids())
        if not checks:
            return VerificationResult(
                verdict=Verdict.INCONCLUSIVE, method="state", pre=pre,
                detail=detail + " / 상태검증 가능한 조건 없음")

        sqr = self.defender.state_query(StateQuery(checks=checks),
                                        episode=episode, round=round)
        by_id = {r.check_id: r for r in sqr.results}
        resolved = [by_id.get(c.check_id) for c in checks]

        if any(r is None for r in resolved):          # 응답 누락 → 못 믿음
            return VerificationResult(
                verdict=Verdict.INCONCLUSIVE, method="state", pre=pre, state=sqr,
                detail=detail + " / 일부 상태검증 응답 누락")

        still_open = [r.check_id for r in resolved if r and r.vulnerable]
        if still_open:
            return VerificationResult(
                verdict=Verdict.NOT_BLOCKED, method="state", pre=pre, state=sqr,
                flags_still_reachable=still_open,
                detail=detail + f" / 상태상 여전히 취약: {still_open}")
        return VerificationResult(
            verdict=Verdict.BLOCKED, method="state", pre=pre, state=sqr,
            detail=detail + " / 상태상 전부 차단 확인")


__all__ = ["Verdict", "VerificationResult", "VerificationEngine"]
