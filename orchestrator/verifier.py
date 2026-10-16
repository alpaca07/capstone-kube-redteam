"""③ 검증 엔진 — 차등 리플레이 + 상태검증 + 판정 (VM C의 심장).

작은 인터페이스(verify 하나) 뒤에 '방어가 진짜 먹혔나'를 가리는 전 과정을 숨긴다.
판정은 순수 코드(LLM 아님)라 fake 이음새로 완전히 테스트된다.

A2(k8s 네이티브) 흐름 — VM 스냅샷 전환 없이 '같은 출발점 ± 패치'의 차등 실험:
  ① 안전망용 god-view 캡처(패치된 라이브 상태 — 리셋하면 못 보므로 먼저).
  ② POST 재생: 패치된 라이브 클러스터에 대본 재생(상태 전환 0).
  ③ 베이스라인 리셋(패치 제거 → 클린 취약) → PRE 재생(재현 관문 + 다음 에피소드 클린 보장).
  스냅샷 stun 이 없어 느려지거나 VM 이 멈추지 않는다(§8 #1 해소).

판정표:
  pre 성공 + post 성공 = FAKE_PATCH (막은 척, 방어 실패)
  pre 성공 + post 실패 = BLOCKED    (진짜 차단, 방어 성공)
  pre 실패 → 상태검증(패치 상태 god-view): 취약 True → NOT_BLOCKED / 전부 False → BLOCKED / 불가 → INCONCLUSIVE

판정 우선순위(해시 노이즈 대응): ① success 지표 → ② 정규화 해시(matched_baseline) → ③ 상태검증 안전망.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from common.messages import (
    ReplayPhase, ReplayRequest, ReplayResult, StateQuery, StateQueryResult,
)
from common.replay_schema import ReplayScript

from .baseline import ClusterReset
from .clients import AttackerClient, DefenderClient
from .flags import FlagRegistry


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
    """의존성을 주입받아(이음새) 차등 리플레이 + 상태검증을 돌리고 Verdict를 낸다.

    attacker : 리플레이 재생 위임(VM A가 결정론 재생 엔진 보유)
    defender : 상태검증 질의(클러스터 내부 관점 god-view)
    baseline : 아레나를 클린 취약 베이스라인으로 되돌림(k8s 네이티브 — reset_to_clean)
    flags    : god-view 답안지(상태검증 쿼리 생성·값 대조)
    """

    def __init__(self, attacker: AttackerClient, defender: DefenderClient,
                 baseline: ClusterReset, flags: FlagRegistry) -> None:
        self.attacker = attacker
        self.defender = defender
        self.baseline = baseline
        self.flags = flags

    # ───────────── public 인터페이스 ─────────────
    def verify(self, script: ReplayScript, *, episode: int, round: int,
               target: Optional[str] = None) -> VerificationResult:
        """공격 대본을 '패치된 라이브(post)'와 '클린 리셋 후(pre)'에 재생해 방어 효과를 판정.

        끝나면 클러스터는 클린 베이스라인 상태로 남는다(다음 에피소드 바로 시작 가능).
        """
        # ① 안전망용 god-view 는 '패치된 라이브'에서 먼저 캡처(리셋하면 클린이라 패치 상태를 못 봄).
        state_patched = self._capture_state(episode=episode, round=round)

        # ② POST: 패치된 라이브 클러스터에 그대로 재생(상태 전환 없음).
        post = self.attacker.replay(
            ReplayRequest(replay_script=script, phase=ReplayPhase.POST, target=target),
            episode=episode, round=round)
        post_ok, post_reason, post_reached = self._reproduced(post, script)

        # ③ PRE 대조군: 클린 베이스라인으로 리셋(패치 제거) 후 재생 — 재현 관문.
        self.baseline.reset_to_clean()
        pre = self.attacker.replay(
            ReplayRequest(replay_script=script, phase=ReplayPhase.PRE, target=target),
            episode=episode, round=round)
        pre_ok, pre_reason, _ = self._reproduced(pre, script)

        # ④ 판정
        if not pre_ok:
            # 클린에서도 재현 실패 → 재생으로 판정 불가 → 패치 상태 god-view 안전망.
            return self._state_branch(
                state=state_patched, pre=pre,
                detail=f"pre(클린) 재현 실패({pre_reason}) → 상태검증")
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
    def _capture_state(self, *, episode: int, round: int) -> Optional[StateQueryResult]:
        """안전망용 god-view 상태를 '현재(패치된 라이브)'에서 캡처. best-effort —
        상태검증 가능한 조건이 없거나(값-flag만 있는 경우) 질의가 실패하면 None."""
        checks = self.flags.checks_for(self.flags.all_ids())
        if not checks:
            return None
        try:
            return self.defender.state_query(
                StateQuery(checks=checks), episode=episode, round=round)
        except Exception:                 # noqa: BLE001 — best-effort, 실패 시 None
            return None

    def _state_branch(self, *, state: Optional[StateQueryResult],
                      pre: ReplayResult, detail: str) -> VerificationResult:
        """재생으로 판정 못 할 때. 미리 캡처한 '패치 상태' god-view 로 킬체인(①②③)이 아직
        열렸나 확인. 공격자 자기보고가 아니라 god-view 사실로 판정한다."""
        if state is None:
            return VerificationResult(
                verdict=Verdict.INCONCLUSIVE, method="state", pre=pre,
                detail=detail + " / 상태검증 불가(체크 없음·응답 실패)")

        checks = self.flags.checks_for(self.flags.all_ids())
        by_id = {r.check_id: r for r in state.results}
        resolved = [by_id.get(c.check_id) for c in checks]

        if any(r is None for r in resolved):          # 응답 누락 → 못 믿음
            return VerificationResult(
                verdict=Verdict.INCONCLUSIVE, method="state", pre=pre, state=state,
                detail=detail + " / 일부 상태검증 응답 누락")

        still_open = [r.check_id for r in resolved if r and r.vulnerable]
        if still_open:
            return VerificationResult(
                verdict=Verdict.NOT_BLOCKED, method="state", pre=pre, state=state,
                flags_still_reachable=still_open,
                detail=detail + f" / 상태상 여전히 취약: {still_open}")
        return VerificationResult(
            verdict=Verdict.BLOCKED, method="state", pre=pre, state=state,
            detail=detail + " / 상태상 전부 차단 확인")


__all__ = ["Verdict", "VerificationResult", "VerificationEngine"]
