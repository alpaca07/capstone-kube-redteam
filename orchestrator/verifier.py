"""③ 검증 엔진 — POST 재생으로 방어 효과를 판정 (VM C의 심장).

작은 인터페이스(verify 하나) 뒤에 '방어가 진짜 먹혔나'를 가리는 과정을 숨긴다.
판정은 순수 코드(LLM 아님)라 fake 이음새로 완전히 테스트된다.

판정 설계(POST-only) — 왜 이렇게:
  - 검증은 두 축으로 나뉜다. ① '공격이 진짜 목표에 도달했나' = 값-flag 대조(공격 턴에서 끝남,
    위조 불가). ② '패치가 그 공격을 막나' = 여기, POST 재생.
  - POST: 패치된 '라이브' 클러스터에 공격 대본을 그대로 재실행 → 여전히 flag 도달하면 막은 척
    (FAKE_PATCH), 못 도달하면 진짜 차단(BLOCKED). 이게 '이 공격이 막혔나'의 직접 측정이다.
  - '패치 전엔 통한다'(PRE 대조군)는 이번 라운드 '실공격이 방금 성공'(값-flag 대조로 검증됨)이
    증명한다 → 별도 PRE 재생/리셋 불필요. 결정론 재생이라 거짓 BLOCKED 위험도 낮다.
  - ★ 상태검증(①②③ '각 취약점이 열렸나')은 verdict 에서 제외: NetworkPolicy 패치는 ③만 닫고
    ①②는 열린 채라, 그걸 섞으면 거짓 NOT_BLOCKED 가 난다. god-view 상태는 §8 #6 탐지 채점용.
  - ★ 리셋 안 함 → 패치가 '라이브'에 남아 다음 라운드가 누적된 방어를 상대한다(공진화). 에피소드
    경계 리셋은 시퀀서 init·BaselineManager 담당.

판정표:  POST 성공 = FAKE_PATCH / POST 실패 = BLOCKED / POST 재생 불능(빈 결과) = INCONCLUSIVE
판정 우선순위(해시 노이즈 대응): ① success 지표 → ② 정규화 해시(matched_baseline).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from common.messages import ReplayPhase, ReplayRequest, ReplayResult, StateQueryResult
from common.replay_schema import ReplayScript

from .baseline import ClusterReset
from .clients import AttackerClient, DefenderClient
from .flags import FlagRegistry


class Verdict(str, Enum):
    BLOCKED = "blocked"            # 진짜 차단 — 방어 성공
    FAKE_PATCH = "fake_patch"      # 가짜 패치(리플레이 여전히 성공) — 방어 실패
    NOT_BLOCKED = "not_blocked"    # 상태상 여전히 취약 — 방어 실패(상태기반 검증용, §8 #6)
    INCONCLUSIVE = "inconclusive"  # 검증 불능 — 판정 보류


@dataclass
class VerificationResult:
    verdict: Verdict
    method: str                                    # "replay" | "state"
    pre: Optional[ReplayResult] = None             # (예약: 상태기반 검증 연동 시)
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
    """의존성을 주입받아(이음새) POST 재생으로 방어 효과를 판정한다.

    attacker : 리플레이 재생 위임(VM A가 결정론 재생 엔진 보유) — verify 가 쓰는 유일한 의존.
    defender·baseline·flags : 예약(향후 상태기반 검증·리셋 연동용). 현재 POST-only 판정엔 미사용
      — 리셋은 시퀀서 init·BaselineManager 담당, 상태검증은 §8 #6 탐지 채점용.
    """

    def __init__(self, attacker: AttackerClient, defender: DefenderClient,
                 baseline: ClusterReset, flags: FlagRegistry) -> None:
        self.attacker = attacker
        self.defender = defender      # 예약
        self.baseline = baseline      # 예약(verify 는 리셋 안 함 — 방어 누적 유지)
        self.flags = flags            # 예약

    # ───────────── public 인터페이스 ─────────────
    def verify(self, script: ReplayScript, *, episode: int, round: int,
               target: Optional[str] = None) -> VerificationResult:
        """패치된 라이브 클러스터에 공격 대본을 재생해 방어 효과를 판정(POST-only).

        상태 조작(리셋) 없음 → 방어 패치가 라운드 간 누적된다(에피소드 경계 리셋은 시퀀서 담당).
        """
        post = self.attacker.replay(
            ReplayRequest(replay_script=script, phase=ReplayPhase.POST, target=target),
            episode=episode, round=round)
        if not post.steps_result:
            # 재생이 한 스텝도 안 돌아감(재생 불능·오류) → 차단으로 오인하지 않게 판정 보류.
            return VerificationResult(
                verdict=Verdict.INCONCLUSIVE, method="replay", post=post,
                detail="POST 재생 결과 비어 있음(재생 불능) → 판정 보류")
        post_ok, post_reason, post_reached = self._reproduced(post, script)
        if post_ok:
            return VerificationResult(
                verdict=Verdict.FAKE_PATCH, method="replay", post=post,
                flags_still_reachable=post_reached,
                detail=f"POST 성공({post_reason}) → 공격 여전히 통함(가짜 패치)")
        return VerificationResult(
            verdict=Verdict.BLOCKED, method="replay", post=post,
            detail=f"POST 실패({post_reason}) → 패치가 이 공격을 차단")

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


__all__ = ["Verdict", "VerificationResult", "VerificationEngine"]
