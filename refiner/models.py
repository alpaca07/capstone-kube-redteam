"""하네스² 메타층 자료형 — 하네스·수정안·시험실행 점수·개량 결과.

전부 순수 dataclass(부작용 없음). 점수 방향 규약: score 는 '공격이 얼마나 잘 됐나'로,
높을수록 좋은 하네스다(크라운 깊이·플래그 도달 등에서 어댑터가 스칼라로 환산해 넣는다).
메타층은 이 스칼라를 비교만 할 뿐 어떤 지표인지는 모른다(정책은 어댑터에).
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from typing import Optional


class Component:
    """편집 가능한 하네스 부품(Harness² 8부품 중 공격 하네스에 실재하는 것부터).

    매핑: SYSTEM_PROMPT→attacker/prompts/attacker_system.txt,
          TOOL_GUIDANCE→프롬프트 내 '가용 도구' 안내,
          GUARDRAILS→attacker/scope.py 범위(초기엔 프롬프트 레이어로만 표현),
          MEMORY→attacker/history.py 요약 방식.
    초기 구현은 프롬프트 계열(SYSTEM_PROMPT·TOOL_GUIDANCE)만 오버레이로 편집한다.
    """
    SYSTEM_PROMPT = "system_prompt"
    TOOL_GUIDANCE = "tool_guidance"
    GUARDRAILS = "guardrails"
    MEMORY = "memory"

    ALL = (SYSTEM_PROMPT, TOOL_GUIDANCE, GUARDRAILS, MEMORY)


@dataclass(frozen=True)
class HarnessEdit:
    """편집자가 제안한 하네스 수정 하나.

    kind: 'invariant'(에이전트 일반 실패 교정) | 'domain'(대상 도메인 지식 보강) —
      Harness² 의 두 갈래 제안. 초기엔 overlay_text(프롬프트에 덧대는 블록)로만 적용한다.
    """
    id: str
    component: str                      # Component.* 중 하나
    kind: str                          # invariant | domain
    rationale: str                     # 왜 이 수정이 도움 되는지(편집자 설명)
    overlay_text: str                  # 하네스에 덧댈 텍스트 블록


@dataclass(frozen=True)
class Harness:
    """공격 하네스의 편집 대상 상태 = 불변 기반(base) + 승급된 오버레이들.

    base_prompt 는 절대 수정하지 않는다(롤백 안전). 개량은 오버레이를 쌓는 것.
    effective_prompt() 가 실제 하네스에 넣을 최종 프롬프트를 렌더한다.
    """
    base_prompt: str
    overlays: tuple[HarnessEdit, ...] = ()

    def with_overlay(self, edit: HarnessEdit) -> "Harness":
        """오버레이 하나를 얹은 새 Harness(원본 불변)."""
        return replace(self, overlays=self.overlays + (edit,))

    def effective_prompt(self) -> str:
        """기반 프롬프트 + 승급된 오버레이 블록들을 합친 최종 프롬프트."""
        if not self.overlays:
            return self.base_prompt
        blocks = [self.base_prompt, "", "[운영 개량 — 하네스² 자동반영]"]
        for e in self.overlays:
            blocks.append(e.overlay_text.strip())
        return "\n".join(blocks)


@dataclass
class ProbeScore:
    """시험실행 한 번의 점수. edit_id=None 이면 현재 하네스(기준선) 측정."""
    edit_id: Optional[str]
    score: float                       # 높을수록 좋은 공격(공격 성공 정도)
    basis: str                         # clean | patched (어느 스냅샷에서 쟀나)
    detail: dict = field(default_factory=dict)


@dataclass
class RefineResult:
    """개량 한 사이클 결과 — 기준선·후보 점수들·승급 여부."""
    baseline: ProbeScore
    probe_scores: list[ProbeScore]
    chosen: Optional[HarnessEdit]
    promoted: bool
    reason: str

    def to_dict(self) -> dict:
        return {
            "baseline": {"score": self.baseline.score, "basis": self.baseline.basis},
            "probe_scores": [
                {"edit_id": p.edit_id, "score": p.score, "basis": p.basis}
                for p in self.probe_scores
            ],
            "chosen": self.chosen.id if self.chosen else None,
            "promoted": self.promoted,
            "reason": self.reason,
        }


__all__ = [
    "Component", "HarnessEdit", "Harness", "ProbeScore", "RefineResult",
]
