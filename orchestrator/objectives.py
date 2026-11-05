"""목표(크라운 주얼) 조건표 — god-view 답안지의 플래그리스 일반화 (VM C 전용).

기존 flags.py 의 값기반 플래그(④ 랜덤 FLAG{} 대조)를 걷어내고, 최종 침해를 '접근 흔적'으로
판정한다. 심판은 '심어둔 문자열이 보고됐나'가 아니라 '목표 자산이 실제로 빠졌나'(크라운 반출
자백 줄)를 본다.

설계 요지:
- 조건 한 줄 = {channel, field, operator, expected}. channel(통로)만 '어느 관측을 볼지'를 코드가
  고르는 닫힌 목록이고, field/operator/expected 는 전부 데이터 → 새 목표는 조건만 더하면 됨.
- 한 목표(ObjectiveSpec) 달성 = 그 조건줄들이 '전부' 참('그리고'만). '또는'은 없다 — 같은 크라운에
  이르는 길이 여럿이면 목표를 '길별로' 여러 개 등록하고, 같은 goal 로 묶어 '하나라도' 달성되면
  그 goal 성공('모로 가든 성공은 성공').
- 평가기는 통로별 관측 집합에 조건을 대보는 멍청한 함수(LLM 아님). 관측은 {channel: {field: set}}
  형태로 심판이 각 통로에서 뽑아 넘긴다(app_access 는 AppLogSource.crowns_in_window).

범위(2026-11): 크라운 주얼만 조건표로 옮긴다. ①②③ 상태검증·탐지 채점은 기존 flags.py 유지.
host(노드 파일, 탈출 전용)는 앱 통로가 아니라 이번 범위 밖.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from common.app_signals import CROWN_CUSTOMERS_PII, CROWN_INTERNAL_SECRETS

# 관측 타입: 관측축(channel) → 항목(field) → 관측된 값 집합.
# 예: {"crown": {"asset": {"internal_secrets"}}}
# channel 은 '관측 축'(닫힌 목록): "crown"(반출 자백 — app·db 통로 합집합) · 향후 audit/falco/cluster_state.
# 같은 축에 여러 통로가 기여할 수 있다(crown = AppLogSource + DbLogSource) → 축 단위로 합쳐 넘긴다.
Observation = dict[str, dict[str, set]]


@dataclass(frozen=True)
class Condition:
    """조건 한 줄. operator 로 통로 관측집합과 expected 를 대조한다."""
    channel: str       # 통로(닫힌 목록): "app_access" (지금) · 향후 audit/falco/cluster_state
    field: str         # 통로별 항목(항목사전): app_access → "crown"
    operator: str      # "eq" | "in" | "exists"
    expected: Any = None   # eq=값 / in=값들 / exists=없음


@dataclass(frozen=True)
class ObjectiveSpec:
    """목표(크라운 주얼) 하나의 god-view 정의. conditions 전부 참이면 달성."""
    objective_id: str
    mitre: str                        # 조회 열쇠 겸 메타(MITRE 기법 ID)
    goal: str                         # 크라운 묶음키 — 같은 goal 의 여러 길 중 하나면 goal 성공
    description: str
    conditions: tuple[Condition, ...]

    def __post_init__(self) -> None:
        if not self.conditions:
            raise ValueError(f"objective {self.objective_id} 에 conditions 가 비어 있음")


def _eval_condition(c: Condition, obs: Observation) -> bool:
    """조건 한 줄을 관측에 대보는 멍청한 대조(통로 무관 순수 함수)."""
    observed = obs.get(c.channel, {}).get(c.field, set())
    if c.operator == "eq":
        return c.expected in observed
    if c.operator == "in":
        try:
            return any(e in observed for e in c.expected)
        except TypeError:
            return False
    if c.operator == "exists":
        return bool(observed)
    # 미지원 연산자는 보수적으로 미달성(심판은 추측 안 함)
    return False


class ObjectiveRegistry:
    """목표 조건표 모음 + 관측 대조(작은 인터페이스, 답안지 전체를 숨김)."""

    def __init__(self, specs: list[ObjectiveSpec]) -> None:
        self._by_id: dict[str, ObjectiveSpec] = {}
        for s in specs:
            if s.objective_id in self._by_id:
                raise ValueError(f"중복 objective_id: {s.objective_id}")
            self._by_id[s.objective_id] = s

    def get(self, objective_id: str) -> Optional[ObjectiveSpec]:
        return self._by_id.get(objective_id)

    def all_ids(self) -> list[str]:
        return list(self._by_id.keys())

    def goals(self) -> set[str]:
        return {s.goal for s in self._by_id.values()}

    def is_reached(self, objective_id: str, obs: Observation) -> bool:
        """지정 목표가 관측상 달성됐나 — 조건줄 '전부' 참(그리고)."""
        spec = self._by_id.get(objective_id)
        if spec is None:
            return False
        return all(_eval_condition(c, obs) for c in spec.conditions)

    def reached_objectives(self, obs: Observation) -> set[str]:
        """관측상 달성된 목표 id 집합."""
        return {oid for oid in self._by_id if self.is_reached(oid, obs)}

    def reached_goals(self, obs: Observation) -> set[str]:
        """관측상 달성된 goal 집합 — goal 의 길 중 '하나라도' 달성되면 포함(또는)."""
        return {s.goal for oid, s in self._by_id.items() if self.is_reached(oid, obs)}


# ───────────── 기본 레지스트리(크라운 주얼) ─────────────
# ④ internal_secrets 와 고객 PII 를 같은 goal("db_exfil")로 묶는다 — 어느 경로(SQLi·BOLA)로
# 빠지든 '데이터 탈취' 달성. 조건은 app_access 통로의 crown 자백 집합에 대한 멤버십.
def default_objectives() -> ObjectiveRegistry:
    return ObjectiveRegistry([
        ObjectiveSpec(
            objective_id="crown-secrets", mitre="T1213", goal="db_exfil",
            description="④ 목표물 internal_secrets 반출(과거 값기반 FLAG 자리)",
            conditions=(Condition("crown", "asset", "eq", CROWN_INTERNAL_SECRETS),),
        ),
        ObjectiveSpec(
            objective_id="crown-pii", mitre="T1213", goal="db_exfil",
            description="고객 PII(이름·이메일·전화·주소·주민번호) 반출",
            conditions=(Condition("crown", "asset", "eq", CROWN_CUSTOMERS_PII),),
        ),
    ])


__all__ = [
    "Observation", "Condition", "ObjectiveSpec", "ObjectiveRegistry",
    "default_objectives",
]
