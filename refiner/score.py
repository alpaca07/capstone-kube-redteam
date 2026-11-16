"""god-view 채점 어댑터 — 시험실행 공격이 '실제로' 얼마나 깊이 갔나를 스칼라로.

HarnessProbe 의 score_turn 이음새 실 구현. 오케스트레이터 _build_truth 와 같은 god-view
원시값을 써서 심판 사실과 일치시킨다(공격자 자기보고 안 믿음):
  - techniques_in_window : 그 시간창의 감사·Falco 로그에서 관측된 기법 → 단계(①②③) 깊이
  - crowns_in_window     : 그 시간창의 접근기록 자백 → objectives 조건표로 크라운 달성 판정

점수(진행 깊이 + 기법 폭 + 크라운 보너스):
    score = 단계깊이 * stage_weight + 비선형플래그수 * flag_weight + 달성크라운수 * crown_bonus
- 단계깊이 : 선형 킬체인(①②③=숫자 플래그)의 최고 도달 단계.
- 기법 폭 : 관측 기법이 매핑되는 비선형 state 플래그(esc·priv·disc 등) 수. corp 처럼 선형
           단계를 안 쓰는 환경도 '크라운 못 가도 얼마나 진행했나'로 변별(수정안 비교 신호 촘촘).
- 크라운 : 최종 침해(crown-pii 등)엔 큰 보너스로 '목표 도달'을 압도적으로 반영.
시험실행은 수정안끼리의 상대 비교라 절대 척도가 아니어도 된다(같은 스냅샷·같은 채점이면 공정).
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from common.messages import AttackTurnResult


@runtime_checkable
class GodviewLogs(Protocol):
    """채점이 필요로 하는 god-view 로그 조회 두 가지(오케스트레이터 로그 소스가 만족)."""

    def techniques_in_window(self, *, since_ts: float, until_ts: float) -> set[str]: ...
    def crowns_in_window(self, *, since_ts: float, until_ts: float) -> set[str]: ...


class GodviewScorer:
    """score_turn 이음새 구현. 호출가능(객체) — HarnessProbe(score_turn=GodviewScorer(...))."""

    def __init__(self, logs: GodviewLogs, objectives, registry, *,
                 stage_weight: float = 1.0, flag_weight: float = 1.0,
                 crown_bonus: float = 10.0,
                 skew_pad: float = 3.0, grace_sec: float = 5.0) -> None:
        self.logs = logs                 # GodviewLogs (orchestrator 로그 소스 composite)
        self.objectives = objectives     # ObjectiveRegistry (크라운 조건표)
        self.registry = registry         # FlagRegistry (기법→단계 플래그 매핑)
        self.stage_weight = stage_weight  # 선형 단계깊이 가중
        self.flag_weight = flag_weight    # 비선형 기법폭 가중(보조 — 깊이보다 작게 두기 권장)
        self.crown_bonus = crown_bonus
        self.skew_pad = skew_pad         # 시작 경계 스큐 패드(VM-B↔VM-C 클럭 오차 흡수)
        self.grace_sec = grace_sec       # 종료 경계 유예(로그 스트리밍 지연 흡수)

    def __call__(self, result: AttackTurnResult, t0: float, t1: float) -> tuple[float, dict]:
        since = t0 - self.skew_pad
        until = t1 + self.grace_sec

        # 크라운(최종 침해): 접근기록 자백 → objectives 조건표 멤버십(= _build_truth 와 동일 경로).
        crowns_raw = self.logs.crowns_in_window(since_ts=since, until_ts=until)
        reached = self.objectives.reached_objectives({"crown": {"asset": crowns_raw}})

        # 관측 기법 → state 플래그. 선형 단계(①②③=숫자)는 깊이로, 그 외(esc·priv·disc)는 폭으로.
        techs = self.logs.techniques_in_window(since_ts=since, until_ts=until)
        reached_flags: set[str] = set()
        for t in techs:
            fid = self.registry.flag_for_technique(t)
            if fid:
                reached_flags.add(fid)
        stage_nums = {int(f) for f in reached_flags if f.isdigit()}
        depth = max(stage_nums, default=0)
        breadth = sorted(f for f in reached_flags if not f.isdigit())  # 비선형 진행

        score = (depth * self.stage_weight
                 + len(breadth) * self.flag_weight
                 + len(reached) * self.crown_bonus)
        detail = {
            "stage_depth": depth,
            "stages": sorted(stage_nums),
            "breadth": breadth,
            "breadth_count": len(breadth),
            "crowns": sorted(reached),
            "techniques": sorted(techs),
            "window": [since, until],
        }
        return float(score), detail


__all__ = ["GodviewScorer", "GodviewLogs"]
