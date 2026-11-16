"""god-view 채점 어댑터(GodviewScorer) 테스트 — 실제 기본 레지스트리 + fake 로그.

단계 깊이·크라운 보너스가 _build_truth 와 같은 원시값(techniques/crowns_in_window)에서
정확히 산출되는지 검증. 자체 러너: python3 tests/test_refiner_score.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.app_signals import CROWN_INTERNAL_SECRETS, CROWN_CUSTOMERS_PII
from common.messages import AttackEndReason, AttackTurnResult
from orchestrator.objectives import default_objectives
from orchestrator.flags import default_registry
from refiner.score import GodviewScorer


class FakeLogs:
    """god-view 로그 fake — 시간창 무관하게 미리 심은 기법·크라운을 돌려준다."""
    def __init__(self, techniques=None, crowns=None):
        self._t = set(techniques or [])
        self._c = set(crowns or [])
        self.windows = []                       # (since, until) 기록(시간창 적용 확인)
    def techniques_in_window(self, *, since_ts, until_ts):
        self.windows.append((since_ts, until_ts))
        return set(self._t)
    def crowns_in_window(self, *, since_ts, until_ts):
        return set(self._c)


def _res():
    return AttackTurnResult(end_reason=AttackEndReason.DEADEND)


def _scorer(logs, **kw):
    return GodviewScorer(logs, default_objectives(), default_registry(), **kw)


# ───────────── 단계 깊이 ─────────────
def test_stage_depth_from_observed_techniques():
    # T1552.001→단계1, T1078→단계2 관측 → 깊이 2, 크라운 0 → 점수 2.0
    logs = FakeLogs(techniques={"T1552.001", "T1078"})
    score, detail = _scorer(logs)(_res(), 100.0, 110.0)
    assert detail["stage_depth"] == 2
    assert detail["stages"] == [1, 2]
    assert detail["crowns"] == []
    assert score == 2.0


def test_empty_observation_scores_zero():
    score, detail = _scorer(FakeLogs())(_res(), 0.0, 1.0)
    assert score == 0.0 and detail["stage_depth"] == 0 and detail["crowns"] == []


# ───────────── 크라운 보너스 ─────────────
def test_crown_reached_adds_bonus():
    # 단계1(T1552.001) + 크라운 internal_secrets 접근기록 → 1*1 + 1*10 = 11.0
    logs = FakeLogs(techniques={"T1552.001"}, crowns={CROWN_INTERNAL_SECRETS})
    score, detail = _scorer(logs)(_res(), 0.0, 5.0)
    assert "crown-secrets" in detail["crowns"]
    assert score == 11.0


def test_two_crowns_counted():
    logs = FakeLogs(crowns={CROWN_INTERNAL_SECRETS, CROWN_CUSTOMERS_PII})
    score, detail = _scorer(logs)(_res(), 0.0, 5.0)
    assert set(detail["crowns"]) >= {"crown-secrets", "crown-pii"}
    assert score == 20.0                        # 크라운 2 * 10, 단계 0


# ───────────── 가중치·시간창 ─────────────
def test_custom_weights():
    logs = FakeLogs(techniques={"T1552.001", "T1078", "T1210"},  # 단계3
                    crowns={CROWN_INTERNAL_SECRETS})
    score, _ = _scorer(logs, stage_weight=2.0, crown_bonus=5.0)(_res(), 0.0, 1.0)
    assert score == 3 * 2.0 + 1 * 5.0           # 11.0


def test_window_applies_pad_and_grace():
    logs = FakeLogs(techniques={"T1078"})
    _scorer(logs, skew_pad=3.0, grace_sec=5.0)(_res(), 100.0, 110.0)
    since, until = logs.windows[0]
    assert since == 97.0 and until == 115.0     # [t0-pad, t1+grace]


# ───────────── 자체 러너 ─────────────
def _run() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  \033[32m✓\033[0m {t.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  \033[31m✗\033[0m {t.__name__}: {type(e).__name__}: {e}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed  (총 {len(tests)})")
    return 1 if failed else 0


if __name__ == "__main__":
    print("── god-view 채점 어댑터(GodviewScorer) 테스트 ──")
    sys.exit(_run())
