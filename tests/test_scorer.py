"""채점·로깅 테스트 — 지표 함수 + 누적 채점 + 에피소드 요약.

    python3 tests/test_scorer.py        # 자체 러너
기댓값은 손으로 계산한 독립 출처(혼동행렬·MTTD 정의)에서 가져옴.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.messages import (  # noqa: E402
    AttackEndReason, AttackTurnResult, DefenseEndReason, DefenseTurnResult, Detection,
)
from orchestrator.scorer import (  # noqa: E402
    Scorer, confusion_matrix, mttd,
)
from orchestrator.truth_log import TruthEntry, TruthEvent, TruthLog  # noqa: E402
from orchestrator.verifier import Verdict, VerificationResult  # noqa: E402

_EPS = 1e-9


# ───────────── 빌더 ─────────────
def _attack(end=AttackEndReason.FLAG, elapsed=1.0) -> AttackTurnResult:
    return AttackTurnResult(end_reason=end, elapsed_sec=elapsed)


def _defense(techs=(), patch=True, health=True,
             end=DefenseEndReason.PATCHED, elapsed=1.0) -> DefenseTurnResult:
    return DefenseTurnResult(
        patch_applied=patch, end_reason=end,
        detected=[Detection(technique=t, evidence="e") for t in techs],
        healthcheck_passed=health, elapsed_sec=elapsed)


def _verif(verdict=Verdict.BLOCKED, method="replay") -> VerificationResult:
    return VerificationResult(verdict=verdict, method=method)


def _truth_2round() -> TruthLog:
    """ep1: r1에 T1078(②), r2에 T1210(③)."""
    tl = TruthLog()
    tl.record(TruthEntry(episode=1, round=1,
                         events=[TruthEvent("T1078", flag_id="2")], flags_reached=["2"]))
    tl.record(TruthEntry(episode=1, round=2,
                         events=[TruthEvent("T1210", flag_id="3")], flags_reached=["3"]))
    return tl


# ───────────── 순수 지표: 혼동행렬 ─────────────
def test_confusion_basic():
    d = confusion_matrix(reported={"A", "B"}, truth={"B", "C"})
    assert (d.tp, d.fp, d.fn) == (1, 1, 1)                 # B맞춤 / A오탐 / C놓침
    assert abs(d.precision() - 0.5) < _EPS
    assert abs(d.recall() - 0.5) < _EPS


def test_confusion_none_edges():
    assert confusion_matrix(set(), {"A"}).precision() is None   # 보고 0 → precision 정의안됨
    assert confusion_matrix({"A"}, set()).recall() is None      # 발생 0 → recall 정의안됨
    perfect = confusion_matrix({"A", "B"}, {"A", "B"})
    assert (perfect.tp, perfect.fp, perfect.fn) == (2, 0, 0)


# ───────────── 순수 지표: MTTD ─────────────
def test_mttd_basic():
    occ = {"T1": 1, "T2": 2, "T3": 3}
    det = {"T1": 2, "T2": 2}                                # T3 미탐지
    m = mttd(occ, det)
    assert abs(m.mean_rounds - 0.5) < _EPS                  # (1 + 0) / 2
    assert m.detected == 2 and m.total_true == 3
    assert abs(m.detection_rate() - (2 / 3)) < _EPS


def test_mttd_detection_before_occurrence_ignored():
    m = mttd({"T1": 3}, {"T1": 1})                          # 발생 전 보고 → 탐지로 안 침
    assert m.mean_rounds is None and m.detected == 0 and m.total_true == 1


def test_mttd_empty():
    m = mttd({}, {})
    assert m.mean_rounds is None and m.total_true == 0 and m.detection_rate() is None


# ───────────── TruthLog 질의 ─────────────
def test_truthlog_queries():
    tl = _truth_2round()
    assert tl.techniques_in_round(1, 1) == {"T1078"}
    assert tl.techniques_up_to(1, 2) == {"T1078", "T1210"}
    assert tl.flags_up_to(1, 2) == {"2", "3"}
    assert tl.first_occurrence_round(1) == {"T1078": 1, "T1210": 2}


# ───────────── Scorer 통합 ─────────────
def test_score_round_true_positive():
    tl = _truth_2round()
    sc = Scorer(tl, episode=1)
    rec = sc.score_round(round=1, attack_result=_attack(),
                         defense_result=_defense(techs=["T1078"]), verification=_verif())
    assert (rec.detection_cum.tp, rec.detection_cum.fp, rec.detection_cum.fn) == (1, 0, 0)
    assert rec.flags_reached_cum == ["2"]
    assert rec.verdict == "blocked" and rec.verify_method == "replay"
    assert rec.reported_techniques == ["T1078"]


def test_score_round_false_positive():
    tl = _truth_2round()
    sc = Scorer(tl, episode=1)
    rec = sc.score_round(round=1, attack_result=_attack(),
                         defense_result=_defense(techs=["T9999"]), verification=_verif())
    assert (rec.detection_cum.tp, rec.detection_cum.fp, rec.detection_cum.fn) == (0, 1, 1)


def test_score_cumulative_across_rounds():
    tl = _truth_2round()
    sc = Scorer(tl, episode=1)
    sc.score_round(round=1, attack_result=_attack(),
                   defense_result=_defense(techs=["T1078"]), verification=_verif())
    rec2 = sc.score_round(round=2, attack_result=_attack(),
                          defense_result=_defense(techs=["T1210"]), verification=_verif())
    assert (rec2.detection_cum.tp, rec2.detection_cum.fp, rec2.detection_cum.fn) == (2, 0, 0)
    assert rec2.flags_reached_cum == ["2", "3"]


def test_episode_summary():
    tl = _truth_2round()
    sc = Scorer(tl, episode=1)
    sc.score_round(round=1, attack_result=_attack(),
                   defense_result=_defense(techs=["T1078"], health=True), verification=_verif())
    sc.score_round(round=2, attack_result=_attack(),
                   defense_result=_defense(techs=["T1210"], health=False),
                   verification=_verif(verdict=Verdict.FAKE_PATCH))
    s = sc.summary(end_reason="max_rounds")
    assert s.rounds == 2
    assert s.max_flag_depth == 3                            # ③까지 도달
    assert (s.detection.tp, s.detection.fp, s.detection.fn) == (2, 0, 0)
    assert abs(s.mttd.mean_rounds - 0.0) < _EPS             # 둘 다 발생 즉시 탐지
    assert s.verdict_counts == {"blocked": 1, "fake_patch": 1}
    assert abs(s.availability - 0.5) < _EPS                 # 패치 2회 중 health 1회 통과
    assert s.patches == 2


def test_sink_receives_each_round():
    tl = _truth_2round()
    captured: list[dict] = []
    sc = Scorer(tl, episode=1, sink=captured.append)
    sc.score_round(round=1, attack_result=_attack(),
                   defense_result=_defense(techs=["T1078"]), verification=_verif())
    assert len(captured) == 1
    assert captured[0]["detection_cum"]["tp"] == 1          # JSONL dict 형태 확인
    assert captured[0]["episode"] == 1 and captured[0]["round"] == 1


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
    print("── 채점·로깅 테스트 ──")
    sys.exit(_run())
