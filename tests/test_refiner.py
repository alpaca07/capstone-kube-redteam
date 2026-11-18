"""하네스² 개량 사이클 테스트 — 제안·시험실행·합성 수직 슬라이스(fake 이음새).

자체 러너(pytest 불필요): python3 tests/test_refiner.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from refiner.models import Component, Harness, HarnessEdit
from refiner.refiner import refine
from refiner.fakes import FakeEditor, FakeProbe, FakeHarnessStore


def _edit(eid: str, kind: str = "invariant") -> HarnessEdit:
    return HarnessEdit(id=eid, component=Component.SYSTEM_PROMPT, kind=kind,
                       rationale=f"{eid} 사유", overlay_text=f"개량블록 {eid}")


# ───────────── 모델 단위 ─────────────
def test_overlay_preserves_base():
    """with_overlay 는 원본 Harness 를 안 건드리고 새 객체를 돌려준다."""
    h0 = Harness(base_prompt="BASE")
    h1 = h0.with_overlay(_edit("e1"))
    assert h0.overlays == ()                     # 원본 불변
    assert len(h1.overlays) == 1
    assert "BASE" in h1.effective_prompt()
    assert "개량블록 e1" in h1.effective_prompt()
    assert h0.effective_prompt() == "BASE"       # 오버레이 없으면 기반 그대로


# ───────────── 합성 결정 ─────────────
def test_promotes_best_candidate_beating_baseline():
    """기준선 0.3, 후보 e1=0.5/e2=0.7 → 더 높은 e2 승급."""
    store = FakeHarnessStore(base_prompt="BASE")
    editor = FakeEditor([_edit("e1"), _edit("e2")])
    probe = FakeProbe({None: 0.3, "e1": 0.5, "e2": 0.7})

    r = refine({}, store=store, editor=editor, probe=probe,
               n_candidates=2, probe_top_k=2)

    assert r.promoted is True
    assert r.chosen.id == "e2"
    assert store.promoted and store.promoted[-1].id == "e2"
    assert r.baseline.edit_id is None and r.baseline.score == 0.3


def test_keeps_harness_when_no_candidate_beats_baseline():
    """기준선 0.8, 후보 전부 그 아래 → 승급 없음, 하네스 보존."""
    store = FakeHarnessStore(base_prompt="BASE")
    editor = FakeEditor([_edit("e1"), _edit("e2")])
    probe = FakeProbe({None: 0.8, "e1": 0.5, "e2": 0.6})

    r = refine({}, store=store, editor=editor, probe=probe,
               n_candidates=2, probe_top_k=2)

    assert r.promoted is False
    assert r.chosen is None
    assert store.promoted == []


def test_min_gain_threshold_blocks_marginal_gain():
    """후보가 기준선보다 높지만 min_gain 문턱 미달이면 승급 안 함(노이즈 거름)."""
    store = FakeHarnessStore(base_prompt="BASE")
    editor = FakeEditor([_edit("e1")])
    probe = FakeProbe({None: 0.50, "e1": 0.52})

    r = refine({}, store=store, editor=editor, probe=probe,
               n_candidates=1, probe_top_k=1, min_gain=0.05)

    assert r.promoted is False                   # 0.52 < 0.50+0.05
    assert store.promoted == []


# ───────────── 탈옥 실측 아끼기(상위 k만) ─────────────
def test_only_top_k_probed():
    """n_candidates=4 지만 probe_top_k=2 → 탈옥 시험실행은 기준선1+상위2 = 3회뿐."""
    store = FakeHarnessStore(base_prompt="BASE")
    cands = [_edit("e1"), _edit("e2"), _edit("e3"), _edit("e4")]
    # 순위를 e3>e4>e1>e2 로 지정 → 상위 2 = e3,e4 만 실측돼야.
    editor = FakeEditor(cands, order=["e3", "e4", "e1", "e2"])
    probe = FakeProbe({None: 0.3, "e3": 0.9, "e4": 0.4, "e1": 0.99, "e2": 0.99})

    r = refine({}, store=store, editor=editor, probe=probe,
               n_candidates=4, probe_top_k=2)

    probed_ids = {pid for _, pid in probe.calls}
    assert probed_ids == {None, "e3", "e4"}      # e1·e2 는 선별 탈락 → 실측 안 함
    assert len(probe.calls) == 3                 # 기준선1 + 상위2
    assert r.chosen.id == "e3"                   # 실측된 것 중 최고(순위 1등이 실제로도 승)


def test_proposes_requested_candidate_count():
    """refine 이 n_candidates 를 편집자에게 그대로 요청한다."""
    store = FakeHarnessStore(base_prompt="BASE")
    editor = FakeEditor([_edit("e1"), _edit("e2"), _edit("e3")])
    probe = FakeProbe({None: 0.3, "e1": 0.4, "e2": 0.5, "e3": 0.6})

    refine({}, store=store, editor=editor, probe=probe,
           n_candidates=3, probe_top_k=3)

    assert editor.propose_calls == [3]
    assert editor.rank_calls == 1


def test_baseline_probe_injected_into_editor_digest():
    """refine 이 기준선 실측 결과를 편집자 digest 에 합쳐 넘긴다(깜깜이 제안 방지)."""
    store = FakeHarnessStore(base_prompt="BASE")
    editor = FakeEditor([_edit("e1")])
    probe = FakeProbe({None: 0.3, "e1": 0.5})

    refine({"round": 7}, store=store, editor=editor, probe=probe,
           n_candidates=1, probe_top_k=1)

    d = editor.last_digest
    assert d["round"] == 7                        # 호출자 digest 보존
    assert "baseline_probe" in d                  # 기준선 주입
    assert d["baseline_probe"]["score"] == 0.3    # 기준선 점수가 편집자에게 전달


def test_no_candidates_keeps_harness():
    """편집자가 수정안을 안 내면(빈 목록) 승급 없이 안전 종료."""
    store = FakeHarnessStore(base_prompt="BASE")
    editor = FakeEditor([])
    probe = FakeProbe({None: 0.3})

    r = refine({}, store=store, editor=editor, probe=probe,
               n_candidates=4, probe_top_k=2)

    assert r.promoted is False
    assert "수정안을 내지 않음" in r.reason


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
    print("── 하네스² 개량 사이클 테스트 ──")
    sys.exit(_run())
