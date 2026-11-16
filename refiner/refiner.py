"""하네스² 개량 사이클 — 제안·시험실행·합성(propose·probe·compose).

순수 조율 로직. 모든 I/O(정렬 LLM·탈옥 시험실행·오버레이 저장)는 이음새 뒤.

사이클(refine 1회 = 에피소드 경계 1회):
  1) 기준선 측정 — 현재 하네스를 basis 스냅샷에서 시험실행(baseline).
  2) 제안      — 편집자(정렬)가 수정안 n_candidates 개 생성.
  3) 선별      — 편집자가 순위 매겨 상위 probe_top_k 만 남김(탈옥 희소 → 실측 최소화).
  4) 시험실행  — 상위 각 수정안을 탈옥 모델로 실측(오버레이 얹은 하네스로).
  5) 합성      — 최고점이 기준선 + min_gain 을 넘으면 그 수정안만 승급, 아니면 보존.

점수 규약: 높을수록 좋은 공격. 확률적 실행이 약한 수정을 좋아 보이게 할 수 있어(저자 경고)
min_gain 문턱으로 노이즈를 거른다 — god-view 사실 채점이 신호라 이 문턱이 의미를 가진다.
"""
from __future__ import annotations

from refiner.models import Harness, ProbeScore, RefineResult
from refiner.seams import Editor, ProbeRunner, HarnessStore


def refine(
    digest: dict,
    *,
    store: HarnessStore,
    editor: Editor,
    probe: ProbeRunner,
    n_candidates: int = 4,
    probe_top_k: int = 2,
    basis: str = "clean",
    min_gain: float = 0.0,
) -> RefineResult:
    """개량 한 사이클을 돌리고 결과(승급 여부 포함)를 반환. 승급 시 store 에 기록(부작용)."""
    harness: Harness = store.read()

    # 1) 기준선 — 현재 하네스 그대로.
    baseline: ProbeScore = probe.probe(harness, basis=basis)
    baseline.edit_id = None

    # 2) 제안 — 정렬 모델이 수정안 생성.
    candidates = editor.propose(digest, harness, n=n_candidates)
    if not candidates:
        return RefineResult(
            baseline=baseline, probe_scores=[], chosen=None, promoted=False,
            reason="편집자가 수정안을 내지 않음",
        )

    # 3) 선별 — 정렬 모델 순위로 상위 k만(탈옥 실측 아끼기).
    ranked = editor.rank(digest, candidates)[: max(0, probe_top_k)]

    # 4) 시험실행 — 상위 각 수정안을 탈옥 모델로 실측.
    scores: list[ProbeScore] = []
    by_id = {}
    for e in ranked:
        s = probe.probe(harness.with_overlay(e), basis=basis)
        s.edit_id = e.id
        scores.append(s)
        by_id[e.id] = e

    if not scores:
        return RefineResult(
            baseline=baseline, probe_scores=[], chosen=None, promoted=False,
            reason="선별 후 시험실행 대상이 없음(probe_top_k=0?)",
        )

    # 5) 합성 — 최고점 후보가 기준선+문턱을 넘나.
    best = max(scores, key=lambda p: p.score)
    threshold = baseline.score + min_gain
    if best.score > threshold:
        chosen = by_id[best.edit_id]
        store.promote(chosen)
        return RefineResult(
            baseline=baseline, probe_scores=scores, chosen=chosen, promoted=True,
            reason=f"{best.edit_id} 점수 {best.score:.3f} > 기준선 {baseline.score:.3f}+문턱 {min_gain:.3f}",
        )

    return RefineResult(
        baseline=baseline, probe_scores=scores, chosen=None, promoted=False,
        reason=f"최고 후보 {best.score:.3f} 가 기준선 {baseline.score:.3f}+문턱 {min_gain:.3f} 미달 — 하네스 보존",
    )


__all__ = ["refine"]
