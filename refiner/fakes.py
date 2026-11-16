"""하네스² 메타층 인메모리 fake — 정렬 LLM·탈옥 시험실행·오버레이 저장소 없이 테스트.

프로그래머블: 테스트가 수정안·순위·점수를 미리 심고, 호출 순서를 검사한다.
"""
from __future__ import annotations

from typing import Optional

from refiner.models import Harness, HarnessEdit, ProbeScore


class FakeEditor:
    """편집자 fake. 미리 심은 수정안을 돌려주고, 순위는 심은 순서(또는 지정) 그대로."""

    def __init__(self, candidates: list[HarnessEdit],
                 order: Optional[list[str]] = None) -> None:
        self._candidates = candidates
        self._order = order                      # edit id 순서(없으면 propose 순서 유지)
        self.propose_calls: list[int] = []       # 요청받은 n 기록
        self.rank_calls = 0

    def propose(self, digest: dict, harness: Harness, *, n: int) -> list[HarnessEdit]:
        self.propose_calls.append(n)
        return list(self._candidates[:n])

    def rank(self, digest: dict, edits: list[HarnessEdit]) -> list[HarnessEdit]:
        self.rank_calls += 1
        if self._order is None:
            return list(edits)
        pos = {eid: i for i, eid in enumerate(self._order)}
        return sorted(edits, key=lambda e: pos.get(e.id, 10_000))


class FakeProbe:
    """시험실행 fake. 하네스의 '맨 위 오버레이 id'(없으면 None=기준선)로 점수를 찾는다.

    scores: {edit_id|None: 점수}. 호출(basis, 측정한 id) 순서를 기록.
    """

    def __init__(self, scores: dict[Optional[str], float]) -> None:
        self._scores = scores
        self.calls: list[tuple[str, Optional[str]]] = []   # (basis, 측정 id)

    def probe(self, harness: Harness, *, basis: str) -> ProbeScore:
        top = harness.overlays[-1].id if harness.overlays else None
        self.calls.append((basis, top))
        return ProbeScore(edit_id=top, score=self._scores.get(top, 0.0), basis=basis)


class FakeHarnessStore:
    """하네스 저장소 fake. 기반 프롬프트 고정 + 승급 오버레이를 메모리에 누적."""

    def __init__(self, base_prompt: str = "BASE", overlays=None) -> None:
        self._base = base_prompt
        self._overlays: list[HarnessEdit] = list(overlays or [])
        self.promoted: list[HarnessEdit] = []    # 승급 이력

    def read(self) -> Harness:
        return Harness(base_prompt=self._base, overlays=tuple(self._overlays))

    def promote(self, edit: HarnessEdit) -> None:
        self._overlays.append(edit)
        self.promoted.append(edit)


__all__ = ["FakeEditor", "FakeProbe", "FakeHarnessStore"]
