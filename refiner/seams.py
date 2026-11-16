"""하네스² 메타층 이음새(seam) — 세 계약만 정의(작은 인터페이스).

실제 구현 두 갈래가 이 계약을 만족:
  - 실 어댑터(다음 단계): 정렬 LLM 제안·탈옥 하네스 시험실행·프롬프트 파일 오버레이.
  - 인메모리 fake: 테스트·오프라인 드라이런(refiner/fakes.py).

역할별 모델 배치(설계 확정):
  - Editor      → 정렬 모델(두 번째 엔드포인트, 서빙 여유). 제안 생성 + 자체 순위.
  - ProbeRunner → 탈옥 모델 동일본(유일 엔드포인트, 에피소드 경계 시간분리). 실제 공격 수행.
  - HarnessStore→ attacker/prompts 오버레이 파일 읽기/승급(기반 프롬프트 불변).
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from refiner.models import Harness, HarnessEdit, ProbeScore


@runtime_checkable
class Editor(Protocol):
    """편집자(정렬 모델). 수정안을 '생성'하고 '순위'까지 매긴다 — 탈옥 희소라 상위만 실측."""

    def propose(self, digest: dict, harness: Harness, *, n: int) -> list[HarnessEdit]:
        """에피소드 요약(digest: god-view 점수·대본·막힌 경로)을 읽고 수정안 n개 생성.

        invariant(일반 실패 교정)·domain(도메인 지식 보강) 두 갈래를 섞어 낸다.
        """
        ...

    def rank(self, digest: dict, edits: list[HarnessEdit]) -> list[HarnessEdit]:
        """정렬 모델이 수정안을 좋을 것 같은 순서로 정렬(best-first). 실측 전 싼 선별."""
        ...


@runtime_checkable
class ProbeRunner(Protocol):
    """시험실행기(탈옥 모델 동일본). 주어진 하네스로 고정 스냅샷에 실제 공격 → 점수."""

    def probe(self, harness: Harness, *, basis: str) -> ProbeScore:
        """basis('clean'=베이스라인 | 'patched'=직전 패치 상태) 스냅샷으로 되돌린 뒤
        이 하네스 프롬프트로 탈옥 모델 공격 턴을 돌리고 god-view 채점기로 스칼라 점수.
        반환 ProbeScore.edit_id 는 호출자가 채운다(기준선=None)."""
        ...


@runtime_checkable
class HarnessStore(Protocol):
    """하네스 상태 저장소. 기반 프롬프트 불변 + 승급 오버레이 영속화."""

    def read(self) -> Harness:
        """현재 하네스(기반 + 이미 승급된 오버레이들) 로드."""
        ...

    def promote(self, edit: HarnessEdit) -> None:
        """수정안을 라이브 하네스로 승급(오버레이 추가 기록). 다음 에피소드부터 반영."""
        ...


__all__ = ["Editor", "ProbeRunner", "HarnessStore"]
