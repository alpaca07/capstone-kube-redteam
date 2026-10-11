"""② 스냅샷 매니저 이음새(seam) — VMware 스냅샷으로 VM B 상태를 되돌린다.

검증 엔진이 'pre(패치 전) ↔ post(패치 후)' 상태를 오가며 같은 공격을 재생하려면
상태를 원자적으로 전환할 수단이 필요하다. 그 계약이 SnapshotManager.
- 에피소드당: clean 베이스라인 1개(에피소드 시작 리셋).
- 라운드당: 공격후·패치후 임시 2개(검증용, 끝나면 정리).

이 파일은 계약만 정의. 실제 구현 두 가지가 이 계약을 만족:
  - 실 어댑터: govc(CLI) 또는 pyvmomi 래핑 (orchestrator/govc_snapshot.py, 다음 단계).
    작업 완료까지 블로킹(폴링) — revert가 안 끝났는데 재생하면 오염되므로 원자성 필수.
  - 인메모리 fake: 테스트·드라이런 (orchestrator/fakes.py) — 호출 순서·현재 상태만 추적.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class SnapshotManager(Protocol):
    """VM B 스냅샷 제어 계약. 모든 메서드는 작업 완료까지 블로킹(원자성 보장)."""

    def save(self, name: str) -> None:
        """현재 VM B 상태를 name 스냅샷으로 저장(있으면 덮어씀)."""
        ...

    def revert_to(self, name: str) -> None:
        """VM B를 name 스냅샷 상태로 되돌리고 완료까지 대기."""
        ...

    def delete(self, name: str) -> None:
        """name 스냅샷 제거(라운드 임시 스냅샷 정리용). 없으면 무시."""
        ...

    def list(self) -> list[str]:
        """현재 존재하는 스냅샷 이름 목록."""
        ...


__all__ = ["SnapshotManager"]
