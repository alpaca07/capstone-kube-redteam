"""로그 소스 이음새(seam) — VM C가 god-view로 감사/Falco 로그를 직접 조회.

정답 타임라인(TruthLog)을 채우려면 '이 라운드에 실제로 무슨 기법이 일어났나'를 알아야 한다.
그 사실의 출처가 로그다. VM C는 공격받는 VM B를 거치지 않고 로그를 직접 읽어(위조·누락
방지) 조건으로 검색한다. 로그 줄 → MITRE 기법 매핑의 복잡함은 실 어댑터 안에 숨긴다
(작은 인터페이스: 시간창을 주면 관측된 기법 집합을 돌려준다).

실제 구현(다음 단계)은 감사로그 JSON·Falco JSON을 파싱해 기법으로 매핑.
인메모리 fake는 라운드별 관측 기법을 미리 심어둔다(orchestrator/fakes.py).
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class LogSource(Protocol):
    """god-view 로그 조회 계약. 시간창 내 관측된 MITRE 기법 집합을 반환."""

    def techniques_in_window(self, *, since_ts: float, until_ts: float) -> set[str]:
        """[since_ts, until_ts] 구간의 감사/Falco 로그에서 관측된 기법 ID들."""
        ...


__all__ = ["LogSource"]
