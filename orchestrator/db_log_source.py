"""DB 로그 소스 — postgres statement 로그를 god-view 로 읽어 '직접 DB 접속' 크라운 반출을 뽑는다.

메인 킬체인 ④ 의 주 경로는 공격자 파드가 유출 크레덴셜로 postgres 에 '직접' 접속(③ NetworkPolicy
부재)해 민감 테이블을 조회하는 것이다. 이 경로는 앱(catalog/order)을 안 거치므로 app 자백 줄이
안 남는다 → postgres 가 쿼리를 statement 로그로 남기고(log_statement=all), VM C 가 그 로그를
직접 읽어(위조·누락 방지) 민감 테이블 조회를 크라운 반출로 판정한다.

로그 줄 → 크라운 판정은 common.app_signals.crown_of_sql(VM C 전용). 여기선 '시간창 조회 +
statement 추출'만 담당. LogSource 계약을 충족하되 기법은 안 뽑는다(기법=감사/Falco/app 담당).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Optional

from common.app_signals import crown_of_sql

from .log_source import LineReader

# postgres %m 타임스탬프: "2026-11-05 01:00:00.123 UTC" (ISO T 도 허용). 줄 어디서든 첫 매칭.
_TS = re.compile(
    r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(?:UTC|Z|[+-]\d{2}:?\d{2})?")
# "LOG:  statement: <sql>" 또는 "LOG:  execute <name>: <sql>" 뒤의 SQL.
_STMT = re.compile(r"(?:statement|execute\b[^:]*):\s*(.*)$", re.IGNORECASE)


def _pg_ts(line: str) -> Optional[float]:
    m = _TS.search(line)
    if not m:
        return None
    date, clock, frac = m.group(1), m.group(2), m.group(3)
    iso = f"{date}T{clock}" + (f".{frac}" if frac else "")
    try:
        return datetime.fromisoformat(iso).replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


class DbLogSource:
    """postgres statement 로그를 god-view 로 조회. 시간창 내 반출 크라운 자산 집합 반환."""

    def __init__(self, reader: LineReader) -> None:
        self.reader = reader

    def crowns_in_window(self, *, since_ts: float, until_ts: float) -> set[str]:
        out: set[str] = set()
        for line in self.reader():
            ts = _pg_ts(line)
            if ts is None or not (since_ts <= ts <= until_ts):
                continue
            m = _STMT.search(line)
            if not m:
                continue
            c = crown_of_sql(m.group(1))
            if c:
                out.add(c)
        return out

    def techniques_in_window(self, *, since_ts: float, until_ts: float) -> set[str]:
        """DB 통로는 크라운 전용 — 기법 관측은 감사/Falco/app 담당. 계약 충족용 빈 집합."""
        return set()


__all__ = ["DbLogSource"]
