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
from typing import Iterable, Optional

from common.app_signals import crown_of_sql

from .log_source import LineReader

# postgres %m 타임스탬프: "2026-11-05 01:00:00.123 UTC" (ISO T 도 허용). 줄 어디서든 첫 매칭.
_TS = re.compile(
    r"(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d+))?\s*(?:UTC|Z|[+-]\d{2}:?\d{2})?")
# "LOG:  statement: <sql>" 또는 "LOG:  execute <name>: <sql>" 뒤의 SQL.
_STMT = re.compile(r"(?:statement|execute\b[^:]*):\s*(.*)$", re.IGNORECASE)
# 접속 role(%u) — log_line_prefix '%m [%p] %u@%d ' 의 "[42] legacy_admin@shopflow".
# postgres 기본 prefix(%m [%p])엔 role 이 없다 → attacker_roles 를 줄 때만 쓴다.
_ROLE = re.compile(r"\[\d+\]\s+(?P<role>[^@\s]+)@\S+")


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
    """postgres statement 로그를 god-view 로 조회. 시간창 내 반출 크라운 자산 집합 반환.

    actor 스코핑(선택): attacker_roles 를 주면 그 role 로 접속한 쿼리만 크라운으로 센다.
    ShopFlow 처럼 앱·더미트래픽이 민감 테이블을 상시 조회하는 환경에서, 유출 크레덴셜 전용
    role(예: legacy_admin)로만 좁혀 거짓 크라운을 막는다 — 앱 role·슈퍼유저 조회는 제외.
    None/빈이면 스코핑 없이 쿼리 패턴만 본다(정상 트래픽 없는 VulHub 단독 postgres·기존 동작).
    전제: 켤 땐 postgres log_line_prefix 에 '%u@%d' 가 있어야 role 을 뽑는다(없으면 그 줄 제외).
    """

    channel = "db"   # 크라운 반출 통로 이름(직접 DB 접속 — 표시용, 판정엔 안 쓰임)

    def __init__(self, reader: LineReader, *,
                 attacker_roles: Optional[Iterable[str]] = None) -> None:
        self.reader = reader
        self.attacker_roles: Optional[set[str]] = set(attacker_roles) if attacker_roles else None

    def crowns_in_window(self, *, since_ts: float, until_ts: float) -> set[str]:
        out: set[str] = set()
        for line in self.reader():
            ts = _pg_ts(line)
            if ts is None or not (since_ts <= ts <= until_ts):
                continue
            if self.attacker_roles is not None:
                rm = _ROLE.search(line)
                # role prefix 켠 환경: 공격 role 접속만 크라운(앱·슈퍼유저·role 불명 제외).
                if rm is None or rm.group("role") not in self.attacker_roles:
                    continue
            m = _STMT.search(line)
            if not m:
                continue
            c = crown_of_sql(m.group(1))
            if c:
                out.add(c)
        return out

    def crowns_by_channel_in_window(self, *, since_ts: float, until_ts: float) -> dict[str, set[str]]:
        """통로별 크라운 맵(표시 전용) — {"db": {자산}}. 판정은 crowns_in_window 이 담당."""
        c = self.crowns_in_window(since_ts=since_ts, until_ts=until_ts)
        return {self.channel: c} if c else {}

    def techniques_in_window(self, *, since_ts: float, until_ts: float) -> set[str]:
        """DB 통로는 크라운 전용 — 기법 관측은 감사/Falco/app 담당. 계약 충족용 빈 집합."""
        return set()


__all__ = ["DbLogSource"]
