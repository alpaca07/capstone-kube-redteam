"""DB 통로 스모크 — postgres statement 로그에서 직접 DB 접속 크라운 반출을 뽑는가.

직접 DB 경로(③ NetworkPolicy 부재)로 민감 테이블을 조회하면 app 자백은 안 남지만 postgres
statement 로그엔 남는다 → DbLogSource 가 그걸 크라운으로 판정(메인 킬체인 ④ 주 경로 커버).
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.app_signals import (  # noqa: E402
    CROWN_CUSTOMERS_PII, CROWN_INTERNAL_SECRETS, crown_of_sql)
from orchestrator.db_log_source import DbLogSource  # noqa: E402


# ───────────── crown_of_sql 단위 ─────────────
def test_sql_internal_secrets():
    assert crown_of_sql("SELECT value FROM internal_secrets") == CROWN_INTERNAL_SECRETS
    assert crown_of_sql("select key,value from internal_secrets where id=1") == CROWN_INTERNAL_SECRETS


def test_sql_customers_pii():
    assert crown_of_sql("SELECT * FROM customers") == CROWN_CUSTOMERS_PII
    assert crown_of_sql("SELECT ssn, email FROM customers WHERE id=7") == CROWN_CUSTOMERS_PII
    assert crown_of_sql("select name, phone from customers") == CROWN_CUSTOMERS_PII


def test_sql_normal_queries_none():
    # 이름만 조인(PII 컬럼 없음) → 반출 아님
    assert crown_of_sql(
        "SELECT o.id, c.name AS customer FROM orders o JOIN customers c ON o.customer_id=c.id") is None
    assert crown_of_sql("SELECT id,name,category,price,stock FROM products ORDER BY id") is None


def test_sql_non_select_none():
    # 조회가 아닌 쿼리는 반출 아님(UPDATE/INSERT)
    assert crown_of_sql("UPDATE customers SET phone='x' WHERE id=1") is None
    assert crown_of_sql("INSERT INTO internal_secrets VALUES (1)") is None


# ───────────── DbLogSource 파싱 + 시간창 ─────────────
def _ts(s: str) -> float:
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc).timestamp()


_LOGS = [
    "2026-11-05 01:00:05.123 UTC [42] LOG:  statement: SELECT value FROM internal_secrets",
    "2026-11-05 01:00:06.000 UTC [42] LOG:  statement: SELECT * FROM customers",
    # kubectl logs --prefix 접두어가 붙어도 postgres 타임스탬프를 찾아 파싱
    "[pod/postgres-abc/postgres] 2026-11-05 01:00:07.000 UTC [43] LOG:  statement: "
    "SELECT ssn,email FROM customers WHERE id=1",
    # 정상 쿼리(이름만) → 크라운 아님
    "2026-11-05 01:00:08.000 UTC [44] LOG:  statement: SELECT o.id, c.name FROM orders o "
    "JOIN customers c ON o.customer_id=c.id",
    # 시간창 밖
    "2026-11-05 09:00:00.000 UTC [44] LOG:  statement: SELECT * FROM internal_secrets",
    # 비-statement 로그(연결 등)
    "2026-11-05 01:00:05.000 UTC [42] LOG:  connection authorized: user=app",
]


def test_db_crowns_in_window():
    src = DbLogSource(lambda: iter(_LOGS))
    crowns = src.crowns_in_window(since_ts=_ts("2026-11-05 01:00:00"),
                                  until_ts=_ts("2026-11-05 01:00:10"))
    assert crowns == {CROWN_INTERNAL_SECRETS, CROWN_CUSTOMERS_PII}


def test_db_window_excludes_outside():
    src = DbLogSource(lambda: iter(_LOGS))
    # 좁은 창: 첫 줄(internal_secrets)만 포함
    crowns = src.crowns_in_window(since_ts=_ts("2026-11-05 01:00:05"),
                                  until_ts=_ts("2026-11-05 01:00:05.5"))
    assert crowns == {CROWN_INTERNAL_SECRETS}


def test_db_techniques_empty():
    # DB 통로는 크라운 전용 — 기법은 안 뽑음
    src = DbLogSource(lambda: iter(_LOGS))
    assert src.techniques_in_window(since_ts=0, until_ts=9e9) == set()


# ───────────── actor 스코핑(선택) ─────────────
# log_line_prefix '%m [%p] %u@%d ' 를 켠 환경: role 로 접속자를 가른다.
_ROLE_LOGS = [
    # 공격자: 유출 크레덴셜 전용 role 로 민감 테이블 조회 → 크라운
    "2026-11-05 01:00:05.000 UTC [42] legacy_admin@shopflow LOG:  statement: SELECT * FROM customers",
    "2026-11-05 01:00:06.000 UTC [42] legacy_admin@shopflow LOG:  statement: SELECT value FROM internal_secrets",
    # 앱 정상 트래픽: 같은 민감 쿼리라도 앱 role → 크라운 아님(actor 스코핑의 핵심)
    "2026-11-05 01:00:07.000 UTC [43] shopflow_app@shopflow LOG:  statement: SELECT * FROM customers",
    # 슈퍼유저 유지보수 조회도 제외
    "2026-11-05 01:00:08.000 UTC [44] postgres@shopflow LOG:  statement: SELECT ssn FROM customers",
]


def test_db_actor_scoping_only_attacker_role():
    # attacker_roles 지정 → legacy_admin 접속만 크라운
    src = DbLogSource(lambda: iter(_ROLE_LOGS), attacker_roles={"legacy_admin"})
    crowns = src.crowns_in_window(since_ts=_ts("2026-11-05 01:00:00"),
                                  until_ts=_ts("2026-11-05 01:00:10"))
    assert crowns == {CROWN_CUSTOMERS_PII, CROWN_INTERNAL_SECRETS}


def test_db_actor_scoping_excludes_app_and_super():
    # 앱·슈퍼유저 role 만 있으면(공격 role 접속 없음) 크라운 없음 — 거짓 크라운 방지
    app_only = [ln for ln in _ROLE_LOGS if "legacy_admin" not in ln]
    src = DbLogSource(lambda: iter(app_only), attacker_roles={"legacy_admin"})
    crowns = src.crowns_in_window(since_ts=_ts("2026-11-05 01:00:00"),
                                  until_ts=_ts("2026-11-05 01:00:10"))
    assert crowns == set()


def test_db_no_scoping_is_backward_compatible():
    # attacker_roles 미지정(기존 동작) → role 무시, 쿼리 패턴만 → 민감 쿼리 전부 크라운
    src = DbLogSource(lambda: iter(_ROLE_LOGS))   # role prefix 있어도 스코핑 안 함
    crowns = src.crowns_in_window(since_ts=_ts("2026-11-05 01:00:00"),
                                  until_ts=_ts("2026-11-05 01:00:10"))
    assert crowns == {CROWN_CUSTOMERS_PII, CROWN_INTERNAL_SECRETS}


def test_db_scoping_skips_roleless_lines():
    # role prefix 없는 줄(기본 prefix) + attacker_roles 지정 → role 불명이라 제외(보수적)
    roleless = ["2026-11-05 01:00:05.000 UTC [42] LOG:  statement: SELECT * FROM customers"]
    src = DbLogSource(lambda: iter(roleless), attacker_roles={"legacy_admin"})
    crowns = src.crowns_in_window(since_ts=_ts("2026-11-05 01:00:00"),
                                  until_ts=_ts("2026-11-05 01:00:10"))
    assert crowns == set()


# ───────────────────── 자체 러너 ─────────────────────
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
    print("── DB 통로 스모크 ──")
    sys.exit(_run())
