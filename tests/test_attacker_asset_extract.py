"""자산 기계 추출 테스트 — 실 런 로그 기반 명령·출력에서 자산 포집.

    python3 tests/test_attacker_asset_extract.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.asset_extract import extract_assets  # noqa: E402


def _by_name(assets):
    return {a["name"]: a for a in assets}


# ── K8s 서비스 DNS ──
def test_svc_dns():
    a = _by_name(extract_assets(["wget -qO- http://internal-wiki.internal.svc.cluster.local/",
                                 "nslookup postgres.database.svc.cluster.local"]))
    assert "internal-wiki.internal.svc.cluster.local" in a
    assert "postgres.database.svc.cluster.local" in a
    assert a["postgres.database.svc.cluster.local"]["kind"] == "service"


# ── URL → host(서비스) + path(엔드포인트) ──
def test_url_host_and_endpoint():
    a = _by_name(extract_assets(["wget -qO- http://10.43.183.240:80/secret 2>&1"]))
    assert "10.43.183.240:80" in a or "10.43.183.240" in a   # host 포집
    # 엔드포인트(path) 포집
    assert any(x["kind"] == "endpoint" and "/secret" in x["name"] for x in a.values())


def test_url_port_attr():
    a = _by_name(extract_assets(["curl http://admin-dashboard:8080/"]))
    assert a["admin-dashboard"]["attrs"].get("port") == 8080


# ── IP:port → 서비스 ──
def test_ip_port():
    a = _by_name(extract_assets(["psql -h 10.43.214.23 -p 5432", "nc -zv 10.43.214.23:5432"]))
    assert "10.43.214.23:5432" in a
    assert a["10.43.214.23:5432"]["attrs"]["port"] == 5432


# ── 단독 IP는 자산 안 만듦(노이즈 방지) — 포트·URL 없이 등장한 IP ──
def test_bare_ip_not_captured():
    a = _by_name(extract_assets(["ping 10.0.0.5 ; traceroute 192.168.1.1"]))
    assert "10.0.0.5" not in a and "192.168.1.1" not in a


# ── IP:port면 그 IP가 호스트 부모로 생성되고 서비스가 자식 ──
def test_ip_port_creates_host_parent():
    a = _by_name(extract_assets(["nc -zv 10.43.214.23:5432"]))
    assert "10.43.214.23" in a and a["10.43.214.23"]["kind"] == "host"
    assert a["10.43.214.23:5432"]["parent"] == "10.43.214.23"


# ── URL 엔드포인트는 host 서비스의 자식(parent) ──
def test_endpoint_parent_is_host():
    a = _by_name(extract_assets(["wget http://admin-dashboard/secret"]))
    ep = a["admin-dashboard/secret"]
    assert ep["kind"] == "endpoint" and ep["parent"] == "admin-dashboard"


# ── 잘못된 IP(255 초과)는 버림 ──
def test_invalid_ip_dropped():
    a = _by_name(extract_assets(["nc -zv 10.999.1.1:5432", "psql -h 10.999.1.1 -p 5432"]))
    assert "10.999.1.1:5432" not in a


# ── 의도 target: 가장 강한 신호. 'A (B)'·CIDR 처리 ──
def test_intent_target():
    a = _by_name(extract_assets([], intent_target="PostgreSQL service (10.43.214.23)"))
    assert "postgresql service" in a
    # CIDR은 자산 아님
    a2 = _by_name(extract_assets([], intent_target="10.0.0.0/24"))
    assert a2 == {}
    # IP:port target은 분해
    a3 = _by_name(extract_assets([], intent_target="10.0.0.5:8080"))
    assert "10.0.0.5:8080" in a3


# ── name 정규화(소문자·공백) + dedup ──
def test_normalize_and_dedup():
    a = extract_assets(["http://Internal-Wiki.internal.svc.cluster.local/",
                        "nslookup internal-wiki.internal.svc.cluster.local"])
    names = [x["name"] for x in a]
    # 대소문자 달라도 하나로
    assert names.count("internal-wiki.internal.svc.cluster.local") == 1


# ── 실 런 로그 한 묶음: 여러 자산이 한 번에 포집 ──
def test_real_log_batch():
    texts = [
        "sh -c env | grep -iE 'service|host|port'",
        "wget -qO- http://10.43.183.240:80/ 2>&1 | head",
        "wget -qO- http://internal-wiki.internal.svc.cluster.local/",
        "nslookup postgres.database.svc.cluster.local",
        "psql -h 10.43.214.23 -p 5432 -U postgres",
        "cat /var/run/secrets/kubernetes.io/serviceaccount/token",
    ]
    names = {a["name"] for a in extract_assets(texts, intent_target="internal-wiki")}
    assert "10.43.183.240:80" in names
    assert "internal-wiki.internal.svc.cluster.local" in names
    assert "postgres.database.svc.cluster.local" in names
    assert "10.43.214.23:5432" in names
    # 전부 미식별(CPE 없음) — 기계 추출은 식별 안 함
    for a in extract_assets(texts):
        assert "cpe" not in a or not a.get("cpe")


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
    print("── 자산 추출 테스트 ──")
    sys.exit(_run())
