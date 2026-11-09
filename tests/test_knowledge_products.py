"""바닥층 Product 적재(knowledge/load_products.py) 스모크.

allowlist 로드·Product 노드·nvd 입력 생성·CPE 연결 호출을 Neo4j 없이 검증.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from knowledge.load_products import (  # noqa: E402
    _link_pairs, emit_nvd_targets, load_allowlist, load_products, product_nodes)


class FakeSession:
    def __init__(self):
        self.calls = []

    def run(self, q, **p):
        self.calls.append((q, p))
        return []


def test_load_allowlist_real_file():
    products = load_allowlist()                 # 기본 경로 = knowledge/kg-cpe-allowlist.yaml
    assert len(products) >= 35
    pairs = {(p["vendor"], p["product"]) for p in products}
    # 직관과 다른 vendor 들이 정확히 들어갔나(실측 교정 확인)
    assert ("oracle", "mysql") in pairs
    assert ("konghq", "kong_gateway") in pairs
    assert ("vmware", "spring_framework") in pairs
    assert ("apache", "http_server") in pairs
    assert ("f5", "nginx") in pairs and ("nginx", "nginx") in pairs   # 병기


def test_product_nodes_shape_and_label():
    nodes = product_nodes([{"vendor": "gitlab", "product": "gitlab", "category": "cicd"}])
    assert nodes[0]["label"] == "Product"
    assert nodes[0]["id"] == "gitlab:gitlab"
    assert nodes[0]["props"]["vendor"] == "gitlab" and nodes[0]["props"]["category"] == "cicd"


def test_emit_nvd_targets():
    tgt = emit_nvd_targets([{"vendor": "gitlab", "product": "gitlab"},
                            {"vendor": "oracle", "product": "mysql"}])
    assert tgt["cve_ids"] == []
    assert "cpe:2.3:a:gitlab:gitlab" in tgt["cpe_matches"]
    assert "cpe:2.3:a:oracle:mysql" in tgt["cpe_matches"]


def test_link_pairs_needle():
    pairs = _link_pairs([{"vendor": "gitlab", "product": "gitlab"}])
    assert pairs[0] == {"vp": "gitlab:gitlab", "needle": ":gitlab:gitlab:"}


def test_load_products_merges_and_links():
    sess = FakeSession()
    n = load_products(sess, [{"vendor": "gitlab", "product": "gitlab", "category": "cicd"}])
    assert n == 1
    # Product-IDENTIFIED_BY->CPE 연결 Cypher 가 pairs 와 함께 호출됐나
    assert any("IDENTIFIED_BY" in q for q, _ in sess.calls)
    assert any("pairs" in p for _, p in sess.calls)


def test_load_allowlist_dedup():
    # 같은 쌍 중복은 제거(파일에 실수로 두 번 들어가도 안전)
    import tempfile
    import os
    content = ("products:\n"
               "  - {vendor: redis, product: redis}\n"
               "  - {vendor: redis, product: redis}\n")
    fd, path = tempfile.mkstemp(suffix=".yaml")
    try:
        os.write(fd, content.encode()); os.close(fd)
        assert len(load_allowlist(path)) == 1
    finally:
        os.unlink(path)


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
    print("── 바닥층 Product 적재 스모크 ──")
    sys.exit(_run())
