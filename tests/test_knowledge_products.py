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
    _link_pairs, emit_nvd_targets, load_allowlist, load_products, load_technologies,
    product_nodes, service_nodes_and_rels, technology_nodes_and_rels)


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


def test_service_nodes_and_rels():
    st_nodes, rels = service_nodes_and_rels([
        {"vendor": "oracle", "product": "mysql", "category": "database"},
        {"vendor": "mariadb", "product": "mariadb", "category": "database"},   # 같은 category
        {"vendor": "f5", "product": "nginx", "category": "web_server"}])
    assert sorted(n["id"] for n in st_nodes) == ["database", "web_server"]     # category 별 1개
    assert all(n["label"] == "ServiceType" for n in st_nodes)
    pairs = {(r["from_id"], r["to_id"]) for r in rels if r["type"] == "PROVIDES_SERVICE"}
    assert ("oracle:mysql", "database") in pairs          # Product(vendor:product) → ServiceType(category)
    assert ("mariadb:mariadb", "database") in pairs and ("f5:nginx", "web_server") in pairs


def test_technology_nodes_and_rels():
    t_nodes, rels = technology_nodes_and_rels([
        {"id": "java", "name": "Java", "products": ["apache:tomcat", "vmware:spring_framework"]},
        {"id": "python", "name": "Python", "products": ["palletsprojects:flask"]}])
    assert sorted(n["id"] for n in t_nodes) == ["java", "python"]        # 기술 노드(언어/런타임 축)
    assert all(n["label"] == "Technology" for n in t_nodes)
    pairs = {(r["from_id"], r["to_id"]) for r in rels if r["type"] == "USES_TECHNOLOGY"}
    assert ("apache:tomcat", "java") in pairs                           # Product(vendor:product) → Technology
    assert ("vmware:spring_framework", "java") in pairs and ("palletsprojects:flask", "python") in pairs


def test_load_technologies_real_file():
    techs = load_technologies()                 # 기본 경로 = knowledge/kg-technologies.yaml
    ids = {t["id"] for t in techs}
    assert {"java", "python", "c"} <= ids
    java = next(t for t in techs if t["id"] == "java")
    assert "apache:tomcat" in java["products"] and "vmware:spring_framework" in java["products"]


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
    # ServiceType + PROVIDES_SERVICE 도 적재됐나(병합: load_products 로 통합)
    assert any("ServiceType" in q for q, _ in sess.calls)
    assert any("PROVIDES_SERVICE" in q for q, _ in sess.calls)
    # Technology + USES_TECHNOLOGY 도 적재(언어/런타임 축, 실파일 기반)
    assert any("USES_TECHNOLOGY" in q for q, _ in sess.calls)


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
