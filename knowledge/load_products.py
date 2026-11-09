"""바닥층 Product 노드 적재 + nvd 입력 생성 — 팀원 ETL(sources.py) 을 안 건드리는 독립 스크립트.

방식 A(CPE 경유): Product 노드(id=vendor:product)를 적재하고, nvd 가 만든 CPE(--nvd-cpe-nodes,
id=cpe:2.3 문자열)에 Product-IDENTIFIED_BY->CPE 로 잇는다. 매칭은 CPE id 에 ':vendor:product:' 가
들었나로(cpe:2.3:a:vendor:product:version...). 버전 특정 CPE 가 자산 앵커링 조인키가 된다.

왜 독립 스크립트인가: 바닥층 표준 ETL(parse_*·PARSERS)은 팀원 소관이라 안 건드린다. Product 는
그 공백이라, graph_writer 의 적재 엔진만 재사용해 여기서 따로 넣는다(라벨 Product 는 schema.LABELS).

흐름 (VM-A, 네트워크 ON · Neo4j 기동):
  1) python -m knowledge.load_products --emit-targets knowledge/nvd_targets.baseline.json
       # allowlist → nvd 입력(cpe_matches)으로 펴 파일 출력 (네트워크·Neo4j 불필요)
  2) python -m knowledge --sources nvd --nvd-targets knowledge/nvd_targets.baseline.json \
       --nvd-cpe-nodes --password "$NEO4J_PASSWORD"      # CVE + CPE(버전 특정) 적재
  3) python -m knowledge.load_products --link --password "$NEO4J_PASSWORD"
       # Product 노드 적재 + Product-IDENTIFIED_BY->CPE 연결
"""
from __future__ import annotations

import os
from typing import Iterable

from . import graph_writer
from . import schema

_DEFAULT_ALLOWLIST = os.path.join(os.path.dirname(__file__), "kg-cpe-allowlist.yaml")


def load_allowlist(path: str = _DEFAULT_ALLOWLIST) -> list[dict]:
    """allowlist YAML → [{vendor, product, category}, ...]. 중복 쌍 제거."""
    import yaml  # 지연 import
    data = yaml.safe_load(open(path, encoding="utf-8")) or {}
    out: list[dict] = []
    seen: set[tuple] = set()
    for p in data.get("products", []):
        vendor, product = (p.get("vendor") or "").strip(), (p.get("product") or "").strip()
        if not vendor or not product or (vendor, product) in seen:
            continue
        seen.add((vendor, product))
        out.append({"vendor": vendor, "product": product, "category": (p.get("category") or "").strip()})
    return out


def product_nodes(products: Iterable[dict]) -> list[dict]:
    """allowlist 쌍 → Product 노드(graph_writer.merge_nodes 형식). id=vendor:product."""
    nodes = []
    for p in products:
        vp = f"{p['vendor']}:{p['product']}"
        node = {"label": "Product", "id": vp,
                "props": {"name": p["product"], "vendor": p["vendor"], "category": p.get("category", "")}}
        schema.check_node(node)          # 라벨 허용목록 검사(안전하게 쿼리에 끼움)
        nodes.append(node)
    return nodes


def emit_nvd_targets(products: Iterable[dict]) -> dict:
    """allowlist → nvd 입력 {cve_ids:[], cpe_matches:[cpe:2.3:a:vendor:product, ...]}.

    virtualMatchString 은 접미 와일드카드가 생략돼도 그 제품 전체 CVE 를 받는다. 중복 제거.
    """
    seen, matches = set(), []
    for p in products:
        m = f"cpe:2.3:a:{p['vendor']}:{p['product']}"
        if m not in seen:
            seen.add(m)
            matches.append(m)
    return {"cve_ids": [], "cpe_matches": matches}


# Product-IDENTIFIED_BY->CPE 연결 — nvd 가 CPE 를 적재한 뒤 한 번 실행.
#   CPE id(cpe:2.3:a:vendor:product:version...)에 ':vendor:product:' 가 들면 그 Product 의 것.
_LINK_CYPHER = (
    "UNWIND $pairs AS pr "
    "MATCH (p:Product {id: pr.vp}) "
    "MATCH (c:CPE) WHERE c.id CONTAINS pr.needle "
    "MERGE (p)-[:IDENTIFIED_BY]->(c)")


def _link_pairs(products: Iterable[dict]) -> list[dict]:
    """연결 Cypher 파라미터: Product id 와 CPE 매칭용 바늘(':vendor:product:')."""
    return [{"vp": f"{p['vendor']}:{p['product']}",
             "needle": f":{p['vendor']}:{p['product']}:"} for p in products]


def link_products_to_cpe(session, products: Iterable[dict]) -> None:
    """Product-IDENTIFIED_BY->CPE 를 세션(run 계약)으로 적재. CPE 노드가 먼저 있어야 함."""
    session.run(_LINK_CYPHER, pairs=_link_pairs(list(products)))


def load_products(session, products: list[dict]) -> int:
    """Product 노드 적재 + CPE 연결. 적재한 Product 수 반환."""
    nodes = product_nodes(products)
    graph_writer.merge_nodes(session, nodes)
    link_products_to_cpe(session, products)
    return len(nodes)


# ───────────────────────────── CLI ─────────────────────────────
def main() -> None:
    import argparse
    import json
    ap = argparse.ArgumentParser(prog="knowledge.load_products",
                                 description="바닥층 Product 노드 적재 + nvd 입력 생성")
    ap.add_argument("--allowlist", default=_DEFAULT_ALLOWLIST)
    ap.add_argument("--emit-targets", metavar="PATH", default=None,
                    help="allowlist → nvd 입력 JSON 을 이 경로로 출력하고 종료(Neo4j 불필요)")
    ap.add_argument("--link", action="store_true",
                    help="Product 노드 적재 + Product-IDENTIFIED_BY->CPE 연결(Neo4j 필요)")
    ap.add_argument("--uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    ap.add_argument("--user", default=os.environ.get("NEO4J_USER", "neo4j"))
    ap.add_argument("--password", default=os.environ.get("NEO4J_PASSWORD"))
    a = ap.parse_args()

    products = load_allowlist(a.allowlist)
    print(f"[allowlist] {len(products)} 제품 쌍")

    if a.emit_targets:
        targets = emit_nvd_targets(products)
        with open(a.emit_targets, "w", encoding="utf-8") as f:
            json.dump(targets, f, ensure_ascii=False, indent=2)
        print(f"[emit] nvd 입력 {len(targets['cpe_matches'])}개 cpe_matches → {a.emit_targets}")
        return

    if a.link:
        if not a.password:
            raise SystemExit("NEO4J_PASSWORD (또는 --password) 필요")
        from neo4j import GraphDatabase  # 지연 import
        driver = GraphDatabase.driver(a.uri, auth=(a.user, a.password))
        try:
            with driver.session() as s:
                n = load_products(s, products)
            print(f"[link] Product {n}개 적재 + CPE 연결 완료")
        finally:
            driver.close()
        return

    ap.error("--emit-targets 또는 --link 중 하나를 줘라")


if __name__ == "__main__":
    main()
