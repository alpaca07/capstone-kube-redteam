"""멱등 MERGE 적재 엔진 — node/rel 딕셔너리를 Neo4j 에 올린다.

라벨·관계 타입은 schema 허용목록으로 검사 후에만 쿼리 문자열에 끼운다(주입 차단).
값은 전부 파라미터 바인딩. 같은 label 끼리 묶어 UNWIND 로 배치.
세션은 주입받는다(이음새) → 실 Neo4j 없이도 dry-run/페이크로 테스트 가능.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Iterable, Protocol

from . import schema


class Session(Protocol):
    """neo4j 드라이버 세션의 최소 계약(실전=neo4j.Session, 테스트=페이크)."""
    def run(self, query: str, **params): ...


def merge_nodes(session: Session, nodes: Iterable[dict], *, batch: int = 500) -> int:
    """label 별로 묶어 UNWIND MERGE. 반환=올린 노드 수."""
    by_label: dict[str, list[dict]] = defaultdict(list)
    for n in nodes:
        schema.check_node(n)
        by_label[n["label"]].append({"id": n["id"], "props": n.get("props", {})})

    total = 0
    for label, rows in by_label.items():
        query = (
            f"UNWIND $rows AS row "
            f"MERGE (n:{label} {{id: row.id}}) "
            f"SET n += row.props"
        )
        for i in range(0, len(rows), batch):
            session.run(query, rows=rows[i:i + batch])
        total += len(rows)
    return total


def merge_rels(session: Session, rels: Iterable[dict], *, batch: int = 500) -> int:
    """(from_label, to_label, type) 조합별로 묶어 UNWIND MERGE. 반환=올린 관계 수."""
    by_key: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for r in rels:
        schema.check_rel(r)
        key = (r["from_label"], r["to_label"], r["type"])
        by_key[key].append({"from": r["from_id"], "to": r["to_id"], "props": r.get("props", {})})

    total = 0
    for (from_label, to_label, rtype), rows in by_key.items():
        query = (
            f"UNWIND $rows AS row "
            f"MATCH (a:{from_label} {{id: row.from}}) "
            f"MATCH (b:{to_label} {{id: row.to}}) "
            f"MERGE (a)-[rel:{rtype}]->(b) "
            f"SET rel += row.props"
        )
        for i in range(0, len(rows), batch):
            session.run(query, rows=rows[i:i + batch])
        total += len(rows)
    return total


class DryRunSession:
    """실 적재 없이 쿼리·건수만 집계하는 세션(테스트·점검용)."""
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def run(self, query: str, **params):
        rows = params.get("rows", [])
        self.calls.append((query[:60], len(rows)))
        return []
