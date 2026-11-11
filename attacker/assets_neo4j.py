"""Neo4j 구현 of [[AssetGraph]] — 자산 그래프를 실 DB에 영속화.

탐색 그래프([[Neo4jGraph]])와 같은 단일 Neo4j·같은 패턴. 자산 노드는 `:Asset` 라벨(+kind는
속성, 유동이라 라벨로 안 씀) + episode 속성(탐색과 함께 리셋, KG 보존). 같은 name은
MERGE로 원자적 get-or-merge(동시 워커 안전). 병합 규칙은 인메모리와 공유 로직을 트랜잭션
안에서 적용.

그래프 간 조인(확정 설계): Asset↔KG는 직접 엣지 없이 '조회시점 CPE 매칭'(find_by_cpe).
Exploration→Asset은 ANCHORED_TO(탐색 쪽에서 건다 — 여기선 자산 조회만 제공).

neo4j 드라이버는 import 안 함(driver 객체만 받음). 연결은 graph_neo4j.connect_driver 재사용.
"""
from __future__ import annotations

import json
from typing import Optional

from .assets import AssetGraph, AssetNode, merge_asset_fields


# ───────────── 매핑(순수 — 드라이버 불필요, 단위 테스트 대상) ─────────────
def _asset_from_props(p: dict) -> AssetNode:
    return AssetNode(
        id=int(p["id"]), kind=p.get("kind", "") or "", name=p.get("name", "") or "",
        cpe=p.get("cpe", "") or "", confidence=p.get("confidence", "") or "",
        attrs=json.loads(p.get("attrs_json") or "{}"),
        episode=int(p.get("episode", 0) or 0))


def _asset_set_props(n: AssetNode) -> dict:
    """AssetNode → Neo4j SET 프로퍼티."""
    return {"kind": n.kind, "name": n.name, "cpe": n.cpe, "confidence": n.confidence,
            "attrs_json": json.dumps(n.attrs, ensure_ascii=False)}


_NEXT = "MERGE (c:Counter {name:'asset_node'}) SET c.n = coalesce(c.n,0)+1 WITH c.n AS newid"
_CONTAINS = ("MATCH (p:Asset {episode:$episode, id:$parent}), (c:Asset {episode:$episode, id:$child}) "
             "MERGE (p)-[:CONTAINS]->(c)")
_GET = "MATCH (n:Asset {episode:$episode, id:$id}) RETURN n{.*} AS props"
_BY_NAME = "MATCH (n:Asset {episode:$episode, name:$name}) RETURN n{.*} AS props LIMIT 1"
_BY_CPE = "MATCH (n:Asset {episode:$episode, cpe:$cpe}) RETURN n{.*} AS props"
_ALL = "MATCH (n:Asset {episode:$episode}) RETURN n{.*} AS props ORDER BY n.id DESC LIMIT $limit"
_UNID = ("MATCH (n:Asset {episode:$episode}) WHERE n.cpe = '' OR n.cpe IS NULL "
         "RETURN n{.*} AS props ORDER BY n.id DESC LIMIT $limit")
_CHILDREN = ("MATCH (:Asset {episode:$episode, id:$id})-[:CONTAINS]->(c:Asset {episode:$episode}) "
             "RETURN c{.*} AS props")
_RESET = "MATCH (n:Asset {episode:$episode}) DETACH DELETE n"
_SCHEMA = [
    "CREATE INDEX asset_id IF NOT EXISTS FOR (n:Asset) ON (n.episode, n.id)",
    # (episode, name)은 add_asset 의 MERGE 키 — 유니크 제약이 있어야 병렬 워커의 MERGE 경합이
    # 직렬화돼 중복 Asset 노드가 안 생긴다(인덱스는 조회만 빠를 뿐 유일성 미보장). 제약이
    # 뒷받침 인덱스를 자동 생성하므로 기존 asset_name 범위 인덱스는 버린다.
    "DROP INDEX asset_name IF EXISTS",
    "CREATE CONSTRAINT asset_name_uniq IF NOT EXISTS FOR (n:Asset) REQUIRE (n.episode, n.name) IS UNIQUE",
    "CREATE INDEX asset_cpe IF NOT EXISTS FOR (n:Asset) ON (n.episode, n.cpe)",
    # Counter(name)는 _NEXT 의 MERGE 키 — 제약이 없으면 병렬 워커가 같은 카운터를 동시에 증가시켜
    # 중복 노드 + 같은 id 재발급(자산 id 충돌)이 난다. 단일 속성이라 전 버전/에디션 호환. :Counter 는
    # 탐색 그래프와 공유(라벨 하나)라 두 스키마에 같은 제약을 IF NOT EXISTS 로 둔다(먼저 도는 쪽이 생성).
    "CREATE CONSTRAINT counter_name_uniq IF NOT EXISTS FOR (n:Counter) REQUIRE n.name IS UNIQUE",
]


class Neo4jAssetGraph(AssetGraph):
    def __init__(self, driver, *, episode: int, database: Optional[str] = None) -> None:
        self._driver = driver
        self._episode = episode
        self._db = database

    def _run(self, query: str, **params) -> list:
        with self._driver.session(database=self._db) as s:
            return [r.data() for r in s.run(query, episode=self._episode, **params)]

    def ensure_schema(self) -> None:
        with self._driver.session(database=self._db) as s:
            for q in _SCHEMA:
                try:
                    s.run(q)
                except Exception as e:                       # noqa: BLE001
                    if q.startswith("CREATE CONSTRAINT"):     # 보통 기존 중복 노드 때문
                        raise RuntimeError(
                            "유니크 제약 생성 실패 — 보통 기존 중복 노드 때문입니다. VM-A 에서 먼저 비우세요: "
                            "MATCH (n:Asset) DETACH DELETE n; MATCH (n:Finding) DETACH DELETE n; "
                            "MATCH (n:Counter) DETACH DELETE n "
                            "(KG 는 :Product/:CVE 등 다른 라벨이라 영향 없음). 그 뒤 다시 실행. "
                            f"원인: {e}") from e
                    raise

    def reset_episode(self) -> None:
        self._run(_RESET)

    # ── 쓰기 ──
    def add_asset(self, kind: str, name: str, *, cpe: str = "", confidence: str = "",
                  attrs: Optional[dict] = None, parent: Optional[int] = None,
                  anchors: Optional[list[int]] = None) -> int:
        name = (name or "").strip()
        nid = self._driver.session(database=self._db).execute_write(
            self._upsert_tx, kind, name, cpe, confidence, attrs or {})
        if parent is not None:
            self._run(_CONTAINS, parent=parent, child=nid)
        return nid

    def _upsert_tx(self, tx, kind, name, cpe, confidence, attrs) -> int:
        """name으로 원자적 get-or-merge. MERGE가 노드 확보 → 기존이면 공유 규칙으로 병합."""
        rec = tx.run(
            "MERGE (n:Asset {episode:$episode, name:$name}) "
            "ON CREATE SET n:Asset, n._new=true "
            "RETURN n.id AS id, n.kind AS kind, n.cpe AS cpe, n.confidence AS conf, "
            "n.attrs_json AS attrs, n._new AS isnew",
            episode=self._episode, name=name).single()
        if rec.get("isnew"):
            idrow = tx.run(_NEXT + " RETURN newid").single()
            nid = int(idrow["newid"])
            node = AssetNode(id=nid, kind=kind, name=name, cpe=cpe, confidence=confidence,
                             attrs=dict(attrs), episode=self._episode)
            p = _asset_set_props(node)
            tx.run("MATCH (n:Asset {episode:$episode, name:$name}) "
                    "SET n.id=$id, n.kind=$kind, n.cpe=$cpe, n.confidence=$conf, "
                    "n.attrs_json=$attrs REMOVE n._new",
                    episode=self._episode, name=name, id=nid, kind=p["kind"], cpe=p["cpe"],
                    conf=p["confidence"], attrs=p["attrs_json"])
            return nid
        # 기존: 공유 규칙으로 병합 후 기록
        nid = int(rec["id"])
        existing = AssetNode(id=nid, kind=rec.get("kind") or "", name=name,
                             cpe=rec.get("cpe") or "", confidence=rec.get("conf") or "",
                             attrs=json.loads(rec.get("attrs") or "{}"), episode=self._episode)
        merge_asset_fields(existing, kind=kind, cpe=cpe, confidence=confidence, attrs=attrs)
        p = _asset_set_props(existing)
        tx.run("MATCH (n:Asset {episode:$episode, name:$name}) "
                "SET n.kind=$kind, n.cpe=$cpe, n.confidence=$conf, n.attrs_json=$attrs",
                episode=self._episode, name=name, kind=p["kind"], cpe=p["cpe"],
                conf=p["confidence"], attrs=p["attrs_json"])
        return nid

    def link_contains(self, parent_id: int, child_id: int) -> None:
        self._run(_CONTAINS, parent=parent_id, child=child_id)

    # ── 읽기 ──
    def get_asset(self, asset_id: int) -> Optional[AssetNode]:
        rows = self._run(_GET, id=asset_id)
        return _asset_from_props(rows[0]["props"]) if rows else None

    def find_by_name(self, name: str) -> Optional[AssetNode]:
        rows = self._run(_BY_NAME, name=(name or "").strip())
        return _asset_from_props(rows[0]["props"]) if rows else None

    def find_by_cpe(self, cpe: str) -> list[AssetNode]:
        if not cpe:
            return []
        return [_asset_from_props(r["props"]) for r in self._run(_BY_CPE, cpe=cpe)]

    def assets(self, limit: int = 100) -> list[AssetNode]:
        return [_asset_from_props(r["props"]) for r in self._run(_ALL, limit=limit)]

    def children(self, asset_id: int) -> list[AssetNode]:
        return [_asset_from_props(r["props"]) for r in self._run(_CHILDREN, id=asset_id)]

    def unidentified(self, limit: int = 100) -> list[AssetNode]:
        return [_asset_from_props(r["props"]) for r in self._run(_UNID, limit=limit)]


__all__ = ["Neo4jAssetGraph", "_asset_from_props", "_asset_set_props"]
