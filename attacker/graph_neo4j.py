"""Neo4j 구현 of [[ExplorationGraph]] — 탐색 그래프를 실 DB에 영속화.

인메모리([[InMemoryGraph]])와 같은 계약을 Neo4j로. 단일 DB에 라벨로 3그래프 공존
(확정 설계): 탐색 노드는 `:Explore` + kind 라벨(`:Intent`/`:Fact`/`:Finding`)을 달고
`episode` 속성으로 회차 스코프. 지식 그래프(KG)는 `:Explore`를 안 달아 리셋서 보존.

핵심 — claim 원자성(ARTEX의 CAS 대응):
  ARTEX는 SQL `UPDATE ... WHERE state='open'`로 원자 claim. Neo4j는 MATCH의 WHERE가
  SET 시점에 재검사되지 않아, 두 워커가 같은 open 의도를 동시에 집을 수 있다(lost update).
  → Neo4j 권장 패턴: 먼저 쓰기(락 획득)를 걸고, 그 뒤 상태를 '다시' 확인한 뒤 전이한다.
    CLAIM 쿼리의 `SET n.claim_seq=...`가 노드 락을 잡고, 뒤의 `WHERE n.state='open'`이
    락을 쥔 채 재검사 → 이미 running이면 전이 안 됨(이중 claim 차단).

발견 병합(dedup)·payload는 인메모리와 같은 공유 규칙([[merge_finding_payload]])을 쓴다.
payload는 `payload_json`(문자열)으로 저장해 Neo4j의 중첩 프로퍼티 제약을 피한다.

이 모듈은 neo4j 드라이버를 import하지 않는다(Neo4jGraph는 driver 객체만 받음). 실제
연결은 connect() 팩토리가 지연 import. 드라이버 미설치 환경에서도 이 모듈은 로드된다.
"""
from __future__ import annotations

import json
from typing import Optional

from .graph import (
    ExplorationGraph, IntentState, Node, NodeKind, Rel,
    merge_finding_payload,
)

_REL = {Rel.SPAWNS: "SPAWNS", Rel.DERIVED_FROM: "DERIVED_FROM",
        Rel.YIELDS: "YIELDS", Rel.PROVES: "PROVES"}


# ───────────── 매핑 헬퍼(순수 — 드라이버 불필요, 단위 테스트 대상) ─────────────
def _node_from_props(props: dict) -> Node:
    """Neo4j 노드 프로퍼티(map) → Node. payload_json을 payload로 복원."""
    return Node(
        id=int(props["id"]),
        kind=NodeKind(props["kind"]),
        payload=json.loads(props.get("payload_json") or "{}"),
        state=props.get("state", "") or "",
        owner=props.get("owner", "") or "",
        priority=int(props.get("priority", 0) or 0),
        episode=int(props.get("episode", 0) or 0),
        anchors=list(props.get("anchors") or []))


def _base_props(kind: NodeKind, payload: dict, state: str, priority: int,
                anchors: Optional[list[int]]) -> dict:
    """노드 생성 시 쓸 프로퍼티. payload는 json 문자열로 평탄화."""
    return {
        "kind": kind.value, "state": state, "owner": "",
        "priority": int(priority), "payload_json": json.dumps(payload, ensure_ascii=False),
        "anchors": list(anchors or [])}


# ───────────── Cypher ─────────────
# NOTE: 쿼리엔 Cypher 맵 리터럴({name:...} 등)이 많아 str.format을 쓰면 그걸 포맷 필드로
# 오해해 깨진다. 라벨/관계만 .replace(토큰)로 끼운다(라벨·관계는 내부 상수라 주입 위험 없음).
_LABEL = "__LABEL__"
_RELTOK = "__REL__"

_NEXT = "MERGE (c:Counter {name:'explore_node'}) SET c.n = coalesce(c.n,0)+1 WITH c.n AS newid"

_CREATE = (_NEXT + " "
           "CREATE (n:Explore:" + _LABEL + " {id:newid, episode:$episode, kind:$kind, state:$state, "
           "owner:$owner, priority:$priority, payload_json:$payload_json, anchors:$anchors}) "
           "RETURN newid AS id")

# claim: 락 획득(SET) 후 재검사(WHERE) — lost update 방지
_CLAIM = (
    "MATCH (n:Intent {episode:$episode, state:'open'}) "
    "WITH n ORDER BY n.priority DESC, n.id ASC LIMIT 1 "
    "SET n.claim_seq = coalesce(n.claim_seq,0)+1 "      # 노드 락 획득
    "WITH n WHERE n.state = 'open' "                     # 락 쥔 채 재검사
    "SET n.state='running', n.owner=$worker "
    "RETURN n{.*} AS props")

_FRONTIER = ("MATCH (n:Intent {episode:$episode, state:'open'}) "
             "RETURN n{.*} AS props ORDER BY n.priority DESC, n.id ASC LIMIT $limit")
_RUNNING = "MATCH (n:Intent {episode:$episode, state:'running'}) RETURN n{.*} AS props"
_RECENT = ("MATCH (n:" + _LABEL + " {episode:$episode}) "
           "RETURN n{.*} AS props ORDER BY n.id DESC LIMIT $limit")
_GET = "MATCH (n:Explore {episode:$episode, id:$id}) RETURN n{.*} AS props"
_GOAL_EXISTING = "MATCH (n:Goal {episode:$episode}) RETURN n.id AS id ORDER BY n.id LIMIT 1"
# 이 회차 탐색 노드들이 앵커한 자산 id 전체(union) — explored/untouched 판정용
_ANCHORED = ("MATCH (n:Explore {episode:$episode}) "
             "UNWIND coalesce(n.anchors, []) AS aid RETURN DISTINCT aid AS aid")
_LINK = ("MATCH (a:Explore {episode:$episode, id:$src}), (b:Explore {episode:$episode, id:$dst}) "
         "CREATE (a)-[:" + _RELTOK + "]->(b)")
# 표시용 스냅샷(대시보드 공격 추적 그래프) — 이 회차 탐색 노드·엣지 전체
_SNAP_NODES = "MATCH (n:Explore {episode:$episode}) RETURN n{.*} AS props ORDER BY n.id"
_SNAP_EDGES = ("MATCH (a:Explore {episode:$episode})-[r]->(b:Explore {episode:$episode}) "
               "RETURN a.id AS src, type(r) AS rel, b.id AS dst")
_RESET = "MATCH (n:Explore {episode:$episode}) DETACH DELETE n"

_SCHEMA = [
    "CREATE INDEX explore_id IF NOT EXISTS FOR (n:Explore) ON (n.episode, n.id)",
    "CREATE INDEX intent_state IF NOT EXISTS FOR (n:Intent) ON (n.episode, n.state)",
    # (episode, dedup_key)는 add_finding 의 MERGE 키 — 유니크 제약으로 병렬 워커가 같은 발견을
    # 동시에 MERGE 해도 중복 Finding 이 안 생기게 한다. dedup_key 없는 발견은 null 이라 복합
    # 제약에서 자동 면제(_create 경로). 제약이 뒷받침 인덱스를 만드므로 기존 범위 인덱스는 버린다.
    "DROP INDEX finding_dedup IF EXISTS",
    "CREATE CONSTRAINT finding_dedup_uniq IF NOT EXISTS FOR (n:Finding) REQUIRE (n.episode, n.dedup_key) IS UNIQUE",
    # Counter(name)는 _NEXT 의 MERGE 키(여기선 explore_node) — 제약이 없으면 병렬 워커가 같은
    # 카운터를 동시 증가시켜 중복 노드 + 같은 id 재발급(노드 id 충돌)이 난다. :Counter 는 자산
    # 그래프와 공유(라벨 하나)라 두 스키마에 같은 제약을 IF NOT EXISTS 로 둔다.
    "CREATE CONSTRAINT counter_name_uniq IF NOT EXISTS FOR (n:Counter) REQUIRE n.name IS UNIQUE",
]


class Neo4jGraph(ExplorationGraph):
    """ExplorationGraph의 Neo4j 구현. driver는 neo4j.Driver(또는 동형 객체)."""

    def __init__(self, driver, *, episode: int, database: Optional[str] = None) -> None:
        self._driver = driver
        self._episode = episode
        self._db = database
        self._cur_round = 0                  # 현재 라운드 — 새 노드에 생성 라운드로 스탬프

    def set_round(self, round: int) -> None:
        """현재 라운드 설정 — 이후 추가 노드에 생성 라운드로 찍힌다(대시보드 라운드별 강조용)."""
        self._cur_round = int(round or 0)

    # ── 세션 헬퍼 ──
    def _run(self, query: str, **params) -> list:
        with self._driver.session(database=self._db) as s:
            return [r.data() for r in s.run(query, episode=self._episode, **params)]

    def ensure_schema(self) -> None:
        """인덱스·유니크 제약 생성(최초 1회). 운영 배포 시 호출."""
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
                            "(KG 는 다른 라벨이라 영향 없음). 그 뒤 다시 실행. "
                            f"원인: {e}") from e
                    raise

    def reset_episode(self) -> None:
        """이 회차의 탐색 노드만 통에서 비운다(KG는 :Explore 없어 보존)."""
        self._run(_RESET)

    def _create(self, label: str, kind: NodeKind, payload: dict, state: str,
                priority: int, anchors: Optional[list[int]]) -> int:
        payload = dict(payload); payload["_round"] = self._cur_round   # 생성 라운드 스탬프
        p = _base_props(kind, payload, state, priority, anchors)
        rows = self._run(_CREATE.replace(_LABEL, label), kind=p["kind"], state=p["state"],
                         owner=p["owner"], priority=p["priority"],
                         payload_json=p["payload_json"], anchors=p["anchors"])
        return int(rows[0]["id"])

    def _link(self, src: int, rel: Rel, dst: int) -> None:
        self._run(_LINK.replace(_RELTOK, _REL[rel]), src=src, dst=dst)

    # ── 쓰기 ──
    def add_goal(self, payload: dict, *, anchors: Optional[list[int]] = None) -> int:
        existing = self._run(_GOAL_EXISTING)      # 회차당 goal 하나 — 라운드마다 중복 생성 방지
        if existing:
            return int(existing[0]["id"])
        return self._create("Goal", NodeKind.GOAL, payload, "", 0, anchors)

    def add_intent(self, payload: dict, *, priority: int = 0,
                   anchors: Optional[list[int]] = None, origin: str = "planner",
                   spawned_by=None) -> int:
        nid = self._create("Intent", NodeKind.INTENT, payload,
                           IntentState.OPEN.value, priority, anchors)
        srcs = [spawned_by] if isinstance(spawned_by, int) else list(spawned_by or [])
        for src in srcs:                      # 출처→SPAWNS→의도 (Neo4j _link는 양쪽 존재 시만 엣지)
            self._link(src, Rel.SPAWNS, nid)
        return nid

    def add_fact(self, payload: dict, *, intent_id: Optional[int] = None,
                 anchors: Optional[list[int]] = None,
                 derived_from: Optional[list[int]] = None) -> int:
        nid = self._create("Fact", NodeKind.FACT, payload, "confirmed", 0, anchors)
        if intent_id is not None:
            self._link(intent_id, Rel.YIELDS, nid)
        for src in (derived_from or []):
            self._link(nid, Rel.DERIVED_FROM, src)
        return nid

    def add_finding(self, payload: dict, *, proved_by: Optional[list[int]] = None,
                    anchors: Optional[list[int]] = None,
                    dedup_key: Optional[str] = None) -> int:
        if dedup_key:
            # 같은 dedup_key를 get-or-merge. 동시 워커 안전은 (episode,dedup_key) 유니크 제약이
            # 보장한다(_SCHEMA) — execute_write 는 원자성·재시도만 주지 유일성은 제약 몫.
            nid = self._driver.session(database=self._db).execute_write(
                self._merge_finding_tx, dedup_key, payload, anchors)
        else:
            nid = self._create("Finding", NodeKind.FINDING, payload, "claimed", 0, anchors)
        for src in (proved_by or []):
            self._link(src, Rel.PROVES, nid)
        return nid

    def _merge_finding_tx(self, tx, dedup_key: str, payload: dict,
                          anchors: Optional[list[int]]) -> int:
        """트랜잭션 함수: (episode, dedup_key) finding을 get-or-create하고 병합.
        MERGE가 노드를 원자적으로 확보 → 그 안에서 payload 병합(공유 규칙)."""
        rec = tx.run(
            "MERGE (n:Finding {episode:$episode, dedup_key:$dkey}) "
            "ON CREATE SET n:Explore, n.created=true "
            "RETURN n.id AS id, n.payload_json AS pj, n.created AS created",
            episode=self._episode, dkey=dedup_key).single()
        if rec.get("created"):
            # 신규: id 발급 + 초기 payload 기록
            idrow = tx.run(_NEXT + " RETURN newid").single()
            nid = int(idrow["newid"])
            p = _base_props(NodeKind.FINDING, payload, "claimed", 0, anchors)
            tx.run("MATCH (n:Finding {episode:$episode, dedup_key:$dkey}) "
                    "SET n.id=$id, n.kind=$kind, n.state=$state, n.owner=$owner, "
                    "n.priority=$priority, n.payload_json=$pj, n.anchors=$anchors "
                    "REMOVE n.created",
                    episode=self._episode, dkey=dedup_key, id=nid, kind=p["kind"],
                    state=p["state"], owner=p["owner"], priority=p["priority"],
                    pj=p["payload_json"], anchors=p["anchors"])
            return nid
        # 기존: payload 병합 후 기록
        nid = int(rec["id"])
        existing = json.loads(rec.get("pj") or "{}")
        merged = merge_finding_payload(existing, payload)
        tx.run("MATCH (n:Finding {episode:$episode, dedup_key:$dkey}) SET n.payload_json=$pj",
                episode=self._episode, dkey=dedup_key,
                pj=json.dumps(merged, ensure_ascii=False))
        return nid

    # ── frontier / claim ──
    def frontier(self, limit: int = 20) -> list[Node]:
        return [_node_from_props(r["props"]) for r in self._run(_FRONTIER, limit=limit)]

    def claim_next(self, worker: str, limit: int = 20) -> Optional[Node]:
        rows = self._run(_CLAIM, worker=worker)
        return _node_from_props(rows[0]["props"]) if rows else None

    def settle_intent(self, intent_id: int, state: IntentState, reason: str = "") -> bool:
        return bool(self._driver.session(database=self._db).execute_write(
            self._settle_tx, intent_id, state.value, reason))

    def _settle_tx(self, tx, intent_id: int, state: str, reason: str) -> bool:
        rec = tx.run("MATCH (n:Intent {episode:$episode, id:$id, state:'running'}) "
                     "RETURN n.payload_json AS pj",
                     episode=self._episode, id=intent_id).single()
        if rec is None:
            return False
        payload = json.loads(rec.get("pj") or "{}")
        if reason:
            payload["settle_reason"] = reason
        tx.run("MATCH (n:Intent {episode:$episode, id:$id}) SET n.state=$state, n.payload_json=$pj",
                episode=self._episode, id=intent_id, state=state,
                pj=json.dumps(payload, ensure_ascii=False))
        return True

    def reopen_intent(self, intent_id: int) -> bool:
        rows = self._run("MATCH (n:Intent {episode:$episode, id:$id}) "
                         "SET n.state='open', n.owner='' RETURN n.id AS id", id=intent_id)
        return bool(rows)

    def anchor_to(self, node_id: int, asset_ids: list[int]) -> None:
        if not asset_ids:
            return
        # anchors 속성에 새 id만 추가 + 자산 노드에 ANCHORED_TO 엣지(존재하는 자산만)
        self._run(
            "MATCH (n:Explore {episode:$episode, id:$id}) "
            "SET n.anchors = coalesce(n.anchors, []) + "
            "    [x IN $aids WHERE NOT x IN coalesce(n.anchors, [])] "
            "WITH n UNWIND $aids AS aid "
            "MATCH (a:Asset {episode:$episode, id:aid}) "
            "MERGE (n)-[:ANCHORED_TO]->(a)",
            id=node_id, aids=list(asset_ids))

    def select_knowledge(self, node_id: int, technique_ids: list[str]) -> None:
        tids = [str(t).strip() for t in technique_ids if str(t).strip()]
        if not tids:
            return
        # payload 에 선택 기법 누적(InMemory 와 일관) + 존재하는 KG Technique 노드로 SELECTED MERGE.
        # Technique 는 KG 라벨(episode 비스코프)이라 id 로만 매칭 — 없는 기법은 엣지 생략.
        self._run(
            "MATCH (n:Explore {episode:$episode, id:$id}) "
            "SET n.selected_techniques = coalesce(n.selected_techniques, []) + "
            "    [x IN $tids WHERE NOT x IN coalesce(n.selected_techniques, [])] "
            "WITH n UNWIND $tids AS tid "
            "MATCH (t:Technique {id: tid}) "
            "MERGE (n)-[:SELECTED]->(t)",
            id=node_id, tids=tids)

    # ── 읽기 ──
    def get_node(self, node_id: int) -> Optional[Node]:
        rows = self._run(_GET, id=node_id)
        return _node_from_props(rows[0]["props"]) if rows else None

    def recent_facts(self, limit: int = 20) -> list[Node]:
        return [_node_from_props(r["props"])
                for r in self._run(_RECENT.replace(_LABEL, "Fact"), limit=limit)]

    def recent_findings(self, limit: int = 20) -> list[Node]:
        return [_node_from_props(r["props"])
                for r in self._run(_RECENT.replace(_LABEL, "Finding"), limit=limit)]

    def running_intents(self) -> list[Node]:
        return [_node_from_props(r["props"]) for r in self._run(_RUNNING)]

    def anchored_asset_ids(self) -> set[int]:
        return {int(r["aid"]) for r in self._run(_ANCHORED)}

    # ── 표시용 스냅샷(대시보드 공격 추적 그래프) — InMemoryGraph.snapshot()과 동일 스키마 ──
    def snapshot(self) -> dict:
        """이 회차 탐색 그래프 전체(노드·엣지)를 표시용 dict 로. 판정 무관·표시 전용.

        payload 에서 표시 필드만 평탄화. 엣지 관계는 소문자로(대시보드 relColor/relLabel 키와 일치).
        """
        nodes = []
        for row in self._run(_SNAP_NODES):
            n = _node_from_props(row["props"])
            p = n.payload or {}
            nodes.append({
                "id": n.id,
                "kind": n.kind.value if hasattr(n.kind, "value") else str(n.kind),
                "state": n.state, "owner": n.owner, "priority": n.priority,
                "summary": p.get("summary", ""), "target": p.get("target", ""),
                "why": p.get("why", ""), "technique": p.get("technique", ""),
                "evidence": p.get("evidence", ""), "detail": p.get("detail", ""),
                "desc": p.get("desc", ""),            # 사람이 읽는 상세 설명(노드 큐레이션)
                "loot": p.get("loot"),                # 실제 탈취/확보한 값(표시 전용)
                "severity": p.get("severity", ""), "confidence": p.get("confidence"),
                "occurrences": p.get("occurrences"), "anchors": list(n.anchors),
                "round": p.get("_round"),             # 생성 라운드(대시보드 라운드별 추가 강조)
            })
        edges = [{"src": int(r["src"]), "rel": str(r["rel"]).lower(), "dst": int(r["dst"])}
                 for r in self._run(_SNAP_EDGES)]
        return {"nodes": nodes, "edges": edges}


def connect_driver(uri: str, user: str, password: str):
    """neo4j 드라이버만 만든다(지연 import). 하네스가 한 드라이버를 회차마다 재사용."""
    from neo4j import GraphDatabase          # noqa: PLC0415 — 지연 import(미설치 환경 보호)
    return GraphDatabase.driver(uri, auth=(user, password))


def connect(uri: str, user: str, password: str, *, database: Optional[str] = None,
            episode: int = 0):
    """드라이버 생성 + Neo4jGraph + 스키마까지(단발 사용·계약 테스트용)."""
    driver = connect_driver(uri, user, password)
    g = Neo4jGraph(driver, episode=episode, database=database)
    g.ensure_schema()
    return g


__all__ = ["Neo4jGraph", "connect", "connect_driver", "_node_from_props", "_base_props"]
