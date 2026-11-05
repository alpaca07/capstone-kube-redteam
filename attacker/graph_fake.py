"""인메모리 탐색 그래프 — ExplorationGraph 계약의 테스트/오프라인 구현.

실 Neo4j 없이 플래너·워커 풀·실행레인을 돌려보기 위한 '큰 어댑터·작은 구현'.
claim_next의 원자성은 스레드 락으로 보장한다 — 워커 N(스레드)이 동시에 불러도
같은 의도를 둘이 집지 못한다(ARTEX의 CAS `WHERE state='open'`과 같은 의미를 락으로).

단일 프로세스·단일 작성자 전제라 락이면 충분(이번 세션 확정). Neo4j 어댑터는 같은
계약을 조건부 MATCH(CAS)로 구현하고, 워커 코드는 어느 쪽이든 안 바뀐다.
"""
from __future__ import annotations

import threading
from typing import Optional

from .graph import (
    Edge, ExplorationGraph, IntentState, Node, NodeKind, Rel,
)


class InMemoryGraph(ExplorationGraph):
    def __init__(self, *, episode: int = 0) -> None:
        self._episode = episode
        self._lock = threading.Lock()        # claim 및 모든 변이의 원자성
        self._nodes: dict[int, Node] = {}
        self._edges: list[Edge] = []
        self._seq = 0                        # 노드 id 발급(단조 증가)

    # ── 내부 헬퍼(락 안에서만 호출) ──
    def _new_node(self, kind: NodeKind, payload: dict, state: str,
                  priority: int, anchors: Optional[list[int]], owner: str = "") -> int:
        self._seq += 1
        nid = self._seq
        self._nodes[nid] = Node(
            id=nid, kind=kind, payload=dict(payload), state=state, owner=owner,
            priority=priority, episode=self._episode, anchors=list(anchors or []))
        return nid

    def _link(self, src: int, rel: Rel, dst: int) -> None:
        self._edges.append(Edge(src_id=src, rel=rel, dst_id=dst))

    # ── 쓰기 ──
    def add_intent(self, payload: dict, *, priority: int = 0,
                   anchors: Optional[list[int]] = None, origin: str = "planner",
                   spawned_by: Optional[int] = None) -> int:
        with self._lock:
            nid = self._new_node(NodeKind.INTENT, payload, IntentState.OPEN.value,
                                 priority, anchors)
            if spawned_by is not None:
                self._link(spawned_by, Rel.SPAWNS, nid)
            return nid

    def add_fact(self, payload: dict, *, intent_id: Optional[int] = None,
                 anchors: Optional[list[int]] = None,
                 derived_from: Optional[list[int]] = None) -> int:
        with self._lock:
            nid = self._new_node(NodeKind.FACT, payload, "confirmed", 0, anchors)
            if intent_id is not None:
                self._link(intent_id, Rel.YIELDS, nid)
            for src in (derived_from or []):
                self._link(nid, Rel.DERIVED_FROM, src)
            return nid

    def add_finding(self, payload: dict, *, proved_by: Optional[list[int]] = None,
                    anchors: Optional[list[int]] = None) -> int:
        with self._lock:
            nid = self._new_node(NodeKind.FINDING, payload, "claimed", 0, anchors)
            for src in (proved_by or []):
                self._link(src, Rel.PROVES, nid)
            return nid

    # ── frontier / claim ──
    def _open_intents_sorted(self) -> list[Node]:
        opens = [n for n in self._nodes.values()
                 if n.kind == NodeKind.INTENT and n.state == IntentState.OPEN.value]
        # 우선순위 높은 것 먼저, 같으면 먼저 생성된 것(id 오름차순)
        opens.sort(key=lambda n: (-n.priority, n.id))
        return opens

    def frontier(self, limit: int = 20) -> list[Node]:
        with self._lock:
            return [self._copy(n) for n in self._open_intents_sorted()[:limit]]

    def claim_next(self, worker: str, limit: int = 20) -> Optional[Node]:
        # 락이 CAS를 대신한다: open→running 전이를 한 워커만 통과시킨다.
        with self._lock:
            for n in self._open_intents_sorted()[:limit]:
                # 락 안이라 여기 온 시점에 반드시 아직 open — 바로 집는다.
                n.state = IntentState.RUNNING.value
                n.owner = worker
                return self._copy(n)
            return None

    def settle_intent(self, intent_id: int, state: IntentState,
                      reason: str = "") -> bool:
        with self._lock:
            n = self._nodes.get(intent_id)
            if n is None or n.kind != NodeKind.INTENT:
                return False
            if n.state != IntentState.RUNNING.value:
                return False  # running 중인 것만 종료 전이
            n.state = state.value
            if reason:
                n.payload = {**n.payload, "settle_reason": reason}
            return True

    def reopen_intent(self, intent_id: int) -> bool:
        with self._lock:
            n = self._nodes.get(intent_id)
            if n is None or n.kind != NodeKind.INTENT:
                return False
            n.state = IntentState.OPEN.value
            n.owner = ""
            return True

    # ── 읽기 ──
    def _copy(self, n: Node) -> Node:
        """호출자에게 내부 노드의 사본을 준다(바깥 변이가 저장소를 안 건드리게)."""
        return Node(id=n.id, kind=n.kind, payload=dict(n.payload), state=n.state,
                    owner=n.owner, priority=n.priority, episode=n.episode,
                    anchors=list(n.anchors))

    def get_node(self, node_id: int) -> Optional[Node]:
        with self._lock:
            n = self._nodes.get(node_id)
            return self._copy(n) if n else None

    def recent_facts(self, limit: int = 20) -> list[Node]:
        with self._lock:
            facts = [n for n in self._nodes.values() if n.kind == NodeKind.FACT]
            facts.sort(key=lambda n: n.id, reverse=True)
            return [self._copy(n) for n in facts[:limit]]

    def running_intents(self) -> list[Node]:
        with self._lock:
            return [self._copy(n) for n in self._nodes.values()
                    if n.kind == NodeKind.INTENT
                    and n.state == IntentState.RUNNING.value]

    # ── 테스트 편의 ──
    def edges_from(self, src_id: int, rel: Optional[Rel] = None) -> list[Edge]:
        with self._lock:
            return [e for e in self._edges
                    if e.src_id == src_id and (rel is None or e.rel == rel)]


__all__ = ["InMemoryGraph"]
