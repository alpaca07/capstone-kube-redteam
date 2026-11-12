"""탐색 그래프 이음새(인메모리 fake) 테스트 — frontier·원자적 claim·상태전이·관계.

    python3 tests/test_attacker_graph.py
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.graph import IntentState, NodeKind, Rel  # noqa: E402
from attacker.graph_fake import InMemoryGraph  # noqa: E402


def test_add_intent_lands_open_in_frontier():
    g = InMemoryGraph(episode=1)
    i = g.add_intent({"summary": "probe postgres"}, priority=5)
    fr = g.frontier()
    assert len(fr) == 1 and fr[0].id == i
    assert fr[0].kind == NodeKind.INTENT and fr[0].state == IntentState.OPEN.value
    assert fr[0].episode == 1


def test_frontier_orders_by_priority_then_id():
    g = InMemoryGraph()
    a = g.add_intent({"s": "a"}, priority=1)
    b = g.add_intent({"s": "b"}, priority=9)
    c = g.add_intent({"s": "c"}, priority=9)
    ids = [n.id for n in g.frontier()]
    # 우선순위 높은 b,c 먼저(같으면 먼저 생성된 b), 그 뒤 a
    assert ids == [b, c, a]


def test_claim_moves_open_to_running_with_owner():
    g = InMemoryGraph()
    i = g.add_intent({"s": "x"})
    n = g.claim_next("worker-1")
    assert n is not None and n.id == i
    assert n.state == IntentState.RUNNING.value and n.owner == "worker-1"
    # claim된 의도는 frontier에서 빠진다
    assert g.frontier() == []


def test_claim_empty_frontier_returns_none():
    g = InMemoryGraph()
    assert g.claim_next("w") is None


def test_claim_is_atomic_under_concurrency():
    """핵심 불변식: 워커 여럿이 동시에 집어도 한 의도는 한 번만 claim된다."""
    g = InMemoryGraph()
    n_intents = 50
    for k in range(n_intents):
        g.add_intent({"s": f"i{k}"})

    claimed: list[int] = []
    claimed_lock = threading.Lock()
    start = threading.Event()

    def grab():
        start.wait()
        while True:
            node = g.claim_next(threading.current_thread().name)
            if node is None:
                return
            with claimed_lock:
                claimed.append(node.id)

    threads = [threading.Thread(target=grab, name=f"w{t}") for t in range(8)]
    for t in threads:
        t.start()
    start.set()
    for t in threads:
        t.join()

    # 모든 의도가 정확히 한 번씩 claim됨(중복·누락 없음)
    assert len(claimed) == n_intents
    assert len(set(claimed)) == n_intents
    # 남은 open 없음
    assert g.frontier() == []
    # running으로 다 넘어감
    assert len(g.running_intents()) == n_intents


def test_settle_only_running():
    g = InMemoryGraph()
    i = g.add_intent({"s": "x"})
    # open 상태에서는 종료 전이 거부(running만 가능)
    assert g.settle_intent(i, IntentState.DONE) is False
    g.claim_next("w")
    assert g.settle_intent(i, IntentState.DONE, reason="got fact") is True
    assert g.get_node(i).state == IntentState.DONE.value
    assert g.get_node(i).payload.get("settle_reason") == "got fact"


def test_blocked_then_reopen_is_reclaimable():
    g = InMemoryGraph()
    i = g.add_intent({"s": "x"})
    g.claim_next("w1")
    g.settle_intent(i, IntentState.BLOCKED)
    assert g.frontier() == []          # blocked는 아직 frontier에 없음
    assert g.reopen_intent(i) is True
    fr = g.frontier()
    assert len(fr) == 1 and fr[0].id == i and fr[0].owner == ""
    n = g.claim_next("w2")             # 다시 집을 수 있다
    assert n.id == i and n.owner == "w2"


def test_fact_links_from_intent_yields():
    g = InMemoryGraph()
    i = g.add_intent({"s": "probe"})
    g.claim_next("w")
    f = g.add_fact({"summary": "port open", "source_step_ids": ["1.1"]}, intent_id=i)
    edges = g.edges_from(i, Rel.YIELDS)
    assert len(edges) == 1 and edges[0].dst_id == f
    assert g.get_node(f).kind == NodeKind.FACT
    assert g.get_node(f).payload["source_step_ids"] == ["1.1"]


def test_finding_proved_by_facts():
    g = InMemoryGraph()
    f1 = g.add_fact({"summary": "creds found"})
    f2 = g.add_fact({"summary": "db reachable"})
    find = g.add_finding({"summary": "PII readable"}, proved_by=[f1, f2])
    assert len(g.edges_from(f1, Rel.PROVES)) == 1
    assert len(g.edges_from(f2, Rel.PROVES)) == 1
    assert g.edges_from(f1, Rel.PROVES)[0].dst_id == find


def test_derived_from_chains_facts():
    g = InMemoryGraph()
    base = g.add_fact({"summary": "leaked connstr"})
    deriv = g.add_fact({"summary": "full DSN assembled"}, derived_from=[base])
    edges = g.edges_from(deriv, Rel.DERIVED_FROM)
    assert len(edges) == 1 and edges[0].dst_id == base


def test_recent_facts_newest_first():
    g = InMemoryGraph()
    g.add_fact({"summary": "f1"})
    g.add_fact({"summary": "f2"})
    g.add_fact({"summary": "f3"})
    recents = g.recent_facts(limit=2)
    assert [n.payload["summary"] for n in recents] == ["f3", "f2"]


def test_returned_nodes_are_copies():
    """바깥에서 노드를 만져도 저장소가 안 바뀐다(사본 반환)."""
    g = InMemoryGraph()
    i = g.add_intent({"s": "x"})
    n = g.get_node(i)
    n.payload["s"] = "mutated"
    n.state = "hacked"
    assert g.get_node(i).payload["s"] == "x"
    assert g.get_node(i).state == IntentState.OPEN.value


# ── anchored_asset_ids: 모든 노드의 앵커 합집합(explored 자산 판정용) ──
def test_anchored_asset_ids_union():
    g = InMemoryGraph()
    i1 = g.add_intent({"s": "a"})
    i2 = g.add_intent({"s": "b"})
    assert g.anchored_asset_ids() == set()          # 앵커 전엔 빈 집합
    g.anchor_to(i1, [10, 11])
    g.anchor_to(i2, [11, 12])                        # 11 중복 → 합집합에서 하나
    f = g.add_finding({"summary": "breach"}, anchors=[20])   # finding 앵커도 포함
    assert f                                          # 노드 생성됨
    assert g.anchored_asset_ids() == {10, 11, 12, 20}


def test_snapshot_flattens_nodes_and_edges():
    g = InMemoryGraph(episode=2)
    goal = g.add_goal({"summary": "crown"})
    it = g.add_intent({"summary": "probe", "technique": "T1078", "target": "ns/sa"},
                      spawned_by=goal)
    fid = g.add_fact({"summary": "sa over-privileged", "evidence": "can-i yes"}, intent_id=it)
    g.add_finding({"summary": "secret exfil", "severity": "critical", "desc": "DB 비밀 탈취",
                   "loot": {"user": "app_admin", "password": "p@ss"}}, proved_by=[fid])
    snap = g.snapshot()
    kinds = {n["kind"] for n in snap["nodes"]}
    assert kinds == {"goal", "intent", "fact", "finding"}
    rels = {e["rel"] for e in snap["edges"]}
    assert "spawns" in rels and "yields" in rels and "proves" in rels
    intent = next(n for n in snap["nodes"] if n["kind"] == "intent")
    assert intent["technique"] == "T1078" and intent["target"] == "ns/sa"
    # 상세설명·탈취데이터 통과(대시보드 노드 큐레이션용)
    finding = next(n for n in snap["nodes"] if n["kind"] == "finding")
    assert finding["desc"] == "DB 비밀 탈취" and finding["loot"]["password"] == "p@ss"
    import json
    assert isinstance(json.dumps(snap), str)          # 교차망 전송 직렬화 가능


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
    print("── 탐색 그래프 이음새 테스트 ──")
    sys.exit(_run())
