"""Neo4j 어댑터 '순수 부분' 단위 테스트 — 드라이버·DB 불필요.

매핑(props↔Node)·병합 규칙·Cypher 상수의 핵심 불변식(claim의 락-후-재검사 패턴 등)만
검증한다. 실 Neo4j 대상 동시성·쿼리 정합은 tests/test_attacker_graph_neo4j_contract.py
(VM A, 실 DB)에서.

    python3 tests/test_attacker_graph_neo4j_unit.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.graph import NodeKind, merge_finding_payload  # noqa: E402
from attacker.graph_neo4j import _base_props, _node_from_props  # noqa: E402
from attacker import graph_neo4j as gn  # noqa: E402


# ── props → Node 복원 ──
def test_node_from_props_roundtrip():
    payload = {"summary": "probe pg", "target": "postgres", "technique": "T1046",
               "source_step_ids": ["1.1", "1.2"]}
    props = {"id": 7, "kind": "intent", "state": "open", "owner": "",
             "priority": 5, "episode": 3, "anchors": [10, 11],
             "payload_json": json.dumps(payload)}
    n = _node_from_props(props)
    assert n.id == 7 and n.kind == NodeKind.INTENT and n.state == "open"
    assert n.priority == 5 and n.episode == 3 and n.anchors == [10, 11]
    assert n.payload == payload                       # payload 완전 복원


def test_node_from_props_empty_payload():
    n = _node_from_props({"id": 1, "kind": "fact", "payload_json": None})
    assert n.payload == {} and n.kind == NodeKind.FACT


# ── 생성 props: payload를 json 문자열로 평탄화 ──
def test_base_props_flattens_payload():
    p = _base_props(NodeKind.FINDING, {"summary": "creds", "severity": "high"},
                    "claimed", 0, [1, 2])
    assert p["kind"] == "finding" and p["state"] == "claimed"
    assert p["anchors"] == [1, 2]
    assert json.loads(p["payload_json"]) == {"summary": "creds", "severity": "high"}


# ── props↔생성 왕복: _base_props로 만든 걸 _node_from_props가 되돌림 ──
def test_props_create_read_roundtrip():
    payload = {"summary": "x", "reports": ["a", "b"], "occurrences": 2}
    p = _base_props(NodeKind.FINDING, payload, "claimed", 3, None)
    props = {**p, "id": 42, "episode": 1}
    n = _node_from_props(props)
    assert n.id == 42 and n.priority == 3 and n.payload == payload


# ── claim 쿼리: lost-update 방지 패턴(락 획득 SET → 재검사 WHERE)이 들어있나 ──
def test_claim_cypher_has_lock_then_recheck():
    q = gn._CLAIM
    # open만 매치
    assert "state:'open'" in q
    # 락 획득용 선행 SET(claim_seq)
    assert "SET n.claim_seq" in q
    # 락 쥔 뒤 상태 재검사
    assert "WHERE n.state = 'open'" in q
    # 재검사 통과해야 running 전이
    assert "SET n.state='running'" in q
    # claim_seq 증가(락)가 running 전이보다 '먼저' 와야(순서가 패턴의 핵심)
    assert q.index("SET n.claim_seq") < q.index("WHERE n.state = 'open'") < q.index("SET n.state='running'")


# ── frontier 정렬: 우선순위 내림차순, id 오름차순(인메모리와 동일) ──
def test_frontier_cypher_ordering():
    assert "ORDER BY n.priority DESC, n.id ASC" in gn._FRONTIER


# ── reset: :Explore + episode만 지움(KG 보존 전제) ──
def test_reset_cypher_scoped_to_episode_explore():
    assert "n:Explore {episode:$episode}" in gn._RESET
    assert "DETACH DELETE" in gn._RESET


# ── 병합 규칙은 인메모리와 같은 공유 함수 ──
def test_shared_merge_rule():
    base = {"summary": "a", "severity": "high"}
    merged = merge_finding_payload(base, {"summary": "b", "severity": "critical"})
    assert merged["severity"] == "critical"
    assert merged["occurrences"] == 2
    assert merged["reports"] == ["a", "b"]


# ── 라벨/관계 치환이 Cypher 맵 리터럴을 안 깨뜨림(KeyError 'name' 버그 회귀 방지) ──
def test_label_substitution_does_not_break_cypher_literals():
    # _CREATE엔 {name:'explore_node'}·{id:newid...} 같은 Cypher 맵이 있다.
    # 라벨 치환 후에도 그 리터럴들이 온전해야 한다(str.format이었으면 여기서 깨짐).
    q = gn._CREATE.replace(gn._LABEL, "Intent")
    assert gn._LABEL not in q                       # 토큰 소진
    assert "n:Explore:Intent" in q                   # 라벨 끼워짐
    assert "{name:'explore_node'}" in q              # Counter 맵 리터럴 온전
    assert "{id:newid" in q                          # 노드 맵 리터럴 온전
    # 관계 치환
    lk = gn._LINK.replace(gn._RELTOK, "SPAWNS")
    assert gn._RELTOK not in lk and "[:SPAWNS]" in lk
    assert "{episode:$episode, id:$src}" in lk        # 맵 리터럴 온전
    # recent
    rc = gn._RECENT.replace(gn._LABEL, "Fact")
    assert gn._LABEL not in rc and "n:Fact" in rc and "n{.*}" in rc


# ── 모듈이 드라이버 없이 import됨(지연 import 보장) ──
def test_module_imports_without_driver():
    # import 자체가 위에서 성공했고, connect만 드라이버를 요구
    assert hasattr(gn, "Neo4jGraph") and hasattr(gn, "connect")


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
    print("── Neo4j 어댑터 단위 테스트(순수) ──")
    sys.exit(_run())
