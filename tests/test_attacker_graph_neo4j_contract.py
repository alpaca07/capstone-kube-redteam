"""Neo4j 어댑터 '계약 테스트' — 실 Neo4j 대상. VM A에서 실행.

인메모리 그래프와 '같은 불변식'을 실 DB로 재검증한다. 특히 claim의 원자성(동시 워커가
같은 의도 못 집음)은 실 Neo4j에서만 진짜로 확인된다(단위 테스트는 쿼리 패턴만 봄).

드라이버 미설치 또는 환경변수 미설정 시 SKIP(비실패). 설정 예(VM A):
    pip install neo4j
    export NEO4J_URI=bolt://127.0.0.1:7687
    export NEO4J_USER=neo4j
    export NEO4J_PASS=<비밀번호>
    # (선택) export NEO4J_DB=neo4j
    python3 tests/test_attacker_graph_neo4j_contract.py

테스트는 타임스탬프 기반 고유 episode를 써 기존 데이터를 안 건드리고, 끝에 그 episode만
reset(DETACH DELETE)로 정리한다.
"""
from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.graph import IntentState, NodeKind, Rel  # noqa: E402


def _skip(msg: str) -> int:
    print(f"  \033[33mSKIP\033[0m — {msg}")
    print("\n0 passed, 0 failed (SKIPPED)")
    return 0


def _connect():
    uri = os.environ.get("NEO4J_URI")
    user = os.environ.get("NEO4J_USER", "neo4j")
    pw = os.environ.get("NEO4J_PASS")
    db = os.environ.get("NEO4J_DB")
    if not uri or not pw:
        return None, "NEO4J_URI/NEO4J_PASS 미설정"
    try:
        import neo4j  # noqa: F401
    except ImportError:
        return None, "neo4j 드라이버 미설치 (pip install neo4j)"
    from attacker.graph_neo4j import connect
    ep = int(time.time())                      # 고유 에피소드(기존 데이터 보호)
    try:
        g = connect(uri, user, pw, database=db, episode=ep)
    except Exception as e:  # noqa: BLE001
        return None, f"연결 실패: {type(e).__name__}: {e}"
    return g, None


def _checks(g) -> None:
    # 1) add_intent → frontier(open)
    i1 = g.add_intent({"summary": "probe pg", "target": "postgres", "technique": "T1046"},
                      priority=5)
    i2 = g.add_intent({"summary": "low pri"}, priority=1)
    fr = g.frontier()
    assert {n.id for n in fr} >= {i1, i2}, "frontier에 추가한 의도가 없음"
    # 우선순위 정렬: 높은(i1) 먼저
    ids_in_order = [n.id for n in fr]
    assert ids_in_order.index(i1) < ids_in_order.index(i2), "frontier 우선순위 정렬 틀림"

    # 2) claim: open→running + owner
    n = g.claim_next("wA")
    assert n is not None and n.state == IntentState.RUNNING.value and n.owner == "wA"
    claimed_id = n.id

    # 3) settle running→done(+reason), payload에 settle_reason
    assert g.settle_intent(claimed_id, IntentState.DONE, reason="got it") is True
    got = g.get_node(claimed_id)
    assert got.state == IntentState.DONE.value
    assert got.payload.get("settle_reason") == "got it"
    # done은 더 이상 settle 안 됨(running만)
    assert g.settle_intent(claimed_id, IntentState.STOPPED) is False

    # 4) blocked→reopen→재claim
    ib = g.add_intent({"summary": "to block"})
    g.claim_next("wB"); g.settle_intent(ib, IntentState.BLOCKED)
    assert g.reopen_intent(ib) is True
    re = g.claim_next("wC")
    assert re is not None, "reopen 후 재claim 실패"

    # 5) fact: intent→YIELDS→fact, payload·source_step_ids 복원
    iy = g.add_intent({"summary": "yielder"}); g.claim_next("wD")
    f = g.add_fact({"summary": "pg reachable", "source_step_ids": ["1.1", "1.2"]}, intent_id=iy)
    fn = g.get_node(f)
    assert fn.kind == NodeKind.FACT and fn.payload["source_step_ids"] == ["1.1", "1.2"]
    rf = g.recent_facts()
    assert any(x.id == f for x in rf), "recent_facts에 fact 없음"

    # 6) finding dedup: 같은 기법 2번 → 1개로 병합(occurrences=2, severity max)
    fa = g.add_fact({"summary": "creds observed"})
    g.add_finding({"summary": "creds v1", "severity": "high", "technique": "T1552"},
                  proved_by=[fa], dedup_key="T1552")
    g.add_finding({"summary": "creds v2", "severity": "critical", "technique": "T1552"},
                  dedup_key="T1552")
    finds = [x for x in g.recent_findings() if x.payload.get("technique") == "T1552"]
    assert len(finds) == 1, f"dedup 실패: finding {len(finds)}개"
    assert finds[0].payload["severity"] == "critical"
    assert finds[0].payload.get("occurrences") == 2

    # 7) running_intents
    ir = g.add_intent({"summary": "runner"}); g.claim_next("wE")
    assert any(x.id == ir for x in g.running_intents()), "running_intents 누락"


def _concurrency_check(g) -> None:
    """★ 핵심: 워커 다수가 동시에 집어도 한 의도는 한 번만 claim(이중 claim 없음)."""
    n_intents = 60
    seeded = [g.add_intent({"summary": f"c{k}"}) for k in range(n_intents)]
    seeded_set = set(seeded)

    claimed: list[int] = []
    lock = threading.Lock()
    start = threading.Event()

    def grab():
        start.wait()
        while True:
            node = g.claim_next(threading.current_thread().name)
            if node is None:
                # 다른 워커가 아직 claim 경합 중일 수 있으니, frontier에 우리 의도가
                # 남아있으면 잠깐 재시도
                remaining = [x for x in g.frontier(limit=1000) if x.id in seeded_set]
                if not remaining:
                    return
                time.sleep(0.01)
                continue
            if node.id in seeded_set:
                with lock:
                    claimed.append(node.id)

    threads = [threading.Thread(target=grab, name=f"w{t}") for t in range(8)]
    for t in threads:
        t.start()
    start.set()
    for t in threads:
        t.join()

    assert len(claimed) == n_intents, f"claim 수 {len(claimed)} ≠ {n_intents}(누락)"
    assert len(set(claimed)) == n_intents, "★ 이중 claim 발생(원자성 깨짐)"


def _run() -> int:
    g, err = _connect()
    if g is None:
        return _skip(err)
    print(f"  (실 Neo4j 연결 OK — episode={g._episode})")
    passed = failed = 0
    for name, fn in [("기본 불변식", _checks), ("동시 claim 원자성", _concurrency_check)]:
        try:
            fn(g)
            print(f"  \033[32m✓\033[0m {name}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  \033[31m✗\033[0m {name}: {type(e).__name__}: {e}")
            traceback.print_exc()
            failed += 1
    try:
        g.reset_episode()                      # 이 테스트 episode만 정리
        print("  (episode 정리 완료)")
    except Exception as e:  # noqa: BLE001
        print(f"  (정리 실패: {e})")
    print(f"\n{passed} passed, {failed} failed  (총 2)")
    return 1 if failed else 0


if __name__ == "__main__":
    print("── Neo4j 어댑터 계약 테스트(실 DB) ──")
    sys.exit(_run())
