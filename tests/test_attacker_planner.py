"""플래너 테스트 — 태세 렌더링·의도 파싱(느슨)·중복방지 컨텍스트·목표달성 신호·그래프 반영.

LLM은 fake로 주입. 실제 정렬 모델 호출은 안 한다(로직만 검증).

    python3 tests/test_attacker_planner.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.graph import IntentState, NodeKind, Rel  # noqa: E402
from attacker.graph_fake import InMemoryGraph  # noqa: E402
from attacker.planner import (  # noqa: E402
    Planner, build_situation, parse_intents,
)


class _FakeLLM:
    """미리 심은 응답을 순서대로 돌려주고, 받은 (system,user)를 기록."""

    def __init__(self, replies):
        self._replies = list(replies)
        self.calls: list[tuple[str, str]] = []

    def chat_text(self, system, user, **kw):
        self.calls.append((system, user))
        if not self._replies:
            return '{"intents": []}'
        return self._replies.pop(0)


_TWO_INTENTS = ('{"intents": ['
                '{"summary": "probe postgres reachability", "target": "postgres.database", '
                '"why": "path to PII", "technique": "T1046"},'
                '{"summary": "enumerate admin-dashboard SA", "target": "admin-dashboard", '
                '"why": "priv path", "technique": "T1078"}]}')


# ── 파싱: 정상 ──
def test_parse_two_intents():
    its = parse_intents(_TWO_INTENTS)
    assert len(its) == 2
    assert its[0].summary.startswith("probe postgres")
    assert its[0].technique == "T1046"


# ── 파싱: 느슨(펜스·잡설·트레일링콤마 흡수) ──
def test_parse_lenient_fenced_with_prose():
    msg = ('여기 계획입니다:\n```json\n'
           '{"intents": [{"summary": "check wiki config leak", "target": "internal-wiki",}]}\n'
           '```\n이상입니다.')
    its = parse_intents(msg)
    assert len(its) == 1 and its[0].target == "internal-wiki"


# ── 파싱: summary 없는 항목은 버린다 ──
def test_parse_drops_empty_summary():
    its = parse_intents('{"intents": [{"summary": ""}, {"summary": "real one"}]}')
    assert len(its) == 1 and its[0].summary == "real one"


# ── 파싱: JSON이 전혀 없으면(정렬모델 거부·추론만 하다 잘림 등) 에러 신호 ──
def test_parse_garbage_signals_error():
    from common.llm_json import LLMJsonError
    try:
        parse_intents("I cannot output JSON, here is some prose only.")
        assert False, "should have raised"
    except LLMJsonError:
        pass


# ── 태세: 최근 사실 + 진행 중 의도를 보여준다(중복 방지 컨텍스트) ──
def test_situation_shows_facts_and_inflight():
    g = InMemoryGraph()
    i = g.add_intent({"summary": "running one"})
    g.claim_next("w")                       # running 상태로
    g.add_intent({"summary": "open one"})   # frontier에 대기
    g.add_fact({"summary": "leaked connstr", "confidence": "observed"})
    s = build_situation(g, goal="read PII")
    assert "GOAL: read PII" in s
    assert "leaked connstr" in s and "(observed)" in s
    assert "running one" in s and "open one" in s
    assert "do not duplicate" in s


# ── 태세: 개막(사실·의도 없음) 문구 ──
def test_situation_opening_phrasing():
    g = InMemoryGraph()
    s = build_situation(g, goal="x")
    assert "none yet — this is the opening" in s
    assert "INTENTS ALREADY IN FLIGHT: (none)" in s


# ── plan: 의도를 frontier에 추가하고 id를 돌려준다 ──
def test_plan_adds_intents_to_frontier():
    g = InMemoryGraph()
    p = Planner(_FakeLLM([_TWO_INTENTS]), goal="read PII")
    res = p.plan(g)
    assert res.proposed == 2 and len(res.added_ids) == 2
    fr = g.frontier()
    assert len(fr) == 2
    assert all(n.kind == NodeKind.INTENT and n.state == IntentState.OPEN.value for n in fr)
    # 기법 태그가 payload에 실린다(채점 조인용)
    assert g.get_node(res.added_ids[0]).payload["technique"] == "T1046"


# ── plan: 파싱 실패 시 재시도 후 0개 추가 + 에러 보고 ──
def test_plan_parse_fail_retries_then_reports():
    llm = _FakeLLM(["not json", "still not json"])  # retries=1 → 2번 시도 다 실패
    g = InMemoryGraph()
    res = Planner(llm, goal="x", retries=1).plan(g)
    assert res.added_ids == [] and res.error
    assert len(llm.calls) == 2                      # 재시도 1회 포함 2번 호출
    assert g.frontier() == []


# ── plan: 재시도로 복구(1번 실패 후 2번째 성공) ──
def test_plan_recovers_on_retry():
    llm = _FakeLLM(["garbage", _TWO_INTENTS])
    g = InMemoryGraph()
    res = Planner(llm, goal="x", retries=1).plan(g)
    assert res.proposed == 2 and len(g.frontier()) == 2


# ── plan: 빈 intents = 목표달성/막다른 신호(에러 아님) ──
def test_plan_empty_is_goal_reached_signal():
    g = InMemoryGraph()
    res = Planner(_FakeLLM(['{"intents": []}']), goal="x").plan(g)
    assert res.proposed == 0 and not res.error
    assert res.goal_reached_signal is True
    assert g.frontier() == []


# ── plan: spawned_by 주면 SPAWNS 엣지로 계층 연결 ──
def test_plan_spawned_by_links_edge():
    g = InMemoryGraph()
    parent = g.add_intent({"summary": "parent"})
    res = Planner(_FakeLLM([_TWO_INTENTS]), goal="x").plan(g, spawned_by=parent)
    for child in res.added_ids:
        edges = g.edges_from(parent, Rel.SPAWNS)
        assert any(e.dst_id == child for e in edges)


# ── 이벤트 구동 폐곡선(통합): 플래너→풀→플래너 재계획으로 그래프가 자란다 ──
def test_event_driven_loop_with_pool():
    from attacker.exec_lane import ExecutionLane
    from attacker.execute_action import CommandResult
    from attacker.worker_pool import IntentOutcome, WorkerPool
    from attacker.scope import default_policy
    from attacker.actions import AttackAction

    class _R:
        def run(self, tool, args, *, stdin=None, timeout=None):
            return CommandResult(0, "ok", "")

    g = InMemoryGraph()
    # 1라운드 플래너: 의도 2개 생성
    p = Planner(_FakeLLM([_TWO_INTENTS]), goal="read PII")
    p.plan(g)
    assert len(g.frontier()) == 2

    # 워커 풀: 각 의도를 돌려 fact 하나씩 쓰고 done
    def run_intent(graph, wctx, intent):
        obs = wctx.execute(AttackAction(thought="t", tool="get", args=[f"i{intent.id}"]))
        graph.add_fact({"summary": f"result of {intent.id}",
                        "source_step_ids": [obs.step_id]}, intent_id=intent.id)
        return IntentOutcome(IntentState.DONE)

    lane = ExecutionLane(_R(), scope_policy=default_policy(),
                         session_id="s", episode=1, round=1)
    summary = WorkerPool(g, lane, run_intent, n_workers=2).run()
    assert summary.done == 2
    assert len(g.recent_facts()) == 2          # 워커가 쓴 사실이 그래프에 쌓임

    # 2라운드 플래너: 쌓인 사실을 보고 추가 의도 1개 → frontier 다시 참
    p2 = Planner(_FakeLLM(['{"intents": [{"summary": "follow-up probe", "target": "x"}]}']),
                 goal="read PII")
    res2 = p2.plan(g)
    # 플래너가 받은 태세에 1라운드 사실이 들어가 있어야(이벤트 구동)
    seen_user = p2.llm.calls[0][1]
    assert "result of" in seen_user
    assert res2.proposed == 1 and len(g.frontier()) == 1


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
    print("── 플래너 테스트 ──")
    sys.exit(_run())
