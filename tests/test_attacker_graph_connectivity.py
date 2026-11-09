"""그래프 연결성 테스트 — 추론 트리가 하나로 이어지는지.

목표→의도→사실→(그 사실에서 파생된)하위의도→…→발견. 핵심: 플래너의 'from'(출처 사실)이
사실→SPAWNS→의도 엣지로 박혀, 웨이브가 '따로따로'가 아니라 연결되는지.

    python3 tests/test_attacker_graph_connectivity.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.graph import NodeKind, Rel  # noqa: E402
from attacker.graph_fake import InMemoryGraph  # noqa: E402
from attacker.planner import Planner, parse_intents, _parse_ids  # noqa: E402


class _LLM:
    def __init__(self, reply):
        self.reply = reply

    def chat_text(self, system, user, **kw):
        return self.reply


# ── 'from' 파싱: int·"#12"·"12" 허용, 잡값 버림 ──
def test_parse_from_ids():
    assert _parse_ids([12, "15", "#18", "x", True, None]) == [12, 15, 18]
    assert _parse_ids(None) == [] and _parse_ids("nope") == []


def test_parse_intent_reads_from():
    its = parse_intents('{"intents":[{"summary":"s","from":[10,"#12"]}]}')
    assert its[0].from_facts == [10, 12]


# ── add_goal + 개막 의도가 goal에서 파생(default_parent) ──
def test_opening_intents_spawn_from_goal():
    g = InMemoryGraph()
    goal = g.add_goal({"summary": "read PII"})
    llm = _LLM('{"intents":[{"summary":"probe","from":[]},{"summary":"enum","from":[]}]}')
    res = Planner(llm, goal="read PII").plan(g, default_parent=goal)
    assert len(res.added_ids) == 2
    # goal → SPAWNS → 각 개막 의도
    spawned = {e.dst_id for e in g.edges_from(goal, Rel.SPAWNS)}
    assert spawned == set(res.added_ids)


# ── 핵심: 'from' 사실에서 하위 의도가 파생(사실→SPAWNS→의도) ──
def test_subintent_spawns_from_fact():
    g = InMemoryGraph()
    goal = g.add_goal({"summary": "g"})
    i1 = g.add_intent({"summary": "probe"}, spawned_by=goal)
    g.claim_next("w")
    f = g.add_fact({"summary": "admin dashboard exposes creds"}, intent_id=i1)
    # 2웨이브 플래너: 그 사실(f)을 보고 하위 의도를 냄
    llm = _LLM(f'{{"intents":[{{"summary":"extract creds","from":[{f}]}}]}}')
    res = Planner(llm, goal="g").plan(g, default_parent=goal)
    child = res.added_ids[0]
    # 사실 f → SPAWNS → 하위 의도
    assert any(e.dst_id == child for e in g.edges_from(f, Rel.SPAWNS))


# ── 헛 id는 버리고 default_parent로 폴백 ──
def test_invalid_from_falls_back_to_goal():
    g = InMemoryGraph()
    goal = g.add_goal({"summary": "g"})
    llm = _LLM('{"intents":[{"summary":"x","from":[9999]}]}')  # 9999는 없는 노드
    res = Planner(llm, goal="g").plan(g, default_parent=goal)
    child = res.added_ids[0]
    # 헛 id 무시 → goal에서 파생
    assert any(e.dst_id == child for e in g.edges_from(goal, Rel.SPAWNS))


# ── 통합: 라운드가 연결된 트리를 만든다(고립 의도 없음) ──
def test_round_builds_connected_tree():
    from attacker.exec_lane import ExecutionLane
    from attacker.execute_action import CommandResult
    from attacker.intent_runner import IntentRunner, IntentRunnerConfig
    from attacker.round_engine import AttackRound, RoundConfig
    from attacker.scope import default_policy
    from common.messages import AttackTurnStart, Foothold

    class _R:
        def run(self, tool, args, *, stdin=None, timeout=None):
            return CommandResult(0, "ok", "")

    # 플래너: wave1 의도 2개(from []), wave2 의도 1개(from 앞 사실), wave3 빈
    plan_replies = [
        '{"intents":[{"summary":"probe pg","from":[]},{"summary":"enum sa","from":[]}]}',
        '{"intents":[{"summary":"follow up","from":[__FACT__]}]}',
        '{"intents":[]}',
    ]

    class _PlanLLM:
        def __init__(self):
            self.n = 0
        def chat_text(self, system, user, **kw):
            r = plan_replies[min(self.n, len(plan_replies) - 1)]
            self.n += 1
            if "__FACT__" in r:
                # 가장 최근 사실 id를 'from'에 꽂아 연결 유발(실모델이 #id 인용하는 상황 모사)
                import re as _re
                m = _re.findall(r"#(\d+)", user)
                fid = m[-1] if m else "1"
                r = r.replace("__FACT__", fid)
            return r

    class _WorkLLM:
        def chat_text_meta(self, system, user, **kw):
            if "아직 행동 없음" in user:
                return '{"thought":"p","action":{"tool":"get","args":["x"]}}', "stop"
            return '{"thought":"done","action":{"tool":"give_up","args":[]}}', "stop"
        def chat_text(self, system, user, **kw):
            return '{"facts":[{"summary":"observed something"}],"finding":null}'

    g = InMemoryGraph(episode=1)
    cfg = RoundConfig(system_prompt="s", n_workers=2, max_waves=4)
    rnd = AttackRound(attacker_llm=_WorkLLM(), planner_llm=_PlanLLM(), runner=_R(),
                      scope_policy=default_policy(), cfg=cfg)
    start = AttackTurnStart(goal="read PII", time_limit_sec=300,
                            foothold=Foothold(attack_endpoint="10.0.0.5"))
    rnd.run(start, episode=1, round=1, graph=g)

    # goal 노드 존재
    goals = [n for n in [g.get_node(i) for i in range(1, 50) if g.get_node(i)]
             if n.kind == NodeKind.GOAL]
    assert len(goals) >= 1
    gid = goals[0].id

    # 모든 의도가 '출처'를 가진다(고립 없음): 각 의도로 들어오는 SPAWNS 엣지가 있어야
    intents = [n for n in [g.get_node(i) for i in range(1, 50) if g.get_node(i)]
               if n.kind == NodeKind.INTENT]
    assert len(intents) >= 3
    all_edges = []
    for src in range(1, 50):
        all_edges += g.edges_from(src, Rel.SPAWNS)
    spawned_targets = {e.dst_id for e in all_edges}
    for it in intents:
        assert it.id in spawned_targets, f"의도 #{it.id}가 고립됨(출처 SPAWNS 없음)"

    # goal에서 뻗은 개막 의도가 최소 2개(wave1)
    from_goal = {e.dst_id for e in g.edges_from(gid, Rel.SPAWNS)}
    assert len(from_goal) >= 2


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
    print("── 그래프 연결성 테스트 ──")
    sys.exit(_run())
