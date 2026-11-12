"""AttackHarness 병렬 워커 경로 배선 테스트 — mode=parallel 라우팅·회차 그래프
수명(라운드 지속·회차 리셋)·봉투 왕복. LLM만 fake, 나머지 실제 경로.

    python3 tests/test_attacker_server_parallel.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.execute_action import CommandResult  # noqa: E402
from attacker.round_engine import RoundConfig  # noqa: E402
from attacker.scope import default_policy  # noqa: E402
from attacker.server import AttackHarness, handle_message  # noqa: E402
from common.messages import (  # noqa: E402
    AttackEndReason, AttackTurnResult, AttackTurnStart, Foothold, wrap,
)


class _R:
    def run(self, tool, args, *, stdin=None, timeout=None):
        return CommandResult(0, "ok", "")


class _WorkLLM:
    def chat_text_meta(self, system, user, **kw):
        if "아직 행동 없음" in user:
            return '{"thought":"p","action":{"tool":"kubectl","args":["get","po"]}}', "stop"
        return '{"thought":"done","action":{"tool":"give_up","args":[]}}', "stop"

    def chat_text(self, system, user, **kw):
        return '{"facts":[{"summary":"observed"}],"finding":null}'


class _PlanLLM:
    """1웨이브만 의도 2개, 그 뒤 빈(종료). 매 플랜 호출 카운트."""
    def __init__(self):
        self.calls = 0

    def chat_text(self, system, user, **kw):
        self.calls += 1
        # 홀수 호출(각 라운드 첫 웨이브)에만 의도, 짝수(종료확인)엔 빈
        if self.calls % 2 == 1:
            return ('{"intents":[{"summary":"probe pg","target":"pg","technique":"T1046"},'
                    '{"summary":"enum sa","target":"sa","technique":"T1078"}]}')
        return '{"intents": []}'


def _harness(mode="parallel"):
    return AttackHarness(
        llm=_WorkLLM(), runner=_R(), scope_policy=default_policy(),
        system_prompt="attacker-sys", session_id="vmA", step_timeout=5.0,
        mode=mode, planner_llm=_PlanLLM(),
        round_cfg=RoundConfig(system_prompt="attacker-sys", n_workers=2,
                              session_id="vmA", step_timeout=5.0))


def _start():
    return AttackTurnStart(goal="read PII", time_limit_sec=300,
                           foothold=Foothold(attack_endpoint="10.0.0.5"))


# ── mode=parallel이면 병렬 경로로 라우팅(그래프 생성됨) ──
def test_parallel_route_runs_round():
    h = _harness("parallel")
    res = h.attack_turn(_start(), episode=1, round=1)
    assert isinstance(res, AttackTurnResult)
    assert res.replay_script is not None and res.replay_script.round == 1
    assert h._graph is not None and h._graph_episode == 1
    # 의도 2개 처리 → 그래프에 사실 쌓임
    assert len(h._graph.recent_facts()) == 2


# ── 병렬 경로 가시성: 웨이브·스텝 로그가 주입된 log로 흐른다(저널 침묵 회귀 방지) ──
def test_parallel_path_emits_logs():
    logs: list[str] = []
    h = AttackHarness(
        llm=_WorkLLM(), runner=_R(), scope_policy=default_policy(),
        system_prompt="attacker-sys", mode="parallel", planner_llm=_PlanLLM(),
        round_cfg=RoundConfig(system_prompt="attacker-sys", n_workers=2),
        log=logs.append)
    h.attack_turn(_start(), episode=1, round=1)
    joined = "\n".join(logs)
    assert "wave" in joined                       # 라운드 엔진 웨이브 로그
    assert "[공격" in joined                        # ReAct 스텝 로그도 흐른다


# ── mode=single이면 기존 단일 경로(그래프 안 만듦) ──
def test_single_route_untouched():
    h = _harness("single")
    res = h.attack_turn(_start(), episode=1, round=1)
    assert isinstance(res, AttackTurnResult)
    assert h._graph is None            # 병렬 그래프 안 건드림


# ── 회차 그래프 지속: 같은 회차 R1→R2는 그래프 유지(사실 누적) ──
def test_graph_persists_within_episode():
    h = _harness("parallel")
    h.attack_turn(_start(), episode=5, round=1)
    g1 = h._graph
    facts_r1 = len(g1.recent_facts())
    h.attack_turn(_start(), episode=5, round=2)
    assert h._graph is g1                       # 같은 그래프 객체(지속)
    assert len(h._graph.recent_facts()) > facts_r1   # 사실 누적


# ── 회차 바뀌면 그래프 리셋(런 간 기억 유출 방지) ──
def test_graph_resets_on_new_episode():
    h = _harness("parallel")
    h.attack_turn(_start(), episode=1, round=1)
    g1 = h._graph
    h.attack_turn(_start(), episode=2, round=1)
    assert h._graph is not g1                   # 새 그래프
    assert h._graph_episode == 2


# ── R1은 회차 중간이라도 리셋(상주 하네스 런 경계) ──
def test_round1_resets_graph():
    h = _harness("parallel")
    h.attack_turn(_start(), episode=1, round=1)
    h.attack_turn(_start(), episode=1, round=2)
    g_mid = h._graph
    # 같은 회차지만 R1이 다시 들어오면(새 런) 리셋
    h.attack_turn(_start(), episode=1, round=1)
    assert h._graph is not g_mid


# ── 봉투 왕복: handle_message로 attack_turn_start → 결과 봉투 ──
def test_handle_message_envelope_roundtrip():
    h = _harness("parallel")
    env = wrap(_start(), episode=1, round=1).model_dump(mode="json")
    resp = handle_message(h, env)
    assert resp["status"] == "ok"
    assert resp["type"] == "attack_turn_result"
    assert "end_reason" in resp["payload"]


# ── 하네스 예외는 ERROR 결과로 흡수(루프 보호) ──
def test_parallel_harness_error_absorbed():
    class _BoomPlan:
        def chat_text(self, system, user, **kw):
            raise RuntimeError("planner down")
    h = AttackHarness(
        llm=_WorkLLM(), runner=_R(), scope_policy=default_policy(),
        system_prompt="s", mode="parallel", planner_llm=_BoomPlan(),
        round_cfg=RoundConfig(system_prompt="s", n_workers=1))
    # 플래너 호출이 터져도 Planner가 내부에서 잡아 added_ids=[]로 → 라운드는 정상 종료(ERROR 아님)
    res = h.attack_turn(_start(), episode=1, round=1)
    assert isinstance(res, AttackTurnResult)
    # 의도 0개라 DEADEND(플래너 고갈)로 깔끔히 종료
    assert res.end_reason in (AttackEndReason.DEADEND, AttackEndReason.TIMEOUT)


# ── neo4j 백엔드 라우팅: _new_episode_graph가 Neo4jGraph를 만들고 reset 호출 ──
class _FakeSession:
    def __init__(self, log):
        self.log = log

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, q, **p):
        self.log.append(q)
        return []


class _FakeDriver:
    def __init__(self):
        self.queries = []

    def session(self, database=None):
        return _FakeSession(self.queries)


def test_neo4j_backend_dispatch_and_reset():
    drv = _FakeDriver()
    h = AttackHarness(
        llm=_WorkLLM(), runner=_R(), scope_policy=default_policy(),
        system_prompt="s", mode="parallel", planner_llm=_PlanLLM(),
        round_cfg=RoundConfig(system_prompt="s"),
        graph_backend="neo4j", neo4j_driver=drv)
    g = h._new_episode_graph(7)
    from attacker.graph_neo4j import Neo4jGraph
    assert isinstance(g, Neo4jGraph) and g._episode == 7
    # 새 회차 그래프 생성 시 reset_episode(DETACH DELETE)가 돌아야(묵은 노드 제거)
    assert any("DETACH DELETE" in q for q in drv.queries)


def test_memory_backend_default_dispatch():
    h = _harness("parallel")                 # graph_backend 기본 memory
    g = h._new_episode_graph(3)
    from attacker.graph_fake import InMemoryGraph
    assert isinstance(g, InMemoryGraph)


def test_turns_are_serialized():
    """공격 턴 직렬화: 겹친 요청이 들어와도 한 번에 하나만 돈다(공유 그래프 레이스 방지)."""
    import threading
    import time
    gate = threading.Event()        # 첫 턴을 플래너에서 붙잡아 둠
    entered = threading.Event()     # 첫 턴이 턴 락 안으로 들어왔다는 신호
    order: list = []

    class _GatedPlan:
        def __init__(self):
            self.calls = 0

        def chat_text(self, system, user, **kw):
            self.calls += 1
            if self.calls == 1:         # 첫 턴의 첫 플랜 호출에서 붙잡음(락 보유 중)
                entered.set()
                gate.wait(5.0)
            if self.calls % 2 == 1:
                return ('{"intents":[{"summary":"probe","target":"t",'
                        '"technique":"T1046"}]}')
            return '{"intents": []}'

    h = AttackHarness(
        llm=_WorkLLM(), runner=_R(), scope_policy=default_policy(),
        system_prompt="s", session_id="vmA", step_timeout=5.0,
        mode="parallel", planner_llm=_GatedPlan(),
        round_cfg=RoundConfig(system_prompt="s", n_workers=1,
                              session_id="vmA", step_timeout=5.0))

    def _turn(rnd: int) -> None:
        h.attack_turn(_start(), episode=1, round=rnd)
        order.append(rnd)

    t1 = threading.Thread(target=_turn, args=(1,))
    t1.start()
    assert entered.wait(5.0)                   # 턴1이 턴 락을 쥐고 플래너에서 대기
    t2 = threading.Thread(target=_turn, args=(2,))
    t2.start()
    time.sleep(0.2)
    assert order == []                         # 턴1 미완(gate) → 턴2는 락 대기, 둘 다 미완
    gate.set()                                 # 턴1 해제
    t1.join(5.0)
    t2.join(5.0)
    assert order == [1, 2]                      # 직렬화: 턴1 완료 후에야 턴2 실행


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
    print("── 병렬 하네스 배선 테스트 ──")
    sys.exit(_run())
