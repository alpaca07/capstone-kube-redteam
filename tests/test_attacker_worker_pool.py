"""워커 풀 엔진 테스트 — 동시 claim·종료 판정·동적 의도 보충·예외 격리·데드라인.

run_intent은 가짜(LLM 없음)로 주입해 동시성 로직만 검증한다.

    python3 tests/test_attacker_worker_pool.py
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.actions import AttackAction  # noqa: E402
from attacker.exec_lane import ExecutionLane, WorkerContext  # noqa: E402
from attacker.execute_action import CommandResult  # noqa: E402
from attacker.graph import IntentState  # noqa: E402
from attacker.graph_fake import InMemoryGraph  # noqa: E402
from attacker.scope import default_policy  # noqa: E402
from attacker.worker_pool import IntentOutcome, WorkerPool  # noqa: E402


class _FakeRunner:
    def run(self, tool, args, *, stdin=None, timeout=None):
        return CommandResult(exit_code=0, stdout="ok", stderr="")


def _lane():
    return ExecutionLane(_FakeRunner(), scope_policy=default_policy(),
                         session_id="s", episode=1, round=1)


def _act(tool, args):
    return AttackAction(thought="t", tool=tool, args=args)


# ── 기본: 모든 의도가 정확히 한 번씩 처리되고 done으로 정착 ──
def test_drains_frontier_each_intent_once():
    g = InMemoryGraph()
    for k in range(10):
        g.add_intent({"summary": f"i{k}"})

    processed: list[int] = []
    lock = threading.Lock()

    def run_intent(graph, wctx, intent):
        with lock:
            processed.append(intent.id)
        return IntentOutcome(IntentState.DONE)

    s = WorkerPool(g, _lane(), run_intent, n_workers=4).run()
    assert s.claimed == 10 and s.done == 10
    assert sorted(processed) == sorted(set(processed))   # 중복 없음
    assert len(processed) == 10                           # 누락 없음
    assert s.remaining_open == 0
    assert g.frontier() == []


# ── run_intent이 실제 행동을 레인에 흘리고 fact를 그래프에 쓴다 ──
def test_run_intent_writes_facts_and_executes():
    g = InMemoryGraph()
    g.add_intent({"summary": "probe"})

    def run_intent(graph, wctx, intent):
        obs = wctx.execute(_act("kubectl", ["get", "po"]))
        graph.add_fact({"summary": "pods listed", "source_step_ids": [obs.step_id]},
                       intent_id=intent.id)
        return IntentOutcome(IntentState.DONE, reason="done")

    lane = _lane()
    s = WorkerPool(g, lane, run_intent, n_workers=1).run()
    assert s.done == 1
    # 레인에 스텝 1개 기록, fact 1개가 intent에 yields로 연결
    assert len(lane.script.steps) == 1
    facts = g.recent_facts()
    assert len(facts) == 1 and facts[0].payload["summary"] == "pods listed"


# ── 동적 보충: run_intent이 새 의도를 낳으면 풀이 집어간다(조기 종료 안 함) ──
def test_dynamic_intent_refill_is_picked_up():
    g = InMemoryGraph()
    g.add_intent({"summary": "seed", "depth": 0})

    seen_depths: list[int] = []
    lock = threading.Lock()

    def run_intent(graph, wctx, intent):
        d = intent.payload.get("depth", 0)
        with lock:
            seen_depths.append(d)
        if d < 3:                       # 깊이 3까지 자식 의도 하나씩 파생(플래너 흉내)
            graph.add_intent({"summary": f"child of {intent.id}", "depth": d + 1},
                             spawned_by=intent.id)
        return IntentOutcome(IntentState.DONE)

    s = WorkerPool(g, _lane(), run_intent, n_workers=3).run()
    # seed(0)→1→2→3 총 4개가 처리돼야(조기 종료하면 4 미만)
    assert s.claimed == 4 and s.done == 4
    assert sorted(seen_depths) == [0, 1, 2, 3]


# ── 예외 격리: run_intent이 터져도 그 의도만 blocked, 풀은 계속 ──
def test_run_intent_exception_isolated():
    g = InMemoryGraph()
    for k in range(5):
        g.add_intent({"summary": f"i{k}", "boom": (k == 2)})

    def run_intent(graph, wctx, intent):
        if intent.payload.get("boom"):
            raise RuntimeError("explode")
        return IntentOutcome(IntentState.DONE)

    s = WorkerPool(g, _lane(), run_intent, n_workers=2).run()
    assert s.claimed == 5
    assert s.done == 4 and s.blocked == 1
    assert len(s.errors) == 1 and "explode" in s.errors[0]
    assert s.remaining_open == 0


# ── 정착 상태 집계: 종료상태별로 요약에 반영 ──
def test_outcome_states_aggregated():
    g = InMemoryGraph()
    states = [IntentState.DONE, IntentState.BLOCKED, IntentState.EXHAUSTED,
              IntentState.STOPPED, IntentState.DONE]
    for k, st in enumerate(states):
        g.add_intent({"summary": f"i{k}", "st": st.value})

    def run_intent(graph, wctx, intent):
        return IntentOutcome(IntentState(intent.payload["st"]))

    s = WorkerPool(g, _lane(), run_intent, n_workers=3).run()
    assert s.done == 2 and s.blocked == 1 and s.exhausted == 1 and s.stopped == 1


# ── 데드라인: 넘으면 새 claim 중단, 남은 열린 의도는 remaining_open으로 ──
def test_round_deadline_stops_claiming():
    g = InMemoryGraph()
    for k in range(20):
        g.add_intent({"summary": f"i{k}"})

    # 가짜 시계: claim마다 시간이 흐르게 해서 몇 개 처리 후 데드라인 넘기게
    t = {"now": 0.0}
    tick_lock = threading.Lock()

    def clock():
        with tick_lock:
            return t["now"]

    def run_intent(graph, wctx, intent):
        with tick_lock:
            t["now"] += 1.0          # 의도 하나 처리에 1초
        return IntentOutcome(IntentState.DONE)

    # 데드라인 3초 → 대략 3개 전후 처리 후 claim 중단(정확 수는 스케줄 의존)
    s = WorkerPool(g, _lane(), run_intent, n_workers=1,
                   round_deadline=3.0, clock=clock, sleep=lambda _x: None).run()
    assert s.claimed < 20                      # 전부는 아님
    assert s.remaining_open > 0                # 못 집은 의도 남음
    assert s.claimed + s.remaining_open == 20  # 집은 것 + 남은 것 = 전체(누락 없음)


# ── 종료: frontier 비고 running 없으면 즉시 반환(빈 frontier) ──
def test_empty_frontier_returns_immediately():
    g = InMemoryGraph()

    def run_intent(graph, wctx, intent):
        return IntentOutcome(IntentState.DONE)

    s = WorkerPool(g, _lane(), run_intent, n_workers=2).run()
    assert s.claimed == 0 and s.remaining_open == 0


# ── 동시성 부하: 워커 다수·의도 다수 — 전부 한 번씩, 카운트 일관 ──
def test_concurrent_many_intents_consistent():
    g = InMemoryGraph()
    n = 100
    for k in range(n):
        g.add_intent({"summary": f"i{k}"})

    processed: list[int] = []
    lock = threading.Lock()

    def run_intent(graph, wctx, intent):
        wctx.execute(_act("get", [f"x{intent.id}"]))   # 레인 직렬화도 같이 탄다
        with lock:
            processed.append(intent.id)
        return IntentOutcome(IntentState.DONE)

    lane = _lane()
    s = WorkerPool(g, lane, run_intent, n_workers=8).run()
    assert s.claimed == n and s.done == n
    assert len(processed) == n and len(set(processed)) == n   # 전부 유일
    assert len(lane.script.steps) == n                        # 레인 기록도 n개
    nums = sorted(st.step for st in lane.script.steps)
    assert nums == list(range(1, n + 1))                      # step 번호 유일·단조


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
    print("── 워커 풀 엔진 테스트 ──")
    sys.exit(_run())
