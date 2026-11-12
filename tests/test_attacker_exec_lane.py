"""공유 실행 레인 + 워커별 값 맥락 테스트.

핵심: 여러 워커가 하나의 replay_script에 끼어 들어가도 (1) 전역 step_id가 도착순·단조,
(2) 워커별 produces 격리, (3) 병합 대본을 재생해도 같은 이름 충돌이 안 나는지(네임스페이스).

    python3 tests/test_attacker_exec_lane.py
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.actions import AttackAction  # noqa: E402
from attacker.exec_lane import ExecutionLane, WorkerContext, namespace_action  # noqa: E402
from attacker.execute_action import CommandResult  # noqa: E402
from attacker.replay_engine import ReplayEngine  # noqa: E402
from attacker.scope import default_policy  # noqa: E402
from common.replay_schema import (  # noqa: E402
    Extract, ExtractMethod, InputRef, InputSource, ProducesRef,
)

FULL = ExtractMethod.FULL


class _FakeRunner:
    """args에 따라 프로그래밍된 결과를 돌려주고 호출 인자를 기록."""

    def __init__(self, rule=None, default_stdout=""):
        self.calls: list[tuple[str, list]] = []
        self.rule = rule or (lambda tool, args: default_stdout)

    def run(self, tool, args, *, stdin=None, timeout=None):
        self.calls.append((tool, list(args)))
        out = self.rule(tool, list(args))
        return CommandResult(exit_code=0, stdout=out, stderr="")


def _lane(runner, **kw):
    return ExecutionLane(runner, scope_policy=default_policy(denied_hosts=["10.99.0.1"]),
                         session_id="s", episode=1, round=3, **kw)


def _act(tool, args, inputs=None, produces=None):
    return AttackAction(thought="t", tool=tool, args=args,
                        inputs=inputs or {}, produces=produces or {})


# ── 기본: 단일 워커가 레인을 통해 ActionExecutor처럼 동작 ──
def test_single_worker_step_ids_and_produces():
    runner = _FakeRunner(rule=lambda tool, args: "TOKEN123" if tool == "get" else "ok")
    lane = _lane(runner)
    w = WorkerContext(lane, "work1")
    o1 = w.execute(_act("get", ["secret"], produces={"tok": ProducesRef(extract=Extract(method=FULL))}))
    o2 = w.execute(_act("use", ["--auth={tok}"],
                        inputs={"tok": InputRef(source=InputSource.STEP_OUTPUT,
                                                extract=Extract(method=FULL))}))
    assert o1.step_id == "3.1" and o2.step_id == "3.2"
    # 2번째 스텝의 {tok}가 1번째 produces 값으로 치환돼 실행됨
    assert runner.calls[1] == ("use", ["--auth=TOKEN123"])
    assert len(lane.script.steps) == 2


# ── 두 워커 끼어들기: 전역 step_id는 '도착 순서' ──
def test_interleaved_global_order_is_arrival_order():
    runner = _FakeRunner(default_stdout="ok")
    lane = _lane(runner)
    a = WorkerContext(lane, "wA")
    b = WorkerContext(lane, "wB")
    oa1 = a.execute(_act("get", ["a1"]))
    ob1 = b.execute(_act("get", ["b1"]))
    oa2 = a.execute(_act("get", ["a2"]))
    assert [oa1.step_id, ob1.step_id, oa2.step_id] == ["3.1", "3.2", "3.3"]
    # 대본 순서 = 도착 순서
    assert [s.command.args for s in lane.script.steps] == [["a1"], ["b1"], ["a2"]]


# ── produces 네임스페이스: 기록된 대본에서 워커별로 키가 갈림 ──
def test_produces_namespaced_in_recorded_script():
    runner = _FakeRunner(default_stdout="X")
    lane = _lane(runner)
    a = WorkerContext(lane, "wA")
    b = WorkerContext(lane, "wB")
    a.execute(_act("get", ["x"], produces={"tok": ProducesRef(extract=Extract(method=FULL))}))
    b.execute(_act("get", ["y"], produces={"tok": ProducesRef(extract=Extract(method=FULL))}))
    keys0 = list(lane.script.steps[0].produces.keys())
    keys1 = list(lane.script.steps[1].produces.keys())
    assert keys0 == ["wA:tok"] and keys1 == ["wB:tok"]


# ── ★ 결정적 증명: 같은 이름 충돌 상황을 '재생'해도 각자 제 값으로 풀린다 ──
def test_replay_no_cross_worker_value_collision():
    # 기록 단계: 두 워커가 둘 다 'tok'을 뽑아 쓰고, 전역순서로 끼어든다.
    rec_runner = _FakeRunner(default_stdout="REC")
    lane = _lane(rec_runner)
    a = WorkerContext(lane, "wA")
    b = WorkerContext(lane, "wB")
    prod = {"tok": ProducesRef(extract=Extract(method=FULL))}
    use_in = {"tok": InputRef(source=InputSource.STEP_OUTPUT, extract=Extract(method=FULL))}
    # 도착 순서: A.produce(3.1) → B.produce(3.2) → A.use(3.3) → B.use(3.4)
    a.execute(_act("getA", ["a"], produces=prod))
    b.execute(_act("getB", ["b"], produces=prod))
    a.execute(_act("use", ["--auth={tok}"], inputs=use_in))
    b.execute(_act("use", ["--auth={tok}"], inputs=use_in))

    # 재생 단계: produce 스텝이 '새 토큰'을 돌려주도록(토큰 로테이션 모사).
    #   getA → RE_A, getB → RE_B. use 스텝의 실행 인자를 기록해 어느 토큰이 주입됐나 본다.
    def replay_rule(tool, args):
        if tool == "getA":
            return "RE_A"
        if tool == "getB":
            return "RE_B"
        return "ok"
    rep_runner = _FakeRunner(rule=replay_rule)
    eng = ReplayEngine(rep_runner, scope_policy=default_policy(denied_hosts=["10.99.0.1"]))
    from common.messages import ReplayPhase
    eng.replay(lane.script, ReplayPhase.POST)

    # use 스텝 두 개의 실행 인자: wA의 use는 RE_A, wB의 use는 RE_B 여야 한다.
    use_calls = [args for (tool, args) in rep_runner.calls if tool == "use"]
    assert use_calls == [["--auth=RE_A"], ["--auth=RE_B"]], use_calls
    # 네임스페이스가 없었다면 재생의 단일 values[tok]가 RE_B로 덮여 둘 다 RE_B가 됐을 것.


# ── 워커 간 값 격리: 한 워커의 produce는 다른 워커 inputs에 안 샌다 ──
def test_worker_values_isolated():
    runner = _FakeRunner(rule=lambda tool, args: "SECRET_A" if args == ["a"] else "ok")
    lane = _lane(runner)
    a = WorkerContext(lane, "wA")
    b = WorkerContext(lane, "wB")
    a.execute(_act("get", ["a"], produces={"tok": ProducesRef(extract=Extract(method=FULL))}))
    # B는 tok을 안 뽑았는데 {tok}을 참조 → 자기 _values엔 없으니 빈 문자열로 치환(A값 안 샘)
    b.execute(_act("use", ["--auth={tok}"],
                   inputs={"tok": InputRef(source=InputSource.STEP_OUTPUT,
                                           extract=Extract(method=FULL))}))
    use_call = [args for (tool, args) in runner.calls if tool == "use"][0]
    assert use_call == ["--auth="], use_call


# ── 범위 차단도 step_id 받고 기록됨 ──
def test_blocked_still_records_with_step_id():
    runner = _FakeRunner(default_stdout="ok")
    lane = _lane(runner)
    w = WorkerContext(lane, "wA")
    o = w.execute(_act("curl", ["http://10.99.0.1/"]))
    assert o.blocked and o.step_id == "3.1"
    assert len(lane.script.steps) == 1
    # 차단된 스텝은 runner로 안 감
    assert runner.calls == []


# ── FOOTHOLD 입력은 네임스페이스 안 함(foothold 사전 키 보존) ──
def test_foothold_input_not_namespaced():
    args, inputs, produces = namespace_action(
        _act("curl", ["http://{ep}/"],
             inputs={"ep": InputRef(source=InputSource.FOOTHOLD)}), "wA")
    assert "ep" in inputs and "wA:ep" not in inputs     # 그대로
    assert args == ["http://{ep}/"]                      # 플레이스홀더도 그대로


# ── 동시성: 워커 N이 레인을 두드려도 step 번호 유일·단조, 유실 없음 ──
def test_concurrent_lane_wellformed_script():
    runner = _FakeRunner(default_stdout="ok")
    lane = _lane(runner)
    n_workers, per = 8, 25

    start = threading.Event()

    def run_worker(wid):
        w = WorkerContext(lane, wid)
        start.wait()
        for k in range(per):
            w.execute(_act("get", [f"{wid}-{k}"]))

    threads = [threading.Thread(target=run_worker, args=(f"w{t}",)) for t in range(n_workers)]
    for t in threads:
        t.start()
    start.set()
    for t in threads:
        t.join()

    steps = lane.script.steps
    assert len(steps) == n_workers * per
    nums = sorted(s.step for s in steps)
    assert nums == list(range(1, n_workers * per + 1))        # 1..N 유일·빠짐없음
    sids = {s.step_id for s in steps}
    assert len(sids) == n_workers * per                       # step_id도 전부 유일


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
    print("── 실행 레인 + 워커 맥락 테스트 ──")
    sys.exit(_run())
