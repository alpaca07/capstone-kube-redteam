"""execute_action 단일 통로 테스트 — 실행·대본기록·스코프차단·의존성주입·플래그·determinism.

    python3 tests/test_attacker_execute.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.actions import AttackAction  # noqa: E402
from attacker.execute_action import ActionExecutor, CommandResult, extract_value  # noqa: E402
from attacker.scope import default_policy  # noqa: E402
from common.replay_schema import (  # noqa: E402
    Determinism, Extract, ExtractMethod, InputRef, InputSource, ProducesRef,
)

JP, RX, FULL = ExtractMethod.JSONPATH, ExtractMethod.REGEX, ExtractMethod.FULL


class _FakeRunner:
    def __init__(self, results=None, by_tool=None, default=None):
        self.calls = []
        self.results = list(results) if results else None
        self.by_tool = by_tool or {}
        self.default = default or CommandResult(0, "", "")

    def run(self, tool, args, *, stdin=None, timeout=None):
        self.calls.append((tool, list(args)))
        if self.results:
            return self.results.pop(0)
        return self.by_tool.get(tool, self.default)


def _ex(runner):
    return ActionExecutor(runner, scope_policy=default_policy(denied_hosts=["10.99.0.1"]),
                          session_id="s", episode=1, round=1)


# ───────────── 값 추출 ─────────────
def test_extract_jsonpath():
    assert extract_value('{"data":{"password":"cGVw"}}', Extract(method=JP, path="$.data.password")) == "cGVw"
    assert extract_value('{"items":[{"metadata":{"name":"np1"}}]}',
                         Extract(method=JP, path="$.items[0].metadata.name")) == "np1"
    assert extract_value("not json", Extract(method=JP, path="$.a")) is None


def test_extract_regex_and_full():
    assert extract_value("token=abc123;", Extract(method=RX, path=r"token=(\w+)")) == "abc123"
    assert extract_value("x FLAG{y} z", Extract(method=RX, path=r"FLAG\{[^}]*\}")) == "FLAG{y}"
    assert extract_value("nope", Extract(method=RX, path=r"zzz")) is None
    assert extract_value("  hi  ", Extract(method=FULL)) == "hi"
    assert extract_value("  hi  ", None) == "hi"


# ───────────── 단일 통로 ─────────────
def test_execute_basic_records_step():
    runner = _FakeRunner(by_tool={"kubectl": CommandResult(0, "pod1\npod2\n")})
    ex = _ex(runner)
    obs = ex.execute(AttackAction(thought="t", tool="kubectl", args=["get", "pods"]))
    assert obs.success and obs.exit_code == 0 and "pod1" in obs.stdout
    assert runner.calls == [("kubectl", ["get", "pods"])]
    assert len(ex.script.steps) == 1 and ex.script.steps[0].result.success
    assert ex.script.steps[0].result.stdout_hash.startswith("sha256:")


def test_scope_block_skips_execution():
    runner = _FakeRunner()
    ex = _ex(runner)
    obs = ex.execute(AttackAction(thought="t", tool="curl", args=["http://evil.com/x"]))
    assert obs.blocked and not obs.success
    assert runner.calls == []                               # 실행 안 함
    assert "BLOCKED" in ex.script.steps[0].result.stdout_excerpt
    # 관리망도 차단
    ex.execute(AttackAction(thought="t", tool="curl", args=["http://10.99.0.1:8000/"]))
    assert len(runner.calls) == 0


def test_produces_then_input_substitution():
    runner = _FakeRunner(results=[
        CommandResult(0, '{"data":{"password":"SECRET"}}'),
        CommandResult(0, "connected"),
    ])
    ex = _ex(runner)
    ex.execute(AttackAction(thought="t", tool="kubectl", args=["get", "secret", "-o", "json"],
                            produces={"pw": ProducesRef(extract=Extract(method=JP, path="$.data.password"))}))
    ex.execute(AttackAction(thought="t", tool="sh", args=["-c", "echo using {pw}"],
                            inputs={"pw": InputRef(source=InputSource.STEP_OUTPUT, from_step=1,
                                                   extract=Extract(method=JP, path="$.data.password"))}))
    assert runner.calls[1] == ("sh", ["-c", "echo using SECRET"])   # {pw} 치환됨


def test_flag_detection_records_flagcheck():
    runner = _FakeRunner(by_tool={"psql": CommandResult(0, "value\nFLAG{shopflow_abc}\n")})
    ex = _ex(runner)
    obs = ex.execute(AttackAction(thought="t", tool="psql", args=["-c", "SELECT value"]))
    assert obs.flag_found == "FLAG{shopflow_abc}" and ex.flags_found == ["FLAG{shopflow_abc}"]
    step = ex.script.steps[0]
    assert step.flag_check is not None and step.flag_check.obtained
    assert step.result.stdout_full is not None              # 플래그 스텝은 전체 저장


def test_determinism_classified():
    runner = _FakeRunner(by_tool={"openssl": CommandResult(0, "deadbeef")})
    ex = _ex(runner)
    ex.execute(AttackAction(thought="t", tool="openssl", args=["rand", "-hex", "16"]))
    assert ex.script.steps[0].determinism == Determinism.NONDETERMINISTIC
    ex.execute(AttackAction(thought="t", tool="kubectl", args=["get", "po"]))
    assert ex.script.steps[1].determinism == Determinism.DETERMINISTIC


def test_foothold_input():
    runner = _FakeRunner(by_tool={"curl": CommandResult(0, "ok")})
    ex = _ex(runner)
    ex.execute(AttackAction(thought="t", tool="curl", args=["http://{ep}/runbook.html"],
                            inputs={"ep": InputRef(source=InputSource.FOOTHOLD)}),
               foothold={"ep": "10.0.1.5"})
    assert runner.calls[0] == ("curl", ["http://10.0.1.5/runbook.html"])


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
    print("── execute_action 단일 통로 테스트 ──")
    sys.exit(_run())
