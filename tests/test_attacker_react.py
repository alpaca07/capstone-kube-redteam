"""ReAct 루프 예산/타임아웃 스모크 — LLM 호출이 턴 예산을 넘으면 '정상 타임아웃'으로
대본을 보존한 채 끝나는지 검증(네트워크·실 LLM 없이 fake).

    python3 tests/test_attacker_react.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.llm_client import LLMTimeout                     # noqa: E402
from common.messages import AttackEndReason                  # noqa: E402
from attacker.actions import AttackAction                    # noqa: E402
from attacker.execute_action import ActionExecutor, CommandResult, Observation  # noqa: E402
from attacker.history import AttackHistory                   # noqa: E402
from attacker.react_loop import ReActLoop                    # noqa: E402
from attacker.scope import default_policy                    # noqa: E402

_ACTION = '{"thought":"정찰","action":{"tool":"kubectl","args":["get","pods"]}}'
_FLAG_ACTION = '{"thought":"덤프","action":{"tool":"kubectl","args":["get","secret"]}}'
_BAD = "이건 JSON이 아니다"      # 파싱 실패 유발(모든 재시도에서 깨진 출력)


class FakeRunner:
    """CommandRunner — 정해진 stdout 반환(스코프 통과 시 호출됨)."""

    def __init__(self, stdout: str = "ok"):
        self.stdout = stdout
        self.calls = 0

    def run(self, tool, args, *, stdin=None, timeout=None):
        self.calls += 1
        return CommandResult(exit_code=0, stdout=self.stdout)


class FakeLLM:
    """scripted: 호출별 동작 리스트. ('ok', json) 은 그 JSON 반환, ('timeout',) 은 LLMTimeout.
    마지막 항목을 넘어가면 마지막 항목을 반복. 각 호출에 넘어온 timeout 값을 기록."""

    def __init__(self, scripted):
        self.scripted = scripted
        self.calls = 0
        self.timeouts_seen: list = []

    def chat_text(self, system, user, *, timeout=None, **kw):
        self.timeouts_seen.append(timeout)
        item = self.scripted[min(self.calls, len(self.scripted) - 1)]
        self.calls += 1
        if item[0] == "timeout":
            raise LLMTimeout("fake timeout")
        return item[1]


class FailThenOkLLM:
    """처음 `fails`번 호출은 깨진 출력(파싱 실패), 이후 정상 액션 반환."""

    def __init__(self, fails: int, good: str):
        self.fails = fails
        self.good = good
        self.calls = 0

    def chat_text(self, system, user, *, timeout=None, **kw):
        self.calls += 1
        return "not json" if self.calls <= self.fails else self.good


def _loop(llm, *, time_limit=300.0, stdout="ok", max_steps=10):
    ex = ActionExecutor(FakeRunner(stdout), scope_policy=default_policy(),
                        session_id="t", episode=1, round=1)
    return ReActLoop(llm, ex, AttackHistory(), system_prompt="s", goal="g",
                     time_limit_sec=time_limit, max_steps=max_steps)


def test_timeout_midloop_preserves_script():
    # 1수 성공 후 2수에서 LLMTimeout → 정상 타임아웃, 앞서 기록한 대본 1스텝 보존.
    llm = FakeLLM([("ok", _ACTION), ("timeout",)])
    res = _loop(llm).run(foothold={"attack_endpoint": "10.0.0.1"})
    assert res.end_reason == AttackEndReason.TIMEOUT, res.end_reason
    assert res.replay_script is not None
    assert len(res.replay_script.steps) == 1, len(res.replay_script.steps)


def test_timeout_first_call_is_clean_timeout_not_error():
    # 첫 호출부터 타임아웃 → ERROR 아니라 TIMEOUT, 대본 0스텝.
    llm = FakeLLM([("timeout",)])
    res = _loop(llm).run(foothold={"attack_endpoint": "10.0.0.1"})
    assert res.end_reason == AttackEndReason.TIMEOUT, res.end_reason
    assert len(res.replay_script.steps) == 0


def test_percall_timeout_within_budget():
    # 각 LLM 호출에 넘긴 timeout 은 (0, 턴예산] 범위.
    llm = FakeLLM([("ok", _ACTION), ("ok", _ACTION), ("timeout",)])
    _loop(llm, time_limit=300.0).run(foothold={"attack_endpoint": "10.0.0.1"})
    assert llm.timeouts_seen, "timeout 이 안 넘어감"
    assert all(t is not None and 0 < t <= 300.0 for t in llm.timeouts_seen), llm.timeouts_seen


def test_zero_budget_skips_llm():
    # 예산 0 → LLM 호출 자체를 안 하고 바로 TIMEOUT.
    llm = FakeLLM([("ok", _ACTION)])
    res = _loop(llm, time_limit=0.0).run(foothold={"attack_endpoint": "10.0.0.1"})
    assert res.end_reason == AttackEndReason.TIMEOUT, res.end_reason
    assert llm.calls == 0, llm.calls


def test_flag_found_still_terminates_flag():
    # 정상 경로 회귀: stdout 에 FLAG{} 나오면 FLAG 로 종료(타임아웃 변경이 정상 흐름 안 깸).
    llm = FakeLLM([("ok", _FLAG_ACTION)])
    res = _loop(llm, stdout="secret=FLAG{smoke}").run(foothold={"attack_endpoint": "10.0.0.1"})
    assert res.end_reason == AttackEndReason.FLAG, res.end_reason
    assert any(f.value == "FLAG{smoke}" for f in res.flags_obtained)


def test_persistent_parse_fail_is_deadend_not_error():
    # 모든 호출이 깨진 JSON → 스텝마다 스킵, 연속 가드로 DEADEND(ERROR 아님), 대본 0스텝.
    llm = FakeLLM([("ok", _BAD)])
    res = _loop(llm).run(foothold={"attack_endpoint": "10.0.0.1"})
    assert res.end_reason == AttackEndReason.DEADEND, res.end_reason
    assert len(res.replay_script.steps) == 0, len(res.replay_script.steps)


def test_single_parse_fail_then_recovers():
    # 1스텝 파싱 실패(3회 재시도 모두 실패) → 스킵 후 다음 스텝 정상 → FLAG. 한 번 실패가 턴을 안 죽임.
    llm = FailThenOkLLM(fails=3, good=_FLAG_ACTION)
    res = _loop(llm, stdout="secret=FLAG{recover}").run(foothold={"attack_endpoint": "10.0.0.1"})
    assert res.end_reason == AttackEndReason.FLAG, res.end_reason
    assert any(f.value == "FLAG{recover}" for f in res.flags_obtained)


def test_summarize_carries_successful_findings():
    # 라운드 간 기억이 '카운트'가 아니라 성공한 행동+관측을 담아야 다음 라운드가 이어받음.
    h = AttackHistory()
    h.record(AttackAction(thought="정찰", tool="curl", args=["http://192.168.16.128:30080/"]),
             Observation(step=1, tool="curl", exit_code=0, success=True,
                         stdout="db_user=app db_pass=s3cret"))
    h.record(AttackAction(thought="실패수", tool="sh", args=["bad-cmd"]),
             Observation(step=2, tool="sh", exit_code=1, success=False, stderr="not found"))
    s = h.summarize()
    assert "curl http://192.168.16.128:30080/" in s, s   # 성공 명령 보존
    assert "db_pass=s3cret" in s, s                       # 관측(크레덴셜) 보존
    assert "실패 1" in s, s                                # 실패 카운트도


# ───────────── 자체 러너 ─────────────
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
    print("── ReAct 루프 예산/타임아웃 스모크 ──")
    sys.exit(_run())
