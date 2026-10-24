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


class TwoFlagRunner:
    """1번째 호출은 DB FLAG, 이후는 호스트 FLAG stdout — 멀티 objective 수집 테스트용."""

    def __init__(self):
        self.calls = 0

    def run(self, tool, args, *, stdin=None, timeout=None):
        self.calls += 1
        out = "db=FLAG{db1}" if self.calls == 1 else "host=FLAG{host1}"
        return CommandResult(exit_code=0, stdout=out)


class FakeLLM:
    """scripted: 호출별 동작 리스트. ('ok', json[, finish]) 은 그 JSON 반환(finish 기본 'stop'),
    ('timeout',) 은 LLMTimeout. 마지막 항목을 넘어가면 반복. 각 호출의 timeout·max_tokens 기록."""

    def __init__(self, scripted):
        self.scripted = scripted
        self.calls = 0
        self.timeouts_seen: list = []
        self.max_tokens_seen: list = []
        self.users_seen: list = []

    def chat_text_meta(self, system, user, *, timeout=None, max_tokens=None, **kw):
        self.timeouts_seen.append(timeout)
        self.max_tokens_seen.append(max_tokens)
        self.users_seen.append(user)
        item = self.scripted[min(self.calls, len(self.scripted) - 1)]
        self.calls += 1
        if item[0] == "timeout":
            raise LLMTimeout("fake timeout")
        finish = item[2] if len(item) > 2 else "stop"
        return item[1], finish

    def chat_text(self, system, user, **kw):   # 하위호환
        return self.chat_text_meta(system, user, **kw)[0]


class FailThenOkLLM:
    """처음 `fails`번 호출은 깨진 출력(파싱 실패), 이후 정상 액션 반환."""

    def __init__(self, fails: int, good: str):
        self.fails = fails
        self.good = good
        self.calls = 0

    def chat_text_meta(self, system, user, *, timeout=None, max_tokens=None, **kw):
        self.calls += 1
        text = "not json" if self.calls <= self.fails else self.good
        return text, "stop"

    def chat_text(self, system, user, **kw):
        return self.chat_text_meta(system, user, **kw)[0]


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


def test_multi_objective_does_not_stop_on_first_flag():
    # [멀티-objective] 첫 FLAG(DB) 에서 멈추지 않고 계속 탐색 → 두 번째 FLAG(호스트)도 수집.
    #   (예전엔 첫 FLAG 에서 break → 호스트 탈출을 시도조차 못 했음.)
    llm = FakeLLM([("ok", _FLAG_ACTION)])
    ex = ActionExecutor(TwoFlagRunner(), scope_policy=default_policy(),
                        session_id="t", episode=1, round=1)
    res = ReActLoop(llm, ex, AttackHistory(), system_prompt="s", goal="g",
                    time_limit_sec=300.0, max_steps=4).run(foothold={"attack_endpoint": "10.0.0.1"})
    vals = [f.value for f in res.flags_obtained]
    assert "FLAG{db1}" in vals and "FLAG{host1}" in vals, vals     # 두 objective 다 수집
    assert vals.count("FLAG{host1}") == 1                          # 중복 재기록 안 함(값 단위 dedup)


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


def test_truncation_keeps_cap_and_nags_terse():
    # 잘림(finish='length')은 토큰 부족이 아니라 '장황함'이다 → cap 을 키우면(과거 2배 bump 버그로
    # 560s 괴물 호출) 역효과. cap 은 고정하고 '짧게' 나그로 재프롬프트한다.
    truncated = '{"thought":"x","action":{"tool":"kubectl","args":["get"'   # } 안 닫힘
    llm = FakeLLM([("ok", truncated, "length"), ("ok", _ACTION, "stop")])
    ex = ActionExecutor(FakeRunner("ok"), scope_policy=default_policy(),
                        session_id="t", episode=1, round=1)
    loop = ReActLoop(llm, ex, AttackHistory(), system_prompt="s", goal="g",
                     time_limit_sec=300.0, max_steps=1, max_tokens=1024)
    loop.run(foothold={"attack_endpoint": "10.0.0.1"})
    assert llm.max_tokens_seen[:2] == [1024, 1024], llm.max_tokens_seen   # cap 불변(2배 금지)
    assert "잘렸다" in llm.users_seen[1] and "한 문장" in llm.users_seen[1], llm.users_seen[1]  # 짧게 나그
    assert llm.calls == 2, llm.calls                                      # 2콜째에 성공


def test_empty_thinking_output_fastfails_and_lowers_cap():
    # content 빈 채 finish='length' = 사고 모드 overflow(reasoning_effort 미적용 구버전 Ollama).
    # 재시도는 cap 을 512 로 낮춰 빨리 잘리게 해 낭비를 막는다(261s→~50s).
    llm = FakeLLM([("ok", "", "length"), ("ok", _ACTION, "stop")])
    ex = ActionExecutor(FakeRunner("ok"), scope_policy=default_policy(),
                        session_id="t", episode=1, round=1)
    loop = ReActLoop(llm, ex, AttackHistory(), system_prompt="s", goal="g",
                     time_limit_sec=300.0, max_steps=1, max_tokens=1024)
    loop.run(foothold={"attack_endpoint": "10.0.0.1"})
    assert llm.max_tokens_seen[:2] == [1024, 512], llm.max_tokens_seen    # 빈 출력 → cap 축소
    assert llm.calls == 2, llm.calls


def test_reasoning_effort_none_sent_every_call():
    # 사고 끄기: 매 LLM 호출에 reasoning_effort='none'(Ollama /v1 하드 스위치)이 실려야.
    seen = []
    class _CapLLM:
        def chat_text_meta(self, system, user, *, timeout=None, max_tokens=None, extra=None, **kw):
            seen.append(extra)
            return _ACTION, "stop"
    ex = ActionExecutor(FakeRunner("ok"), scope_policy=default_policy(),
                        session_id="t", episode=1, round=1)
    loop = ReActLoop(_CapLLM(), ex, AttackHistory(), system_prompt="s", goal="g",
                     time_limit_sec=300.0, max_steps=1, max_tokens=1024)
    loop.run(foothold={"attack_endpoint": "10.0.0.1"})
    assert seen and seen[0] == {"reasoning_effort": "none"}, seen


def test_format_violation_keeps_cap_and_nags():
    # 잘림이 아닌 형식 위반(finish='stop')이면 cap 은 그대로 두고 나그로 재프롬프트.
    llm = FakeLLM([("ok", "not json", "stop"), ("ok", _ACTION, "stop")])
    ex = ActionExecutor(FakeRunner("ok"), scope_policy=default_policy(),
                        session_id="t", episode=1, round=1)
    loop = ReActLoop(llm, ex, AttackHistory(), system_prompt="s", goal="g",
                     time_limit_sec=300.0, max_steps=1, max_tokens=1024)
    loop.run(foothold={"attack_endpoint": "10.0.0.1"})
    assert llm.max_tokens_seen[:2] == [1024, 1024], llm.max_tokens_seen   # cap 불변(나그만)


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


def test_render_shows_full_recent_observation_with_creds():
    # 방금 가져온 페이지 '본문 하단'의 DB 커넥션 스트링을 모델이 실제로 봐야 한다.
    # (과거 record 300자·render 200자 컷이 하단 크레덴셜을 잘라 공격자가 추측으로 떨어진 병목.)
    h = AttackHistory()
    creds = "postgresql://appuser:devpassword123@postgres.database.svc.cluster.local:5432/customerdb"
    body = "<html><head><title>런북</title></head><body><h1>운영 런북</h1>" + ("설명 " * 90) + creds + "</body>"
    h.record(AttackAction(thought="런북 확인", tool="sh",
                          args=["wget", "-qO-", "http://internal-wiki.internal.svc.cluster.local/runbook.html"]),
             Observation(step=1, tool="sh", exit_code=0, success=True, stdout=body))
    r = h.render()
    assert "devpassword123" in r, "최근 관측 본문 하단의 크레덴셜이 렌더에서 사라짐(절단 회귀)"


def test_render_pins_credentials_across_window():
    # 크레덴셜을 한 번 관측한 뒤, 창 크기(max_entries=12)를 넘겨 스텝을 많이 더 쌓아도
    # 상단 '핵심 발견' 고정 덕분에 크레덴셜이 계속 보여야 한다(여러 스텝 뒤 활용 가능).
    h = AttackHistory()
    creds = "postgresql://appuser:devpassword123@postgres.database.svc.cluster.local:5432/customerdb"
    h.record(AttackAction(thought="런북", tool="sh", args=["wget", "runbook"]),
             Observation(step=1, tool="sh", exit_code=0, success=True, stdout="DB 접속 " + creds))
    for i in range(2, 20):   # 18스텝 더 → 크레덴셜 엔트리를 창(12) 밖으로 밀어냄
        h.record(AttackAction(thought="탐색", tool="sh", args=["echo", str(i)]),
                 Observation(step=i, tool="sh", exit_code=0, success=True, stdout="noise"))
    r = h.render()
    assert "핵심 발견" in r, "고정 섹션이 없음"
    assert "devpassword123" in r, "창 밖으로 밀린 크레덴셜이 고정되지 않음"


def test_render_recent_full_older_truncated():
    # 최근 2개는 넉넉히(full), 오래된 관측은 old_chars(200)로 축약 → 프롬프트 비대 방지.
    h = AttackHistory()
    for i in range(1, 6):
        h.record(AttackAction(thought="t", tool="sh", args=["echo"]),
                 Observation(step=i, tool="sh", exit_code=0, success=True, stdout=f"S{i}_" + ("z" * 800)))
    r = h.render()
    assert "z" * 300 in r, "최근 관측이 넉넉히 안 보임"          # step4·5 는 full
    seg = r.split("S1_", 1)[1] if "S1_" in r else ""           # 가장 오래된 step1
    lead = len(seg) - len(seg.lstrip("z"))
    assert lead <= 200, f"오래된 관측이 축약 안 됨(lead={lead})"


class _FailRunner:
    """항상 실패(exit≠0) 반환 — 막힌 경로를 반복 시도하는 상황 시뮬."""

    def run(self, tool, args, *, stdin=None, timeout=None):
        return CommandResult(exit_code=1, stdout="", stderr="connection refused")


def test_consecutive_exec_failures_deadend():
    # perseveration 가드: 막힌 명령을 계속 실행하면 연속 실패 한계에서 조기 DEADEND
    # (40스텝 다 안 갈아먹고 블록된 라운드를 빠르게 종료).
    from attacker.react_loop import _MAX_EXEC_FAILS
    llm = FakeLLM([("ok", _ACTION)])        # 매번 같은 유효 액션(실행은 계속 실패)
    ex = ActionExecutor(_FailRunner(), scope_policy=default_policy(),
                        session_id="t", episode=1, round=1)
    loop = ReActLoop(llm, ex, AttackHistory(), system_prompt="s", goal="g",
                     time_limit_sec=300.0, max_steps=40)
    res = loop.run(foothold={"attack_endpoint": "10.0.0.1"})
    assert res.end_reason == AttackEndReason.DEADEND, res.end_reason
    assert len(res.replay_script.steps) == _MAX_EXEC_FAILS, len(res.replay_script.steps)  # 한계서 종료


def test_prior_summary_triggers_reattempt_framing():
    # R2+ (carry-forward 있음): '이미 했다'로 포기 안 하게 '매 라운드 재달성' 프레이밍이 붙어야.
    from attacker.react_loop import build_user_prompt
    h = AttackHistory(prior_summary="[R1] psql로 internal_secrets 덤프. 플래그 획득: ['4']")
    p = build_user_prompt(goal="FLAG 획득", flag_format="FLAG{...}", history=h)
    assert "다시" in p and "포기 사유가 아니다" in p, p      # 재시도 지시
    assert "정보(통했던 경로)" in p, p                        # 성과가 아니라 정보로 프레이밍


def test_first_round_no_reattempt_framing():
    # 첫 라운드(prior 없음)엔 재시도 프레이밍이 없어야(불필요).
    from attacker.react_loop import build_user_prompt
    p = build_user_prompt(goal="FLAG 획득", flag_format="FLAG{...}", history=AttackHistory())
    assert "포기 사유가 아니다" not in p


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
