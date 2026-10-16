"""검증 엔진 테스트 — VM C 심장의 판정 로직을 fake 이음새로 완전 검증.

    python3 tests/test_verifier.py      # 자체 러너
    python3 -m pytest tests/            # pytest 있으면 수집됨

기댓값은 설계 판정표(독립 출처)에서 가져온다 — 구현을 다시 계산하지 않음.
  POST 성공 = FAKE_PATCH / POST 실패 = BLOCKED / POST 재생 불능(빈 결과) = INCONCLUSIVE
  (POST-only: 리셋·PRE 없음 → 방어 누적 유지. 공격 검증은 값-flag 대조로 공격 턴에서 끝남.)
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.messages import ReplayPhase, ReplayResult, StepReplayRec  # noqa: E402
from common.replay_schema import Command, FlagCheck, ReplayScript, Step  # noqa: E402
from orchestrator.fakes import (  # noqa: E402
    FakeAttackerClient, FakeDefenderClient, FakeBaseline,
)
from orchestrator.flags import (  # noqa: E402
    FlagKind, FlagRegistry, FlagSpec, default_registry,
)
from orchestrator.verifier import Verdict, VerificationEngine  # noqa: E402
from common.messages import StateCheck  # noqa: E402

PRE, POST = ReplayPhase.PRE, ReplayPhase.POST


# ───────────── 빌더 ─────────────
def _script(flag_id: str = "4", flag_step: int = 2) -> ReplayScript:
    s1 = Step(step=1, command=Command(tool="kubectl", args=["get", "secret"]))
    s2 = Step(step=flag_step, command=Command(tool="psql", args=["-c", "SELECT value"]),
              flag_check=FlagCheck(flag_id=flag_id, obtained=True))
    return ReplayScript(session_id="s", episode=1, round=1, steps=[s1, s2])


def _replay(phase: ReplayPhase, *, flag_step: int = 2, success: bool = True,
            matched=None, overall=None) -> ReplayResult:
    recs = [StepReplayRec(step=1, success=True),
            StepReplayRec(step=flag_step, success=success, matched_baseline=matched)]
    ov = overall if overall is not None else success
    return ReplayResult(phase=phase, steps_result=recs, overall_success=ov,
                        flags_reached=(["4"] if success else []))


def _engine(*, post=None, flags=None):
    attacker = FakeAttackerClient(replay_by_phase=({POST: post} if post is not None else {}))
    defender = FakeDefenderClient()
    baseline = FakeBaseline()
    eng = VerificationEngine(attacker, defender, baseline, flags or default_registry("FLAG{x}"))
    return eng, attacker, defender, baseline


def _run_verify(eng):
    return eng.verify(_script(), episode=1, round=1)


# ───────────── 판정표 (POST-only) ─────────────
def test_post_success_is_fake_patch():
    eng, a, _, _ = _engine(post=_replay(POST, success=True))
    r = _run_verify(eng)
    assert r.verdict == Verdict.FAKE_PATCH
    assert r.method == "replay"
    assert [p for p, _, _ in a.replay_calls] == [POST]       # POST 만 재생(리셋·PRE 없음)
    assert r.flags_still_reachable == ["4"]


def test_post_fail_is_blocked():
    eng, a, _, _ = _engine(post=_replay(POST, success=False))
    r = _run_verify(eng)
    assert r.verdict == Verdict.BLOCKED
    assert r.method == "replay"
    assert [p for p, _, _ in a.replay_calls] == [POST]


def test_empty_post_is_inconclusive():
    # 재생이 한 스텝도 안 돌아감 → 차단으로 오인하지 않고 판정 보류.
    empty = ReplayResult(phase=POST, steps_result=[], overall_success=False)
    eng, _, _, _ = _engine(post=empty)
    r = _run_verify(eng)
    assert r.verdict == Verdict.INCONCLUSIVE


def test_verify_does_not_reset_cluster():
    # 누적 유지 핵심: verify 는 리셋하지 않는다(패치가 라이브에 남아 다음 라운드가 상대).
    eng, _, _, b = _engine(post=_replay(POST, success=False))
    _run_verify(eng)
    assert b.reset_calls == 0


# ───────────── 재현 판정(success-first → hash) ─────────────
def test_reproduced_success_first():
    eng, *_ = _engine(post=_replay(POST))
    ok, reason, reached = eng._reproduced(_replay(POST, success=True, matched=False), _script())
    assert ok and reason == "success" and reached == ["4"]


def test_reproduced_hash_fallback():
    eng, *_ = _engine(post=_replay(POST))
    res = ReplayResult(phase=POST, overall_success=False, steps_result=[
        StepReplayRec(step=1, success=True),
        StepReplayRec(step=2, success=False, matched_baseline=True)])
    ok, reason, reached = eng._reproduced(res, _script())
    assert ok and reason == "hash" and reached == ["4"]


def test_reproduced_no_flag_step_uses_overall_then_hash():
    eng, *_ = _engine(post=_replay(POST))
    bare = ReplayScript(session_id="s", episode=1, round=1,
                        steps=[Step(step=1, command=Command(tool="kubectl", args=["get", "po"]))])
    ok, reason, _ = eng._reproduced(
        ReplayResult(phase=POST, overall_success=True,
                     steps_result=[StepReplayRec(step=1, success=True)]), bare)
    assert ok and reason == "success"
    ok, reason, _ = eng._reproduced(
        ReplayResult(phase=POST, overall_success=False,
                     steps_result=[StepReplayRec(step=1, success=False, matched_baseline=True)]), bare)
    assert ok and reason == "hash"
    ok, *_ = eng._reproduced(
        ReplayResult(phase=POST, overall_success=False,
                     steps_result=[StepReplayRec(step=1, success=False, matched_baseline=False)]), bare)
    assert not ok


# ───────────── 플래그 레지스트리(god-view 답안지) ─────────────
def test_value_match():
    reg = default_registry("FLAG{abc}")
    assert reg.value_match("4", "FLAG{abc}") is True
    assert reg.value_match("4", "  FLAG{abc}  ") is True        # strip
    assert reg.value_match("4", "FLAG{xxx}") is False
    assert reg.value_match("4", None) is False
    assert reg.value_match("1", "whatever") is False            # 상태 플래그는 값대조 대상 아님
    assert default_registry(None).value_match("4", "FLAG{abc}") is False  # 심은값 없음→추측금지


def test_checks_for():
    reg = default_registry("FLAG{x}")
    assert [c.check_id for c in reg.checks_for(["1", "2", "3", "4"])] == ["1", "2", "3"]  # ④ 제외
    assert len(reg.checks_for(["2", "2"])) == 1                 # 중복 제거
    assert reg.checks_for(["4"]) == []                          # 값 전용→빈 리스트


def test_flagspec_validation():
    try:
        FlagSpec(flag_id="x", kind=FlagKind.STATE, mitre="T", description="d")
    except ValueError:
        pass
    else:
        raise AssertionError("STATE 플래그 state_check 없는데 통과함")
    try:
        FlagSpec(flag_id="x", kind=FlagKind.VALUE, mitre="T", description="d",
                 state_check=StateCheck(check_id="x", query="q"))
    except ValueError:
        pass
    else:
        raise AssertionError("VALUE 플래그 state_check 있는데 통과함")


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
    print("── 검증 엔진 테스트 ──")
    sys.exit(_run())
