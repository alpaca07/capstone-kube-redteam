"""검증 엔진 테스트 — VM C 심장의 판정 로직을 fake 이음새로 완전 검증.

    python3 tests/test_verifier.py      # 자체 러너
    python3 -m pytest tests/            # pytest 있으면 수집됨

기댓값은 설계 판정표(독립 출처)에서 가져온다 — 구현을 다시 계산하지 않음.
  pre성공+post성공=FAKE_PATCH / pre성공+post실패=BLOCKED
  pre실패→상태검증: 취약True=NOT_BLOCKED / 전부False=BLOCKED / 불가=INCONCLUSIVE
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
    FakeAttackerClient, FakeDefenderClient, FakeSnapshotManager,
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


def _engine(*, pre, post=None, vuln=None, flags=None, missing=None):
    rp = {PRE: pre}
    if post is not None:
        rp[POST] = post
    attacker = FakeAttackerClient(replay_by_phase=rp)
    defender = FakeDefenderClient(vulnerable_by_check=vuln or {}, missing_checks=missing)
    snaps = FakeSnapshotManager(existing=["clean-baseline", "pre-snap"])
    eng = VerificationEngine(attacker, defender, snaps, flags or default_registry("FLAG{x}"))
    return eng, attacker, defender, snaps


def _run_verify(eng):
    return eng.verify(_script(), episode=1, round=1,
                      pre_snapshot="pre-snap", post_patch_snapshot="post-tmp")


# ───────────── 판정표 ─────────────
def test_pre_success_post_success_is_fake_patch():
    eng, a, _, _ = _engine(pre=_replay(PRE, success=True), post=_replay(POST, success=True))
    r = _run_verify(eng)
    assert r.verdict == Verdict.FAKE_PATCH
    assert r.method == "replay"
    assert [p for p, _, _ in a.replay_calls] == [PRE, POST]   # 둘 다 재생
    assert r.flags_still_reachable == ["4"]


def test_pre_success_post_fail_is_blocked():
    eng, a, _, _ = _engine(pre=_replay(PRE, success=True), post=_replay(POST, success=False))
    r = _run_verify(eng)
    assert r.verdict == Verdict.BLOCKED
    assert r.method == "replay"
    assert [p for p, _, _ in a.replay_calls] == [PRE, POST]


def test_pre_fail_state_not_vulnerable_is_blocked():
    eng, a, d, _ = _engine(pre=_replay(PRE, success=False), post=_replay(POST, success=True),
                           vuln={"1": False, "2": False, "3": False})
    r = _run_verify(eng)
    assert r.verdict == Verdict.BLOCKED
    assert r.method == "state"
    assert [p for p, _, _ in a.replay_calls] == [PRE]          # post 재생 안 함(관문 실패)
    assert d.state_calls == [["1", "2", "3"]]                   # 답안지 전체 상태검증


def test_pre_fail_state_vulnerable_is_not_blocked():
    eng, _, _, _ = _engine(pre=_replay(PRE, success=False),
                           vuln={"1": False, "2": True, "3": False})
    r = _run_verify(eng)
    assert r.verdict == Verdict.NOT_BLOCKED
    assert r.method == "state"
    assert "2" in r.flags_still_reachable


def test_pre_fail_no_state_checks_is_inconclusive():
    eng, _, _, _ = _engine(pre=_replay(PRE, success=False), flags=FlagRegistry([]))
    r = _run_verify(eng)
    assert r.verdict == Verdict.INCONCLUSIVE


def test_pre_fail_missing_state_response_is_inconclusive():
    eng, _, _, _ = _engine(pre=_replay(PRE, success=False),
                           vuln={"1": False, "2": False, "3": False}, missing=["2"])
    r = _run_verify(eng)
    assert r.verdict == Verdict.INCONCLUSIVE


# ───────────── 스냅샷 춤사위 ─────────────
def test_snapshot_choreography_replay_path():
    eng, _, _, s = _engine(pre=_replay(PRE, success=True), post=_replay(POST, success=False))
    _run_verify(eng)
    assert s.calls == [("save", "post-tmp"), ("revert_to", "pre-snap"), ("revert_to", "post-tmp")]
    assert s.current == "post-tmp"        # 끝나면 반드시 패치후 상태(다음 라운드 연속성)


def test_snapshot_choreography_state_path_also_returns_to_post():
    eng, _, _, s = _engine(pre=_replay(PRE, success=False), vuln={"1": False, "2": False, "3": False})
    _run_verify(eng)
    assert s.ops == ["save", "revert_to", "revert_to"]
    assert s.current == "post-tmp"


# ───────────── 재현 판정(success-first → hash) ─────────────
def test_reproduced_success_first():
    eng, *_ = _engine(pre=_replay(PRE))
    ok, reason, reached = eng._reproduced(_replay(POST, success=True, matched=False), _script())
    assert ok and reason == "success" and reached == ["4"]


def test_reproduced_hash_fallback():
    eng, *_ = _engine(pre=_replay(PRE))
    res = ReplayResult(phase=POST, overall_success=False, steps_result=[
        StepReplayRec(step=1, success=True),
        StepReplayRec(step=2, success=False, matched_baseline=True)])
    ok, reason, reached = eng._reproduced(res, _script())
    assert ok and reason == "hash" and reached == ["4"]


def test_reproduced_no_flag_step_uses_overall_then_hash():
    eng, *_ = _engine(pre=_replay(PRE))
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
