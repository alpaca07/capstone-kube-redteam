"""검증 엔진 테스트 — VM C 심장의 판정 로직을 fake 이음새로 완전 검증.

    python3 tests/test_verifier.py      # 자체 러너

플래그리스: 방어 효과는 'POST 재생 후 재생 창의 크라운 자백(crowns)'으로 판정한다.
  크라운 재도달 있음 = FAKE_PATCH / 없음 = BLOCKED / 재생 불능(빈 결과) = INCONCLUSIVE.
  (POST-only: 리셋·PRE 없음 → 방어 누적 유지. 공격 성공은 _build_truth 가 접근기록으로 판정.)
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.app_signals import CROWN_CUSTOMERS_PII, CROWN_INTERNAL_SECRETS  # noqa: E402
from common.messages import ReplayPhase, ReplayResult, StateCheck, StepReplayRec  # noqa: E402
from common.replay_schema import Command, ReplayScript, Step  # noqa: E402
from orchestrator.fakes import (  # noqa: E402
    FakeAttackerClient, FakeBaseline, FakeDefenderClient, FakeLogSource,
)
from orchestrator.flags import FlagKind, FlagSpec, default_registry  # noqa: E402
from orchestrator.objectives import default_objectives  # noqa: E402
from orchestrator.verifier import Verdict, VerificationEngine  # noqa: E402

POST = ReplayPhase.POST


# ───────────── 빌더 ─────────────
def _script() -> ReplayScript:
    s1 = Step(step=1, command=Command(tool="curl", args=["/api/products?q=' UNION"]))
    s2 = Step(step=2, command=Command(tool="curl", args=["/api/invoice/7"]))
    return ReplayScript(session_id="s", episode=1, round=1, steps=[s1, s2])


def _replay(*, steps: int = 2) -> ReplayResult:
    recs = [StepReplayRec(step=i + 1, success=True) for i in range(steps)]
    return ReplayResult(phase=POST, steps_result=recs, overall_success=True)


def _engine(*, post=None, crowns=None):
    attacker = FakeAttackerClient(replay_by_phase=({POST: post} if post is not None else {}))
    defender = FakeDefenderClient()
    baseline = FakeBaseline()
    logs = FakeLogSource(crown_constant=set(crowns or []))
    eng = VerificationEngine(attacker, defender, baseline, default_registry(),
                             logs=logs, objectives=default_objectives())
    return eng, attacker, defender, baseline


def _run_verify(eng):
    return eng.verify(_script(), episode=1, round=1)


# ───────────── 판정표 (POST-only, 크라운 기반) ─────────────
def test_crown_reached_is_fake_patch():
    # 재생 후 크라운이 또 빠짐 → 가짜 패치
    eng, a, _, _ = _engine(post=_replay(), crowns={CROWN_INTERNAL_SECRETS})
    r = _run_verify(eng)
    assert r.verdict == Verdict.FAKE_PATCH
    assert r.method == "replay-crown"
    assert [p for p, _, _ in a.replay_calls] == [POST]       # POST 만 재생(리셋·PRE 없음)
    assert r.flags_still_reachable == ["crown-secrets"]


def test_pii_crown_also_fake_patch():
    eng, _, _, _ = _engine(post=_replay(), crowns={CROWN_CUSTOMERS_PII})
    r = _run_verify(eng)
    assert r.verdict == Verdict.FAKE_PATCH
    assert r.flags_still_reachable == ["crown-pii"]


def test_no_crown_is_blocked():
    # 재생은 됐지만 크라운 재도달 없음 → 진짜 차단
    eng, a, _, _ = _engine(post=_replay(), crowns=set())
    r = _run_verify(eng)
    assert r.verdict == Verdict.BLOCKED
    assert r.method == "replay-crown"
    assert [p for p, _, _ in a.replay_calls] == [POST]


def test_empty_post_is_inconclusive():
    # 재생이 한 스텝도 안 돌아감 → 차단으로 오인하지 않고 판정 보류(크라운 조회 전에 끊음).
    empty = ReplayResult(phase=POST, steps_result=[], overall_success=False)
    eng, _, _, _ = _engine(post=empty, crowns={CROWN_INTERNAL_SECRETS})
    r = _run_verify(eng)
    assert r.verdict == Verdict.INCONCLUSIVE


def test_verify_does_not_reset_cluster():
    # 누적 유지 핵심: verify 는 리셋하지 않는다(패치가 라이브에 남아 다음 라운드가 상대).
    eng, _, _, b = _engine(post=_replay(), crowns=set())
    _run_verify(eng)
    assert b.reset_calls == 0


def test_verify_window_passed_to_logs():
    # 재생 창 [t_pre, t_post] 으로 crowns 를 조회하는가(호출 1회).
    attacker = FakeAttackerClient(replay_by_phase={POST: _replay()})
    logs = FakeLogSource(crown_constant={CROWN_INTERNAL_SECRETS})
    eng = VerificationEngine(attacker, FakeDefenderClient(), FakeBaseline(),
                             default_registry(), logs=logs, objectives=default_objectives())
    eng.verify(_script(), episode=1, round=1)
    assert len(logs.crown_calls) == 1
    since, until = logs.crown_calls[0]
    assert since <= until


# ───────────── 플래그 레지스트리(god-view 답안지, 상태검증 전용) ─────────────
def test_checks_for():
    reg = default_registry()
    # ④ 는 이제 레지스트리에 없다(크라운=objectives) → ①②③ 만 상태검증 생성
    assert [c.check_id for c in reg.checks_for(["1", "2", "3", "4"])] == ["1", "2", "3"]
    assert len(reg.checks_for(["2", "2"])) == 1                 # 중복 제거
    assert reg.checks_for(["4"]) == []                          # ④ 없음→빈 리스트


def test_flag_for_technique_no_value():
    reg = default_registry()
    # 상태 기반 ①②③ 은 매핑되지만, 과거 값기반 ④(T1213)는 레지스트리에서 사라짐
    assert reg.flag_for_technique("T1552.001") == "1"
    assert reg.flag_for_technique("T1213") is None


def test_flagspec_validation():
    try:
        FlagSpec(flag_id="x", kind=FlagKind.STATE, mitre="T", description="d")
    except ValueError:
        pass
    else:
        raise AssertionError("STATE 플래그 state_check 없는데 통과함")
    # state_check 가 있으면 정상 생성
    FlagSpec(flag_id="x", kind=FlagKind.STATE, mitre="T", description="d",
             state_check=StateCheck(check_id="x", query="q"))


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
    print("── 검증 엔진 테스트(크라운 기반) ──")
    sys.exit(_run())
