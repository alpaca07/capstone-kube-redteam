"""이벤트 sink 테스트 — 봉투 형태 + 라운드 결과→이벤트 변환.

    python3 tests/test_events.py        # 자체 러너
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.messages import (  # noqa: E402
    AttackEndReason, AttackTurnResult, DefenseEndReason, DefenseTurnResult,
    Detection, PatchItem,
)
from common.replay_schema import (  # noqa: E402
    Command, ReplayScript, Step, StepResultRec,
)
from orchestrator.events import (  # noqa: E402
    EventSink, record_round_events, ATTACKER, DEFENDER, JUDGE,
)
from orchestrator.verifier import Verdict, VerificationResult  # noqa: E402


# ───────────── 빌더 ─────────────
def _script() -> ReplayScript:
    return ReplayScript(session_id="vmA", episode=1, round=1, steps=[
        Step(step=0, step_id="1.0", command=Command(tool="kubectl", args=["get", "pods"]),
             result=StepResultRec(success=True, exit_code=0)),
        Step(step=1, step_id="1.1", command=Command(tool="curl", args=["http://x"]),
             result=StepResultRec(success=False)),
    ])


def _attack() -> AttackTurnResult:
    return AttackTurnResult(
        end_reason=AttackEndReason.DEADEND, replay_script=_script(),
        attack_summary="요약", elapsed_sec=2.0)


def _defense() -> DefenseTurnResult:
    return DefenseTurnResult(
        patch_applied=True, end_reason=DefenseEndReason.PATCHED,
        detected=[Detection(technique="T1078", evidence="admin-sa secret get")],
        patch_set=[PatchItem(kind="rbac", target="internal", summary="binding 삭제")],
        patch_attempts=["delete rbac → internal [applied] ok",
                        "netpol → database [skip] dry-run 실패"],
        healthcheck_passed=True, elapsed_sec=1.0)


def _capture():
    evs: list[dict] = []
    return evs, EventSink(evs.append)


# ───────────── emit 봉투 ─────────────
def test_emit_envelope_shape():
    evs, sink = _capture()
    ev = sink.emit("attack_step", actor=ATTACKER, episode=1, round=2,
                   payload={"tool": "kubectl"}, phase=1)
    assert len(evs) == 1 and evs[0] is ev
    for k in ("ts", "episode", "round", "phase", "actor", "type", "payload"):
        assert k in ev, f"봉투에 {k} 없음"
    assert ev["actor"] == ATTACKER and ev["type"] == "attack_step"
    assert ev["episode"] == 1 and ev["round"] == 2 and ev["phase"] == 1
    assert ev["payload"]["tool"] == "kubectl"


def test_emit_none_write_safe():
    sink = EventSink(None)                 # write 없음 → 무동작(크래시 없음)
    sink.emit("x", actor=JUDGE, episode=1, round=1)


def test_write_failure_swallowed():
    def boom(_ev):
        raise RuntimeError("디스크 터짐")
    sink = EventSink(boom)
    sink.emit("x", actor=JUDGE, episode=1, round=1)   # 예외가 새 나오면 실패


# ───────────── 라운드 결과 → 이벤트 ─────────────
def test_attack_events_per_step_plus_summary():
    evs, sink = _capture()
    record_round_events(sink, episode=1, round=1, attack=_attack())
    steps = [e for e in evs if e["type"] == "attack_step"]
    turns = [e for e in evs if e["type"] == "attack_turn"]
    assert len(steps) == 2 and len(turns) == 1
    assert all(e["actor"] == ATTACKER for e in evs)
    assert steps[0]["payload"]["tool"] == "kubectl" and steps[0]["payload"]["success"] is True
    assert steps[1]["payload"]["tool"] == "curl" and steps[1]["payload"]["success"] is False
    assert turns[0]["payload"]["steps"] == 2          # 플래그리스: 심판이 크라운으로 판정
    assert turns[0]["payload"]["end_reason"] == "deadend"


def test_defense_events_detection_patch_summary():
    evs, sink = _capture()
    record_round_events(sink, episode=1, round=1, defense=_defense())
    dets = [e for e in evs if e["type"] == "detection"]
    patches = [e for e in evs if e["type"] == "patch"]
    turns = [e for e in evs if e["type"] == "defense_turn"]
    assert len(dets) == 1 and dets[0]["payload"]["technique"] == "T1078"
    assert len(patches) == 2                          # patch_attempts 2줄(적용·스킵)
    assert patches[0]["payload"]["applied"] is True
    assert patches[1]["payload"]["applied"] is False  # [skip] → applied False
    assert len(turns) == 1 and turns[0]["payload"]["patch_applied"] is True
    assert all(e["actor"] == DEFENDER for e in evs)


def test_patch_fallback_to_patch_set_when_no_attempts():
    evs, sink = _capture()
    d = DefenseTurnResult(
        patch_applied=True, end_reason=DefenseEndReason.PATCHED,
        patch_set=[PatchItem(kind="networkpolicy", target="database", summary="NP 추가")])
    record_round_events(sink, episode=1, round=1, defense=d)
    patches = [e for e in evs if e["type"] == "patch"]
    assert len(patches) == 1 and patches[0]["payload"]["kind"] == "networkpolicy"
    assert patches[0]["payload"]["applied"] is True


def test_verdict_event():
    evs, sink = _capture()
    record_round_events(sink, episode=1, round=1,
                        verification=VerificationResult(verdict=Verdict.BLOCKED, method="replay-crown"))
    vs = [e for e in evs if e["type"] == "verdict"]
    assert len(vs) == 1 and vs[0]["actor"] == JUDGE
    assert vs[0]["payload"]["verdict"] == "blocked" and vs[0]["payload"]["method"] == "replay-crown"


def test_full_round_all_actors():
    evs, sink = _capture()
    record_round_events(sink, episode=2, round=3, attack=_attack(), defense=_defense(),
                        verification=VerificationResult(verdict=Verdict.FAKE_PATCH, method="replay"))
    actors = {e["actor"] for e in evs}
    assert actors == {ATTACKER, DEFENDER, JUDGE}
    assert all(e["episode"] == 2 and e["round"] == 3 for e in evs)


def test_sink_none_noop():
    record_round_events(None, episode=1, round=1, attack=_attack())   # 크래시 없으면 통과


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
    print("── 이벤트 sink 테스트 ──")
    sys.exit(_run())
