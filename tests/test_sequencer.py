"""턴 시퀀서 테스트 — fake 이음새로 에피소드 전체 루프를 돌려 제어 로직 검증.

    python3 tests/test_sequencer.py     # 자체 러너
종료조건·라운드 흐름·크래시 복구·킬스위치·god-view 정답 구축을 독립 기댓값으로 확인.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.messages import (  # noqa: E402
    AgentRole, AgentState, AgentStatus,
    AttackEndReason, AttackTurnResult, DefenseEndReason, DefenseTurnResult,
    Detection, FlagObtained, ReplayPhase, ReplayResult, StepReplayRec,
)
from common.replay_schema import Command, FlagCheck, ReplayScript, Step  # noqa: E402
from orchestrator.fakes import (  # noqa: E402
    FakeAttackerClient, FakeDefenderClient, FakeLogSource, FakeSnapshotManager,
)
from orchestrator.flags import default_registry  # noqa: E402
from orchestrator.sequencer import RunParams, TurnSequencer  # noqa: E402
from orchestrator.truth_log import TruthLog  # noqa: E402
from orchestrator.verifier import VerificationEngine  # noqa: E402

PRE, POST = ReplayPhase.PRE, ReplayPhase.POST


# ───────────── 빌더 ─────────────
def _script() -> ReplayScript:
    return ReplayScript(session_id="s", episode=1, round=1, steps=[
        Step(step=1, command=Command(tool="kubectl", args=["get", "secret"])),
        Step(step=2, command=Command(tool="psql", args=["-c", "SELECT value"]),
             flag_check=FlagCheck(flag_id="4", obtained=True))])


def _attack_result() -> AttackTurnResult:
    return AttackTurnResult(
        end_reason=AttackEndReason.FLAG,
        flags_obtained=[FlagObtained(flag_id="4", value="FLAG{win}", step=2)],
        replay_script=_script(), attack_summary="② SA→DB", elapsed_sec=1.0)


def _replay(phase: ReplayPhase, success: bool) -> ReplayResult:
    return ReplayResult(phase=phase, overall_success=success, steps_result=[
        StepReplayRec(step=1, success=True),
        StepReplayRec(step=2, success=success)])


def _defense_result() -> DefenseTurnResult:
    return DefenseTurnResult(
        patch_applied=True, end_reason=DefenseEndReason.PATCHED,
        detected=[Detection(technique="T1078", evidence="admin-sa get secret")],
        healthcheck_passed=True, elapsed_sec=1.0)


def _make(*, post_success: bool, n_consec: int = 2, max_rounds: int = 10,
          episodes: int = 1, kill=None, attacker_override=None):
    attacker = attacker_override or FakeAttackerClient(
        replay_by_phase={PRE: _replay(PRE, True), POST: _replay(POST, post_success)},
        attack_result=_attack_result())
    defender = FakeDefenderClient(defense_result=_defense_result(),
                                  vulnerable_by_check={"1": False, "2": False, "3": False})
    snaps = FakeSnapshotManager(existing=["clean-baseline"])
    registry = default_registry("FLAG{win}")
    verifier = VerificationEngine(attacker, defender, snaps, registry)
    logs = FakeLogSource(constant={"T1078"})
    truth = TruthLog()
    captured: list[dict] = []
    params = RunParams(episodes=episodes, max_rounds=max_rounds, n_consecutive_defense=n_consec,
                       baseline_snapshot="clean-baseline", attack_endpoint="10.0.0.5")
    seq = TurnSequencer(attacker=attacker, defender=defender, snapshots=snaps, verifier=verifier,
                        logs=logs, registry=registry, truth=truth, params=params,
                        sink=captured.append, kill_switch=kill)
    return seq, {"attacker": attacker, "defender": defender, "snaps": snaps,
                 "truth": truth, "captured": captured}


# ───────────── 종료조건 ─────────────
def test_consecutive_defense_ends_episode():
    seq, _ = _make(post_success=False, n_consec=2, max_rounds=10)   # 매 라운드 BLOCKED
    s = seq.run_episode(1)
    assert s.end_reason == "consecutive_defense"
    assert s.rounds == 2                                            # 2연속 방어 성공 후 종료


def test_max_rounds_ends_episode():
    seq, _ = _make(post_success=True, n_consec=2, max_rounds=3)     # 매 라운드 FAKE_PATCH
    s = seq.run_episode(1)
    assert s.end_reason == "max_rounds"
    assert s.rounds == 3
    assert s.verdict_counts.get("fake_patch") == 3


# ───────────── 라운드 흐름 ─────────────
def test_round_flow_and_cleanup():
    seq, ctx = _make(post_success=False, n_consec=99, max_rounds=1)
    seq.run_episode(1)
    snaps = ctx["snaps"]
    assert snaps.calls[0] == ("revert_to", "clean-baseline")        # 0. init
    assert ("save", "ep1-r1-postattack") in snaps.calls            # 2. 공격후 스냅샷
    assert len(ctx["defender"].defense_calls) == 1                  # 3. 방어 턴
    assert [p for p, _, _ in ctx["attacker"].replay_calls] == [PRE, POST]  # 4~5. 검증
    assert len(ctx["truth"].entries(1)) == 1                        # 5.5 정답 기록
    assert len(ctx["captured"]) == 1                                # 6. 채점(JSONL)
    # 8. 라운드 임시 스냅샷 정리
    assert ("delete", "ep1-r1-postattack") in snaps.calls
    assert ("delete", "ep1-r1-postpatch") in snaps.calls


def test_godview_truth_and_detection():
    seq, ctx = _make(post_success=False, n_consec=99, max_rounds=1)
    seq.run_episode(1)
    entry = ctx["truth"].entries(1)[0]
    assert entry.techniques() == {"T1213", "T1078"}                 # ④값대조 + 로그관측
    assert set(entry.flags_reached) == {"2", "4"}
    det = ctx["captured"][0]["detection_cum"]
    assert det["tp"] == 1 and det["fn"] == 1                         # T1078 맞춤 / T1213 놓침


# ───────────── 복구 & 안전 ─────────────
class _BoomAttacker:
    """attack_turn에서 항상 터지는 공격자(크래시 시뮬)."""
    def __init__(self) -> None:
        self.n = 0

    def attack_turn(self, start, *, episode, round):
        self.n += 1
        raise RuntimeError("boom")

    def replay(self, req, *, episode, round):
        raise RuntimeError("unused")

    def status(self):
        return AgentStatus(agent=AgentRole.ATTACKER, state=AgentState.ERROR)


def test_crash_retries_once_then_aborts():
    boom = _BoomAttacker()
    seq, _ = _make(post_success=False, attacker_override=boom)
    s = seq.run_episode(1)
    assert s.end_reason == "aborted"
    assert s.rounds == 0
    assert boom.n == 2                                              # 1회 재시도 후 포기


class _DeadDefender:
    """revert 후 영영 안 깨어나는 방어자(status가 항상 실패)."""
    def __init__(self) -> None:
        self.defense_calls: list = []

    def defense_turn(self, start, *, episode, round):
        self.defense_calls.append((episode, round))
        raise RuntimeError("unused")

    def state_query(self, query, *, episode, round):
        raise RuntimeError("unused")

    def health_check(self, hc, *, episode, round):
        raise RuntimeError("unused")

    def status(self):
        raise RuntimeError("down")


def test_not_ready_after_revert_aborts_episode():
    # VM B가 revert 후 안 깨어나면(공격자는 정상) 공격 턴도 안 가고 에피소드 중단.
    attacker = FakeAttackerClient(
        replay_by_phase={PRE: _replay(PRE, True), POST: _replay(POST, False)},
        attack_result=_attack_result())
    dead = _DeadDefender()
    snaps = FakeSnapshotManager(existing=["clean-baseline"])
    registry = default_registry("FLAG{win}")
    verifier = VerificationEngine(attacker, dead, snaps, registry)
    params = RunParams(episodes=1, max_rounds=5, baseline_snapshot="clean-baseline",
                       attack_endpoint="10.0.0.5", ready_timeout_sec=0.0)
    seq = TurnSequencer(attacker=attacker, defender=dead, snapshots=snaps, verifier=verifier,
                        logs=FakeLogSource(constant={"T1078"}), registry=registry,
                        truth=TruthLog(), params=params, sleeper=lambda s: None)
    s = seq.run_episode(1)
    assert s.end_reason == "aborted"
    assert s.rounds == 0
    assert len(attacker.attack_calls) == 0                 # 준비 안 됨 → 공격 턴 진입 전 중단
    assert snaps.calls[0] == ("revert_to", "clean-baseline")   # revert는 시도함


def test_kill_switch_stops_mid_episode():
    state = {"n": 0}

    def kill():
        state["n"] += 1
        return state["n"] >= 2                                      # 라운드2 진입 전 발동

    seq, _ = _make(post_success=False, n_consec=99, max_rounds=10, kill=kill)
    s = seq.run_episode(1)
    assert s.end_reason == "killed"
    assert s.rounds == 1


# ───────────── 다중 에피소드 ─────────────
def test_run_experiment_multiple_episodes():
    seq, ctx = _make(post_success=True, max_rounds=1, episodes=2)
    res = seq.run_experiment()
    assert len(res) == 2 and all(r.rounds == 1 for r in res)
    assert ctx["snaps"].calls.count(("revert_to", "clean-baseline")) == 2   # 에피소드마다 리셋


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
    print("── 턴 시퀀서 테스트 ──")
    sys.exit(_run())
