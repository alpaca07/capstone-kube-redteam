"""[Wave1] 통합 테스트 — 탈출 체인·다경로·Discovery 가 채점 파이프라인을 끝까지 흐르는지.

    python3 tests/test_wave1_integration.py

유닛 테스트(매핑·render_op)는 조각을 보지만, 여기선 '실제' 코드를 끝까지 엮어 배선을 증명한다:
  (1) 실 AuditFalcoLogSource 가 합성 감사/Falco 로그에서 Wave1 기법 8종을 전부 뽑는가
  (2) 실 TurnSequencer→TruthLog→Scorer 가 그 기법들을 truth 에 넣고 방어자 자기보고와 대조해
      TP/FP/FN 을 정확히 매기는가 — 선형 깊이 ①~④ 불변, 판정(POST 재생) 포함
  (3) detect-only(Discovery)도 '보고하면' 탐지로 정탐(TP)되는가
공격자/방어자/클러스터만 fake(fakes.py) — 제어·채점·매핑 로직은 전부 실제 코드.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.messages import (  # noqa: E402
    AttackEndReason, AttackTurnResult, DefenseEndReason, DefenseTurnResult,
    Detection, FlagObtained, ReplayPhase, ReplayResult, StepReplayRec,
)
from common.replay_schema import Command, FlagCheck, ReplayScript, Step  # noqa: E402
from orchestrator.fakes import FakeAttackerClient, FakeBaseline, FakeDefenderClient, FakeLogSource  # noqa: E402
from orchestrator.flags import default_registry  # noqa: E402
from orchestrator.log_source import AuditFalcoLogSource, parse_rfc3339  # noqa: E402
from orchestrator.sequencer import RunParams, TurnSequencer  # noqa: E402
from orchestrator.truth_log import TruthLog  # noqa: E402
from orchestrator.verifier import VerificationEngine  # noqa: E402

PRE, POST = ReplayPhase.PRE, ReplayPhase.POST
_ADMIN = "system:serviceaccount:internal:admin-sa"
_FOOT = "system:serviceaccount:frontend:foothold-sa"

# 메인 체인(①②③④) + 탈출 체인(T1610/T1611) + Discovery(T1046/T1613/T1069)를 한 라운드에
# 전부 밟았을 때 god-view 로그가 내놓을 기법 집합(T1552.001 은 ①·다경로가 겹쳐 1개로 수렴).
_FULL = {"T1078", "T1552.001", "T1613", "T1069", "T1610", "T1210", "T1046", "T1611"}


# ───────────── (1) 실 log_source 가 합성 로그에서 Wave1 기법을 뽑는가 ─────────────
def _audit(ts: str, user: str, verb: str, resource: str) -> str:
    return json.dumps({"verb": verb, "user": {"username": user},
                       "objectRef": {"resource": resource},
                       "requestReceivedTimestamp": ts})


def _falco(ts: str, rule: str) -> str:
    return json.dumps({"rule": rule, "time": ts})


def _reader(lines):
    return lambda: iter(lines)


def test_real_logsource_extracts_all_wave1_techniques():
    audit = [
        _audit("2026-10-24T10:00:01Z", _ADMIN, "get", "secrets"),        # T1078 ②
        _audit("2026-10-24T10:00:02Z", _ADMIN, "get", "configmaps"),     # T1552.001 다경로
        _audit("2026-10-24T10:00:03Z", _ADMIN, "list", "namespaces"),    # T1613
        _audit("2026-10-24T10:00:04Z", _FOOT, "create", "selfsubjectaccessreviews"),  # T1069
        _audit("2026-10-24T10:00:05Z", _ADMIN, "create", "pods"),        # T1610
    ]
    falco = [
        _falco("2026-10-24T10:00:06.000000000Z", "Credential access from foothold"),  # T1552.001 ①
        _falco("2026-10-24T10:00:07.000000000Z", "Lateral movement to database"),     # T1210 ③
        _falco("2026-10-24T10:00:08.000000000Z", "Port scan from foothold"),          # T1046
        _falco("2026-10-24T10:00:09.000000000Z", "Escape to host filesystem"),        # T1611
    ]
    src = AuditFalcoLogSource(_reader(audit), _reader(falco))
    t0 = parse_rfc3339("2026-10-24T10:00:00Z")
    t1 = parse_rfc3339("2026-10-24T10:00:10Z")
    got = src.techniques_in_window(since_ts=t0, until_ts=t1)
    assert got == _FULL, f"기대 {_FULL}, 실제 {got}"


# ───────────── (2)(3) 실 시퀀서→truth→채점 (공격자/방어자/클러스터만 fake) ─────────────
def _escape_script() -> ReplayScript:
    # 토큰탈취 → T1610 파드배포 → ④ DB FLAG. flag_check 는 ④(검증 판정 기준).
    return ReplayScript(session_id="s", episode=1, round=1, steps=[
        Step(step=1, command=Command(tool="sh", args=["-c", "wget .../internal/secret/internal/admin-sa-token"])),
        Step(step=2, command=Command(tool="sh", args=["-c", "wget --post-data=@pod .../pods"])),
        Step(step=3, command=Command(tool="psql", args=["-c", "SELECT value FROM internal_secrets"]),
             flag_check=FlagCheck(flag_id="4", obtained=True))])


def _escape_attack() -> AttackTurnResult:
    return AttackTurnResult(
        end_reason=AttackEndReason.FLAG,
        flags_obtained=[FlagObtained(flag_id="4", value="FLAG{win}", step=3)],
        replay_script=_escape_script(),
        attack_summary="②토큰탈취→T1610 배포→T1611 탈출 + ④ FLAG", elapsed_sec=1.0)


def _seq(defense: DefenseTurnResult, *, attack: AttackTurnResult = None,
         flag4: str = "FLAG{win}", host: str = None):
    attacker = FakeAttackerClient(
        replay_by_phase={
            PRE: ReplayResult(phase=PRE, overall_success=True,
                              steps_result=[StepReplayRec(step=3, success=True)]),
            POST: ReplayResult(phase=POST, overall_success=False,          # 패치 후 ④ 재생 실패 → BLOCKED
                               steps_result=[StepReplayRec(step=3, success=False)])},
        attack_result=attack or _escape_attack())
    defender = FakeDefenderClient(defense_result=defense)
    snaps = FakeBaseline(existing=["clean-baseline"])
    registry = default_registry(flag4, host)
    verifier = VerificationEngine(attacker, defender, snaps, registry)
    truth = TruthLog()
    captured: list[dict] = []
    params = RunParams(episodes=1, max_rounds=1, n_consecutive_defense=99,
                       baseline_snapshot="clean-baseline", attack_endpoint="10.0.0.5")
    seq = TurnSequencer(attacker=attacker, defender=defender, snapshots=snaps, verifier=verifier,
                        logs=FakeLogSource(constant=_FULL), registry=registry, truth=truth,
                        params=params, sink=captured.append)
    return seq, {"truth": truth, "captured": captured}


def test_escape_chain_scored_end_to_end():
    # 방어자가 ②·③·탈출(T1610/T1611)은 보고, 다경로·Discovery 는 놓침.
    defense = DefenseTurnResult(
        patch_applied=True, end_reason=DefenseEndReason.PATCHED,
        detected=[Detection(technique="T1078", evidence="admin-sa get secret"),
                  Detection(technique="T1210", evidence="falco lateral"),
                  Detection(technique="T1610", evidence="admin-sa create pods"),
                  Detection(technique="T1611", evidence="falco escape")],
        healthcheck_passed=True, elapsed_sec=1.0)
    seq, ctx = _seq(defense)
    summary = seq.run_episode(1)

    # truth 에 탈출 체인·다경로·메인·④가 전부 들어왔나
    techs = ctx["truth"].entries(1)[0].techniques()
    for t in ("T1610", "T1611", "T1552.001", "T1613", "T1069", "T1046", "T1078", "T1210", "T1213"):
        assert t in techs, f"{t} 가 truth 에 없음: {techs}"

    rec = ctx["captured"][0]
    det = rec["detection_cum"]
    assert det["tp"] == 4, det      # T1078·T1210·T1610·T1611 정탐
    assert det["fp"] == 0, det      # 오탐 없음
    assert det["fn"] == 5, det      # T1552·T1213·T1613·T1069·T1046 놓침(패밀리 단위)

    # 선형 깊이는 digit 플래그만 → ④ 도달. 확장 기법(비-digit)이 깊이를 흐리지 않음.
    assert summary.max_flag_depth == 4, summary.max_flag_depth
    assert rec["stages_reached"] == [1, 2, 3, 4], rec["stages_reached"]

    # 판정: 패치 후 ④ 재생 실패 → BLOCKED
    assert rec["verdict"] == "blocked", rec["verdict"]


def test_discovery_reported_counts_as_tp():
    # detect-only(Discovery)라도 '발생 + 보고'면 탐지 정탐(TP). 과잉패치 없이 탐지만으로 점수.
    defense = DefenseTurnResult(
        patch_applied=False, end_reason=DefenseEndReason.PATCHED,
        detected=[Detection(technique="T1046", evidence="falco portscan"),
                  Detection(technique="T1613", evidence="admin-sa list ns")],
        healthcheck_passed=True, elapsed_sec=1.0)
    seq, ctx = _seq(defense)
    seq.run_episode(1)
    det = ctx["captured"][0]["detection_cum"]
    assert det["tp"] == 2 and det["fp"] == 0, det   # 둘 다 truth 에 있음 → TP, 오탐 0


# ───────────── 호스트 objective (크라운 주얼, 값대조) ─────────────
def _attack_db_and_host() -> AttackTurnResult:
    # 하네스는 찾은 FLAG 를 전부 flag_id="4" 로 보고(하드코딩) — god-view 가 '값'으로 구분해야 함.
    return AttackTurnResult(
        end_reason=AttackEndReason.FLAG,
        flags_obtained=[FlagObtained(flag_id="4", value="FLAG{db1}", step=3),
                        FlagObtained(flag_id="4", value="FLAG{host1}", step=5)],
        replay_script=_escape_script(),
        attack_summary="DB ④ + 호스트 탈출 objective 둘 다", elapsed_sec=1.0)


def test_match_value_identifies_objective_by_value():
    reg = default_registry("FLAG{db_xyz}", "FLAG{host_abc}")
    assert reg.match_value("FLAG{db_xyz}") == "4"         # 값으로 ④ 식별
    assert reg.match_value("FLAG{host_abc}") == "host"    # 값으로 호스트 objective 식별
    assert reg.match_value("FLAG{unknown}") is None       # 안 심은 값은 매칭 안 됨(추측 금지)
    assert {s.flag_id for s in reg.objectives()} == {"4", "host"}
    assert reg.get("host").mitre == "T1005"


def test_host_objective_scored_end_to_end():
    # DB(④)·호스트 FLAG 를 둘 다 '값'으로 보고(하네스는 flag_id="4" 하드코딩) → god-view 가 값으로
    # 각 objective 식별 → 'host'(T1005) + ④(T1213) 둘 다 truth. 선형 깊이는 digit(④)만.
    defense = DefenseTurnResult(
        patch_applied=True, end_reason=DefenseEndReason.PATCHED,
        detected=[Detection(technique="T1611", evidence="falco escape")],  # 탈출 실제 발생 → TP
        healthcheck_passed=True, elapsed_sec=1.0)
    seq, ctx = _seq(defense, attack=_attack_db_and_host(), flag4="FLAG{db1}", host="FLAG{host1}")
    summary = seq.run_episode(1)
    entry = ctx["truth"].entries(1)[0]
    assert "host" in entry.flags_reached and "4" in entry.flags_reached   # 두 크라운 주얼 달성
    assert "T1005" in entry.techniques() and "T1213" in entry.techniques()
    assert summary.max_flag_depth == 4            # 선형 깊이는 digit(④)만 — 'host'(비-digit) 안 흐림
    det = ctx["captured"][0]["detection_cum"]
    assert det["tp"] == 1 and det["fp"] == 0      # 탈출 실발생 → T1611 보고는 정탐(오탐 아님)


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
    print("── [Wave1] 통합 테스트 ──")
    sys.exit(_run())
