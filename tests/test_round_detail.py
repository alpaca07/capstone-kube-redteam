"""라운드 상세 persist 테스트 — 직렬화 + 원자적 파일 쓰기 + 토폴로지 분리.

    python3 tests/test_round_detail.py        # 자체 러너
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.messages import (  # noqa: E402
    AttackEndReason, AttackTurnResult, DefenseEndReason, DefenseTurnResult,
    Detection, PatchItem,
)
from common.replay_schema import Command, ReplayScript, Step, StepResultRec  # noqa: E402
from orchestrator.round_detail import round_detail_dict, write_round_detail  # noqa: E402
from orchestrator.verifier import Verdict, VerificationResult  # noqa: E402


def _attack() -> AttackTurnResult:
    script = ReplayScript(session_id="vmA", episode=1, round=1, steps=[
        Step(step=0, step_id="1.0", command=Command(tool="kubectl", args=["get", "ns"]),
             result=StepResultRec(success=True))])
    return AttackTurnResult(end_reason=AttackEndReason.FLAG, replay_script=script,
                            attack_summary="요약", elapsed_sec=1.5)


def _defense(topology=None) -> DefenseTurnResult:
    return DefenseTurnResult(
        patch_applied=True, end_reason=DefenseEndReason.PATCHED,
        detected=[Detection(technique="T1210", evidence="direct db")],
        patch_set=[PatchItem(kind="networkpolicy", target="database", summary="NP")],
        patch_attempts=["netpol → database [applied] ok"],
        healthcheck_passed=True, topology=topology, elapsed_sec=1.0)


def _verif() -> VerificationResult:
    return VerificationResult(verdict=Verdict.BLOCKED, method="replay-crown",
                              detail="차단", flags_still_reachable=[])


# ───────────── 순수 직렬화 ─────────────
def test_dict_is_json_serializable_and_nested():
    d = round_detail_dict(1, 2, attack=_attack(), defense=_defense(), verification=_verif())
    blob = json.dumps(d, ensure_ascii=False)          # 직렬화 터지면 실패
    assert d["episode"] == 1 and d["round"] == 2
    # 공격 대본 스텝까지 보존(드릴다운 소스)
    assert d["attack"]["replay_script"]["steps"][0]["command"]["tool"] == "kubectl"
    # 방어 탐지·패치 보존
    assert d["defense"]["detected"][0]["technique"] == "T1210"
    assert d["defense"]["patch_set"][0]["kind"] == "networkpolicy"
    # 검증 verdict 는 enum.value 문자열
    assert d["verification"]["verdict"] == "blocked"
    assert isinstance(blob, str)


def test_none_objects_safe():
    d = round_detail_dict(1, 1)                        # 전부 None
    assert d["attack"] is None and d["defense"] is None and d["verification"] is None


# ───────────── 파일 쓰기 ─────────────
def test_writes_round_detail_file():
    with tempfile.TemporaryDirectory() as tmp:
        write_round_detail(tmp, 1, 3, attack=_attack(), defense=_defense(), verification=_verif())
        f = Path(tmp) / "round_detail" / "1-3.json"
        assert f.exists(), "round_detail/1-3.json 안 생김"
        loaded = json.loads(f.read_text(encoding="utf-8"))
        assert loaded["round"] == 3 and loaded["defense"]["patch_applied"] is True


def test_topology_written_separately_when_present():
    topo = {"generated": True, "namespaces": [{"name": "database", "has_network_policy": True,
            "services": [], "deployments": [], "network_policies": ["np"]}]}
    with tempfile.TemporaryDirectory() as tmp:
        write_round_detail(tmp, 2, 1, attack=_attack(), defense=_defense(topology=topo),
                           verification=_verif())
        tf = Path(tmp) / "defense_topology" / "2-1.json"
        assert tf.exists(), "토폴로지 있는데 defense_topology/2-1.json 안 생김"
        loaded = json.loads(tf.read_text(encoding="utf-8"))
        assert loaded["topology"]["namespaces"][0]["has_network_policy"] is True


def test_no_topology_no_file():
    with tempfile.TemporaryDirectory() as tmp:
        write_round_detail(tmp, 1, 1, attack=_attack(), defense=_defense(topology=None),
                           verification=_verif())
        assert not (Path(tmp) / "defense_topology" / "1-1.json").exists()


def test_out_dir_none_noop():
    write_round_detail(None, 1, 1, attack=_attack())   # 크래시 없으면 통과


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
    print("── 라운드 상세 persist 테스트 ──")
    sys.exit(_run())
