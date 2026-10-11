"""실 어댑터 테스트 — 실제 네트워크/govc/파일 없이 '순수 부분'만 fake I/O로 검증.

    python3 tests/test_adapters.py
HTTP(봉투 전송 로직) · govc(명령 생성·파싱) · 로그(기법 매핑·시간창) · main(조립·flag 로드).
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.config import load_config  # noqa: E402
from common.messages import (  # noqa: E402
    AttackEndReason, AttackTurnResult, AttackTurnStart,
    DefenseEndReason, DefenseTurnResult, DefenseTurnStart,
    StateCheck, StateCheckResult, StateQuery, StateQueryResult, wrap,
)
from orchestrator.govc_snapshot import (  # noqa: E402
    GovcSnapshotManager, RunResult, SnapshotError, parse_snapshot_tree,
)
from orchestrator.http_clients import HttpAttackerClient, HttpDefenderClient  # noqa: E402
from orchestrator.log_source import (  # noqa: E402
    AuditFalcoLogSource, map_audit_event, map_falco_event, parse_rfc3339,
)
from orchestrator.main import build_sequencer, load_flag4  # noqa: E402
from orchestrator.sequencer import TurnSequencer  # noqa: E402


# ───────────── HTTP 클라이언트 (fake transport) ─────────────
def _transport_returning(response_env):
    sent = {}

    def _t(url, body, timeout):
        sent["url"] = url
        sent["body"] = body
        sent["timeout"] = timeout
        return response_env.model_dump(mode="json")
    return _t, sent


def test_http_attacker_attack_turn():
    resp = wrap(AttackTurnResult(end_reason=AttackEndReason.FLAG, elapsed_sec=2.0),
                episode=1, round=2)
    transport, sent = _transport_returning(resp)
    cli = HttpAttackerClient("http://vm-a:8000/", token="tok", transport=transport)
    out = cli.attack_turn(AttackTurnStart(time_limit_sec=300), episode=1, round=2)
    assert sent["url"] == "http://vm-a:8000/attack_turn_start"   # 요청 타입이 경로
    assert sent["body"]["type"] == "attack_turn_start"
    assert sent["body"]["episode"] == 1 and sent["body"]["round"] == 2
    assert sent["body"]["payload"]["time_limit_sec"] == 300
    assert sent["timeout"] == 300 + 30                           # time_limit + 여유
    assert out.end_reason == AttackEndReason.FLAG                # 응답 파싱


def test_http_defender_defense_turn():
    resp = wrap(DefenseTurnResult(patch_applied=True, end_reason=DefenseEndReason.PATCHED))
    transport, sent = _transport_returning(resp)
    cli = HttpDefenderClient("http://vm-b:8000", transport=transport)
    out = cli.defense_turn(DefenseTurnStart(time_limit_sec=120), episode=3, round=1)
    assert sent["url"] == "http://vm-b:8000/defense_turn_start"
    assert sent["body"]["payload"]["time_limit_sec"] == 120
    assert out.patch_applied is True


def test_http_defender_state_query():
    resp = wrap(StateQueryResult(results=[StateCheckResult(check_id="2", vulnerable=False)]))
    transport, sent = _transport_returning(resp)
    cli = HttpDefenderClient("http://vm-b:8000", transport=transport)
    out = cli.state_query(StateQuery(checks=[StateCheck(check_id="2", query="q")]),
                          episode=1, round=1)
    assert sent["url"] == "http://vm-b:8000/state_query"
    assert out.results[0].check_id == "2" and out.results[0].vulnerable is False


# ───────────── govc 스냅샷 (fake runner) ─────────────
class _FakeRunner:
    def __init__(self, tree_out: str = "") -> None:
        self.cmds: list[list[str]] = []
        self.tree_out = tree_out

    def __call__(self, args: list[str]) -> RunResult:
        self.cmds.append(args)
        if args[1] == "snapshot.tree":
            return RunResult(0, self.tree_out, "")
        return RunResult(0, "", "")

    def subs(self) -> list[str]:
        return [c[1] for c in self.cmds]


def test_govc_revert_builds_command():
    r = _FakeRunner()
    GovcSnapshotManager("VM-B", runner=r).revert_to("clean-baseline")
    assert r.cmds[-1] == ["govc", "snapshot.revert", "-vm", "VM-B", "clean-baseline"]


def test_govc_save_absent_creates_only():
    r = _FakeRunner(tree_out="")                       # 스냅샷 없음
    GovcSnapshotManager("VM-B", runner=r).save("snap")
    assert r.subs() == ["snapshot.tree", "snapshot.create"]   # remove 없음


def test_govc_save_existing_removes_then_creates():
    r = _FakeRunner(tree_out="snap\n")                 # 이미 있음
    GovcSnapshotManager("VM-B", runner=r).save("snap")
    assert r.subs() == ["snapshot.tree", "snapshot.remove", "snapshot.create"]


def test_govc_delete_absent_is_noop():
    r = _FakeRunner(tree_out="other\n")
    GovcSnapshotManager("VM-B", runner=r).delete("snap")
    assert "snapshot.remove" not in r.subs()


def test_govc_list_parses_tree():
    r = _FakeRunner(tree_out="clean-baseline\nep1-r1-postattack\n")
    assert GovcSnapshotManager("VM-B", runner=r).list() == ["clean-baseline", "ep1-r1-postattack"]


def test_govc_error_raises():
    def boom(args):
        return RunResult(1, "", "no such vm")
    try:
        GovcSnapshotManager("VM-B", runner=boom).revert_to("x")
    except SnapshotError:
        return
    raise AssertionError("govc 실패인데 예외 안 남")


def test_parse_snapshot_tree_handles_indent_and_marker():
    out = "clean-baseline\n  child-snap .\nep1-r1-postattack\n\n"
    assert parse_snapshot_tree(out) == ["clean-baseline", "child-snap", "ep1-r1-postattack"]


# ───────────── 로그 소스 (매핑·시간창) ─────────────
def test_parse_rfc3339_known_values():
    assert parse_rfc3339("1970-01-01T00:00:00Z") == 0.0
    assert parse_rfc3339("1970-01-01T00:00:01Z") == 1.0
    assert abs(parse_rfc3339("1970-01-01T00:00:00.123456789Z") - 0.123456) < 1e-9  # 나노초 절단
    assert parse_rfc3339("garbage") is None


def test_map_audit_admin_sa_secret():
    ev = {"verb": "get", "user": {"username": "system:serviceaccount:internal:admin-sa"},
          "objectRef": {"resource": "secrets"}}
    assert map_audit_event(ev) == "T1078"
    # 다른 유저면 매핑 안 됨
    ev2 = dict(ev); ev2["user"] = {"username": "system:serviceaccount:kube-system:default"}
    assert map_audit_event(ev2) is None


def test_map_falco_shell():
    assert map_falco_event({"rule": "Terminal shell in container"}) == "T1059"
    assert map_falco_event({"rule": "Some other rule"}) is None


def _reader(lines):
    return lambda: iter(lines)


def test_log_source_window_and_mapping():
    audit = {"verb": "get", "user": {"username": "system:serviceaccount:internal:admin-sa"},
             "objectRef": {"resource": "secrets"},
             "requestReceivedTimestamp": "2026-10-11T14:56:03.100000Z"}
    falco = {"rule": "Terminal shell in container", "time": "2026-10-11T14:56:04.000000000Z"}
    src = AuditFalcoLogSource(_reader([json.dumps(audit), "not-json"]),
                              _reader([json.dumps(falco)]))
    t0 = parse_rfc3339("2026-10-11T14:56:00Z")
    t1 = parse_rfc3339("2026-10-11T14:56:10Z")
    assert src.techniques_in_window(since_ts=t0, until_ts=t1) == {"T1078", "T1059"}
    # 창 밖이면 비어야 함
    assert src.techniques_in_window(since_ts=t0, until_ts=t0 + 1) == set()


# ───────────── main 조립 & flag 로드 ─────────────
def test_load_flag4_formats():
    with tempfile.TemporaryDirectory() as d:
        p1 = Path(d) / "a.secret"; p1.write_text("FLAG_4=FLAG{abc}\n", encoding="utf-8")
        assert load_flag4(str(p1)) == "FLAG{abc}"
        p2 = Path(d) / "b.secret"; p2.write_text("FLAG{xyz}\n", encoding="utf-8")
        assert load_flag4(str(p2)) == "FLAG{xyz}"
        assert load_flag4(str(Path(d) / "missing")) is None


def test_build_sequencer_from_example_config():
    cfg = load_config(_ROOT / "common" / "config.example.yaml")
    seq = build_sequencer(cfg, flag4_value="FLAG{t}")
    assert isinstance(seq, TurnSequencer)
    assert seq.registry.value_match("4", "FLAG{t}") is True       # ④ 값 주입됨
    assert seq.params.episodes == cfg.experiment.episodes         # config에서 파라미터
    assert seq.params.baseline_snapshot == cfg.vmware.baseline_snapshot


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
    print("── 실 어댑터 테스트 ──")
    sys.exit(_run())
