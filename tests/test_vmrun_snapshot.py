"""vmrun 스냅샷 어댑터 테스트 — 실제 vmrun·ssh 없이 명령 생성·파싱만 fake로 검증.

    python3 tests/test_vmrun_snapshot.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from orchestrator.vmrun_snapshot import (  # noqa: E402
    RunResult, SnapshotError, VmrunSnapshotManager,
    build_remote_cmd, parse_snapshot_list,
)

_VMX = r"C:\VMs\VM-B\VM-B.vmx"


class FakeRunner:
    """vmrun argv를 받아 기록하고, listSnapshots엔 미리 심은 목록을 돌려줌."""

    def __init__(self, snapshots=(), *, fail_on=None):
        self.snaps = list(snapshots)
        self.calls: list[list[str]] = []
        self.fail_on = fail_on          # 이 op면 실패 반환

    def __call__(self, argv):
        self.calls.append(argv)
        op = argv[3]                    # [vmrun, -T, ws, <op>, vmx, ...]
        if self.fail_on and op == self.fail_on:
            return RunResult(1, "", "boom")
        if op == "listSnapshots":
            body = f"Total snapshots: {len(self.snaps)}\n" + "\n".join(self.snaps)
            return RunResult(0, body)
        return RunResult(0, "")

    def ops(self):
        return [c[3] for c in self.calls]


def test_argv_shape_revert():
    fr = FakeRunner()
    VmrunSnapshotManager(_VMX, runner=fr).revert_to("clean-baseline")
    assert fr.calls == [["vmrun", "-T", "ws", "revertToSnapshot", _VMX, "clean-baseline"]]


def test_vmrun_path_override():
    fr = FakeRunner()
    exe = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
    VmrunSnapshotManager(_VMX, runner=fr, vmrun=exe).revert_to("x")
    assert fr.calls[0][0] == exe


def test_save_when_absent_just_creates():
    fr = FakeRunner(snapshots=[])
    VmrunSnapshotManager(_VMX, runner=fr).save("clean-baseline")
    assert fr.ops() == ["listSnapshots", "snapshot"]       # 지우기 없이 생성만


def test_save_when_present_deletes_then_creates():
    fr = FakeRunner(snapshots=["clean-baseline"])
    VmrunSnapshotManager(_VMX, runner=fr).save("clean-baseline")
    assert fr.ops() == ["listSnapshots", "deleteSnapshot", "snapshot"]


def test_delete_absent_is_noop():
    fr = FakeRunner(snapshots=[])
    VmrunSnapshotManager(_VMX, runner=fr).delete("ep1-r1-postattack")
    assert fr.ops() == ["listSnapshots"]                   # 없으면 삭제 안 함


def test_delete_present():
    fr = FakeRunner(snapshots=["ep1-r1-postattack"])
    VmrunSnapshotManager(_VMX, runner=fr).delete("ep1-r1-postattack")
    assert fr.ops() == ["listSnapshots", "deleteSnapshot"]


def test_list_parses_names():
    fr = FakeRunner(snapshots=["clean-baseline", "ep1-r1-postattack"])
    assert VmrunSnapshotManager(_VMX, runner=fr).list() == ["clean-baseline", "ep1-r1-postattack"]


def test_error_raises_snapshoterror():
    fr = FakeRunner(fail_on="revertToSnapshot")
    try:
        VmrunSnapshotManager(_VMX, runner=fr).revert_to("x")
        raise AssertionError("SnapshotError 안 남")
    except SnapshotError as e:
        assert "revertToSnapshot" in str(e)


def test_parse_snapshot_list_header_and_indent():
    out = "Total snapshots: 2\nclean-baseline\n\tep1-r1-postattack\n"
    assert parse_snapshot_list(out) == ["clean-baseline", "ep1-r1-postattack"]
    assert parse_snapshot_list("Total snapshots: 0\n") == []


def test_build_remote_cmd_quotes_spaces_only():
    argv = ["vmrun", "-T", "ws", "snapshot", r"C:\Virtual Machines\VM-B.vmx", "clean-baseline"]
    assert build_remote_cmd(argv) == r'vmrun -T ws snapshot "C:\Virtual Machines\VM-B.vmx" clean-baseline'


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
    print("── vmrun 스냅샷 어댑터 테스트 ──")
    sys.exit(_run())
