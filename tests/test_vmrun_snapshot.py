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
    # revert 후 일시정지 → start로 재개까지 2개 명령(무조건 start).
    assert fr.calls == [
        ["vmrun", "-T", "ws", "revertToSnapshot", _VMX, "clean-baseline"],
        ["vmrun", "-T", "ws", "start", _VMX, "nogui"],
    ]


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


class _LockyRunner:
    """snapshot을 처음 `fails`번은 'file already in use'로, 그 뒤엔 성공으로 돌려줌."""

    def __init__(self, fails: int):
        self.fails_left = fails
        self.snap_calls = 0

    def __call__(self, argv):
        op = argv[3]
        if op == "listSnapshots":
            return RunResult(0, "Total snapshots: 0")
        if op == "snapshot":
            self.snap_calls += 1
            if self.fails_left > 0:
                self.fails_left -= 1
                return RunResult(255, "", "Error: The file is already in use")
            return RunResult(0, "")
        return RunResult(0, "")


def test_run_retries_on_lock_then_succeeds():
    lr = _LockyRunner(fails=2)                 # 2번 잠금 실패 후 3번째 성공
    sleeps: list[float] = []
    sm = VmrunSnapshotManager(_VMX, runner=lr, lock_backoff_sec=0.0,
                              sleeper=lambda s: sleeps.append(s))
    sm.save("clean-baseline")                  # list(0개) → snapshot(실패·실패·성공)
    assert lr.snap_calls == 3                  # 재시도로 결국 성공
    assert len(sleeps) == 2                    # 재시도 사이 2번 대기


def test_run_raises_after_lock_retries_exhausted():
    lr = _LockyRunner(fails=99)                # 계속 잠금
    sm = VmrunSnapshotManager(_VMX, runner=lr, lock_retries=3,
                              lock_backoff_sec=0.0, sleeper=lambda s: None)
    try:
        sm.save("x")
        raise AssertionError("SnapshotError 안 남")
    except SnapshotError as e:
        assert "already in use" in str(e).lower()
    assert lr.snap_calls == 3                  # 총 3번(초기 1 + 재시도 2) 시도 후 포기


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
