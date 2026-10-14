"""HttpSnapshotManager 테스트 — fake transport로 네트워크 없이 요청·파싱·에러 검증.

    python3 tests/test_http_snapshot.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from orchestrator.http_snapshot import HttpSnapshotManager  # noqa: E402
from orchestrator.vmrun_snapshot import SnapshotError        # noqa: E402

_URL = "http://host:8010"


class FakeTransport:
    """(url, body, timeout)를 기록하고 path별로 미리 심은 응답을 반환."""

    def __init__(self, responses):
        self.responses = responses           # {path: dict}
        self.calls = []                       # (url, body, timeout)

    def __call__(self, url, body, timeout):
        self.calls.append((url, body, timeout))
        path = url[len(_URL):] if url.startswith(_URL) else url
        return self.responses.get(path, {"ok": True})

    def paths(self):
        return [u[len(_URL):] for u, _, _ in self.calls]


def test_save_posts_name_and_lists():
    ft = FakeTransport({"/save": {"ok": True, "snapshots": ["clean-baseline"]}})
    HttpSnapshotManager(_URL, transport=ft).save("clean-baseline")
    assert ft.paths() == ["/save"]
    assert ft.calls[0][1] == {"name": "clean-baseline"}


def test_revert_posts_name():
    ft = FakeTransport({"/revert": {"ok": True}})
    HttpSnapshotManager(_URL, transport=ft).revert_to("clean-baseline")
    assert ft.paths() == ["/revert"]
    assert ft.calls[0][1] == {"name": "clean-baseline"}


def test_delete_posts_name():
    ft = FakeTransport({"/delete": {"ok": True}})
    HttpSnapshotManager(_URL, transport=ft).delete("ep1-r1-postattack")
    assert ft.paths() == ["/delete"]
    assert ft.calls[0][1] == {"name": "ep1-r1-postattack"}


def test_list_returns_snapshots():
    ft = FakeTransport({"/list": {"ok": True, "snapshots": ["a", "b"]}})
    assert HttpSnapshotManager(_URL, transport=ft).list() == ["a", "b"]


def test_not_ok_raises_snapshoterror():
    ft = FakeTransport({"/save": {"ok": False, "error": "boom"}})
    try:
        HttpSnapshotManager(_URL, transport=ft).save("x")
        raise AssertionError("SnapshotError 안 남")
    except SnapshotError as e:
        assert "boom" in str(e)


def test_timeouts_long_for_snap_short_for_list():
    ft = FakeTransport({"/save": {"ok": True, "snapshots": []},
                        "/list": {"ok": True, "snapshots": []}})
    sm = HttpSnapshotManager(_URL, transport=ft, snap_timeout=1800.0, list_timeout=60.0)
    sm.save("x")
    sm.list()
    assert ft.calls[0][2] == 1800.0        # save = 긴 타임아웃
    assert ft.calls[1][2] == 60.0          # list = 짧은 타임아웃


def test_empty_url_raises():
    try:
        HttpSnapshotManager("", transport=FakeTransport({}))
        raise AssertionError("ValueError 안 남")
    except ValueError:
        pass


def test_trailing_slash_stripped():
    ft = FakeTransport({"/list": {"ok": True, "snapshots": []}})
    HttpSnapshotManager(_URL + "/", transport=ft).list()
    assert ft.calls[0][0] == _URL + "/list"   # 이중 슬래시 없이


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
    print("── HttpSnapshotManager 테스트 ──")
    sys.exit(_run())
