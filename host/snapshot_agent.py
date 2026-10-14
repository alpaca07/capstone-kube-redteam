"""호스트 스냅샷 에이전트 — Windows 호스트의 '데스크톱 세션'에서 돌리는 작은 HTTP 서버.

왜 필요한가:
  VMware Workstation에서 vmrun의 스냅샷 명령(revertToSnapshot·snapshot·listSnapshots)은
  SSH로도 되지만, revert 후 VM '재개(start)'는 호스트의 interactive 데스크톱 세션이 필요해
  SSH로는 실패한다("Error: There was an error in communication"). 그래서 VM C 오케스트레이터가
  SSH로 vmrun을 직접 때리는 대신, 이 에이전트를 '데스크톱 세션에서' 띄워 로컬 vmrun을
  실행하게 하고, VM C는 HTTP로 호출만 한다(orchestrator/http_snapshot.py).

실행 (반드시 호스트의 로그인된 데스크톱 세션 = PowerShell 창에서):
  python host\\snapshot_agent.py ^
    --vmx "C:\\Users\\ycdc\\Documents\\Virtual Machines\\VM-B-target\\VM-B-target.vmx" ^
    --vmrun "C:\\Program Files (x86)\\VMware\\VMware Workstation\\vmrun.exe" ^
    --host 0.0.0.0 --port 8010

주의:
  - 반드시 로그인된 데스크톱 세션에서 실행해야 vmrun start(재개)가 동작한다. Windows 서비스로
    등록하거나 SSH로 띄우면 세션0 문제로 재개가 다시 실패한다. 실험 중엔 호스트 로그인 유지.
  - 의존성은 Python 표준 라이브러리뿐(추가 pip 설치 없음). orchestrator/vmrun_snapshot.py의
    순수 로직(명령 생성·파싱·잠금 재시도·save/revert)을 재사용한다(레포가 호스트에 있어야 함).
  - 오케스트레이터는 순차 호출이라 단일 스레드 서버로 충분(동시 vmrun 충돌 없음).
"""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# 레포 루트를 경로에(host/snapshot_agent.py → 루트는 한 단계 위) — vmrun_snapshot 재사용.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from orchestrator.vmrun_snapshot import (  # noqa: E402
    SnapshotError, VmrunSnapshotManager, local_runner,
)


def make_handler(sm: VmrunSnapshotManager, token: str = ""):
    """SnapshotManager를 감싸 HTTP 요청을 처리하는 핸들러 클래스 생성(의존성 주입)."""

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code: int, obj: dict) -> None:
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):            # 콘솔에 간단 로그
            sys.stderr.write("[agent] %s\n" % (fmt % args))

        def do_POST(self):                             # noqa: N802
            if token:                                  # 공유 토큰 검사(설정 시)
                if self.headers.get("Authorization", "") != f"Bearer {token}":
                    return self._send(401, {"ok": False, "error": "unauthorized"})
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b"{}"
            try:
                body = json.loads(raw or b"{}")
            except ValueError:
                return self._send(400, {"ok": False, "error": "bad json"})

            path = self.path.rstrip("/") or "/"
            try:
                if path == "/save":
                    sm.save(body["name"])
                    return self._send(200, {"ok": True, "snapshots": sm.list()})
                if path == "/revert":
                    sm.revert_to(body["name"])         # revertToSnapshot + 로컬 gui 재개
                    return self._send(200, {"ok": True})
                if path == "/delete":
                    sm.delete(body["name"])
                    return self._send(200, {"ok": True})
                if path == "/list":
                    return self._send(200, {"ok": True, "snapshots": sm.list()})
                if path in ("/status", "/"):
                    return self._send(200, {"ok": True, "agent": "snapshot", "vmx": sm.vmx})
                return self._send(404, {"ok": False, "error": f"unknown path {path}"})
            except KeyError as e:                      # 필수 필드 누락
                return self._send(400, {"ok": False, "error": f"missing field {e}"})
            except SnapshotError as e:                 # vmrun 실패 → ok:false(오케스트레이터가 처리)
                return self._send(200, {"ok": False, "error": str(e)})
            except Exception as e:                     # noqa: BLE001 — 기타 오류도 ok:false로
                return self._send(200, {"ok": False, "error": f"{type(e).__name__}: {e}"})

    return Handler


def build_manager(vmx: str, vmrun: str) -> VmrunSnapshotManager:
    """로컬 vmrun으로 도는 스냅샷 매니저. 로컬 데스크톱 세션이라 gui 모드로 재개(start)."""
    return VmrunSnapshotManager(vmx, runner=local_runner(), vmrun=vmrun, start_gui=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="호스트 스냅샷 에이전트(로컬 vmrun)")
    ap.add_argument("--vmx", required=True, help="VM B .vmx 전체 경로")
    ap.add_argument("--vmrun", default="vmrun", help="vmrun.exe 전체 경로(PATH에 없으면 필수)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8010)
    ap.add_argument("--token", default="", help="공유 토큰(설정 시 Authorization: Bearer 검사)")
    args = ap.parse_args(argv)

    sm = build_manager(args.vmx, args.vmrun)
    httpd = HTTPServer((args.host, args.port), make_handler(sm, args.token))
    print(f"[*] 스냅샷 에이전트 {args.host}:{args.port}")
    print(f"    vmx={args.vmx}")
    print(f"    vmrun={args.vmrun}")
    print("    ⚠ 반드시 로그인된 데스크톱 세션에서 실행해야 재개(start)가 동작함.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 종료.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
