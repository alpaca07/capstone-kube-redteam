"""실 어댑터 — 호스트 스냅샷 에이전트에 HTTP로 스냅샷/재개를 위임하는 SnapshotManager.

왜: VMware Workstation에서 vmrun의 스냅샷 명령(revertToSnapshot·snapshot·listSnapshots)은
SSH로 실행되지만, revert 후 VM '재개(start)'는 호스트의 interactive 데스크톱 세션이 필요해
SSH로는 실패한다("Error: There was an error in communication"). 그래서 revert+재개를
'호스트 데스크톱 세션에서 도는 에이전트(host/snapshot_agent.py)'가 로컬 vmrun으로 수행하고,
VM C 오케스트레이터는 그 에이전트를 HTTP로 호출만 한다 — VM A/B 하네스 호출과 같은 패턴.

SnapshotManager Protocol(save/revert_to/delete/list)을 그대로 구현하므로 시퀀서·검증엔진은
변경 없이 끼워 쓴다. transport(네트워크 전송)만 주입 교체하면 네트워크 없이 테스트 가능.

HTTP 계약(에이전트가 구현):
  POST {base}/save   {"name"} → {"ok": true, "snapshots":[...]} | {"ok": false, "error"}
  POST {base}/revert {"name"} → {"ok": true}                    (revertToSnapshot + 로컬 재개)
  POST {base}/delete {"name"} → {"ok": true}                    (없으면 조용히 ok)
  POST {base}/list   {}       → {"ok": true, "snapshots":[...]}
"""
from __future__ import annotations

from typing import Callable, Optional

from .vmrun_snapshot import SnapshotError

# transport: (url, body, timeout_sec) -> response dict
Transport = Callable[[str, dict, float], dict]

_SNAP_TIMEOUT = 1800.0   # save/revert/delete 는 느릴 수 있음(스냅샷 통합 포함) — 넉넉히(30분)
_LIST_TIMEOUT = 60.0


def requests_transport(token: str = "") -> Transport:
    """기본 전송 — requests로 JSON POST. requests는 지연 import(미설치 시 호출 때만 에러)."""
    def _t(url: str, body: dict, timeout: float) -> dict:
        import requests  # 지연 import
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = requests.post(url, json=body, headers=headers, timeout=timeout)
        try:
            return resp.json()                      # 에이전트는 실패도 {"ok":false}로 200에 담음
        except ValueError:
            raise SnapshotError(
                f"스냅샷 에이전트 비정상 응답(rc={resp.status_code}): {resp.text[:200]}")
    return _t


class HttpSnapshotManager:
    """SnapshotManager Protocol 구현 — 모든 작업을 호스트 에이전트에 HTTP 위임.

    모든 메서드는 에이전트 응답을 받을 때까지 블로킹(원자성). 실패({"ok":false})면 SnapshotError.
    """

    def __init__(self, agent_url: str, *, token: str = "",
                 transport: Optional[Transport] = None,
                 snap_timeout: float = _SNAP_TIMEOUT,
                 list_timeout: float = _LIST_TIMEOUT) -> None:
        if not agent_url:
            raise ValueError("snapshot_agent_url 미설정 (method=agent인데 에이전트 URL 없음)")
        self.base = agent_url.rstrip("/")
        self.transport = transport or requests_transport(token)
        self.snap_timeout = snap_timeout
        self.list_timeout = list_timeout

    def _post(self, path: str, body: dict, timeout: float) -> dict:
        data = self.transport(f"{self.base}{path}", body, timeout)
        if not data.get("ok", False):
            raise SnapshotError(f"스냅샷 에이전트 {path} 실패: {data.get('error', '알 수 없음')}")
        return data

    def save(self, name: str) -> None:
        self._post("/save", {"name": name}, self.snap_timeout)

    def revert_to(self, name: str) -> None:
        self._post("/revert", {"name": name}, self.snap_timeout)

    def delete(self, name: str) -> None:
        self._post("/delete", {"name": name}, self.snap_timeout)

    def list(self) -> list[str]:
        data = self._post("/list", {}, self.list_timeout)
        return list(data.get("snapshots", []))


__all__ = ["Transport", "requests_transport", "HttpSnapshotManager"]
