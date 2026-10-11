"""실 어댑터 — govc(CLI)로 VM B 스냅샷을 제어하는 SnapshotManager 구현.

Protocol(snapshot.py) 뒤에 끼우는 실제 층. 설계 핵심: govc 명령 '생성·결과 파싱'의 순수
로직과 '실제 subprocess 실행'을 분리한다. runner(주입 가능)만 교체하면 govc 없이 명령
문자열과 파싱을 테스트할 수 있고, 실전에선 subprocess로 govc를 돌린다.

govc는 각 작업을 vCenter task 완료까지 대기(동기) → '블로킹' 요건 충족(원자성).
접속 정보는 GOVC_URL/GOVC_USERNAME/GOVC_PASSWORD/GOVC_INSECURE 환경변수(govc_env로 주입 가능).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional


@dataclass
class RunResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


Runner = Callable[[list[str]], RunResult]


class SnapshotError(RuntimeError):
    """govc 명령 실패."""


def subprocess_runner(govc_env: Optional[dict[str, str]] = None) -> Runner:
    """기본 runner — subprocess로 실행(환경변수에 GOVC_* 병합). 지연 import."""
    def _r(args: list[str]) -> RunResult:
        import os
        import subprocess
        env = dict(os.environ)
        if govc_env:
            env.update(govc_env)
        p = subprocess.run(args, capture_output=True, text=True, env=env)
        return RunResult(p.returncode, p.stdout, p.stderr)
    return _r


def parse_snapshot_tree(stdout: str) -> list[str]:
    """`govc snapshot.tree` 출력에서 스냅샷 이름만 추출(들여쓰기·현재마커 무시).

    전제: 스냅샷 이름에 공백 없음(우리 명명 규칙 ep{e}-r{r}-postattack 등).
    """
    names: list[str] = []
    for raw in stdout.splitlines():
        s = raw.strip()
        if not s:
            continue
        names.append(s.split()[0])
    return names


class GovcSnapshotManager:
    """govc 기반 SnapshotManager. 모든 작업은 govc가 task 완료까지 대기."""

    def __init__(self, vm_name: str, *, runner: Optional[Runner] = None,
                 govc_env: Optional[dict[str, str]] = None) -> None:
        self.vm = vm_name
        self.runner = runner or subprocess_runner(govc_env)

    def _run(self, *args: str) -> RunResult:
        res = self.runner(["govc", *args])
        if res.returncode != 0:
            raise SnapshotError(
                f"govc {' '.join(args)} 실패(rc={res.returncode}): {res.stderr.strip()}")
        return res

    def save(self, name: str) -> None:
        # govc는 동명 덮어쓰기가 없음 → 있으면 지우고 새로 생성.
        if name in self.list():
            self._run("snapshot.remove", "-vm", self.vm, name)
        self._run("snapshot.create", "-vm", self.vm, name)

    def revert_to(self, name: str) -> None:
        self._run("snapshot.revert", "-vm", self.vm, name)

    def delete(self, name: str) -> None:
        if name in self.list():                # 없으면 조용히 무시(정리 best-effort)
            self._run("snapshot.remove", "-vm", self.vm, name)

    def list(self) -> list[str]:
        return parse_snapshot_tree(self._run("snapshot.tree", "-vm", self.vm).stdout)


__all__ = ["RunResult", "Runner", "SnapshotError", "subprocess_runner",
           "parse_snapshot_tree", "GovcSnapshotManager"]
