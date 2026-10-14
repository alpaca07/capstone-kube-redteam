"""실 어댑터 — vmrun(VMware Workstation)으로 VM B 스냅샷을 제어하는 SnapshotManager 구현.

호스트가 ESXi/vCenter가 아니라 Windows + VMware Workstation이라 govc/pyvmomi를 못 쓴다.
Workstation은 호스트에서 `vmrun` CLI로 스냅샷을 제어하는데, vmrun은 '호스트에서' 돌아야
하므로 VM C(오케스트레이터)는 호스트로 SSH해 vmrun을 호출한다.

govc_snapshot.py와 같은 설계: vmrun 명령 '생성·파싱'(순수) + '실제 실행'(runner 주입) 분리.
  - 실전(VM C): ssh_runner — argv를 Windows cmd가 파싱하게 따옴표 처리해 ssh로 호스트에서 실행.
  - 호스트에서 직접 실행 시: local_runner — 로컬 subprocess.
  - 테스트: fake runner — 명령 생성·파싱만 검증(실제 vmrun·ssh 불필요).

전제: baseline 스냅샷은 '켠 상태(메모리 포함) 라이브 스냅샷'이어야 revert가 즉시 ready 클러스터로
복원된다. (전원 off 상태로 찍었다면 revert 후 vmrun start가 별도로 필요.)
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional, Sequence


@dataclass
class RunResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


# runner: vmrun argv(list) → 실행 결과. 실 구현은 ssh/subprocess, 테스트는 fake.
Runner = Callable[[list[str]], RunResult]


class SnapshotError(RuntimeError):
    """vmrun 명령 실패."""


_VMRUN_TYPE = "ws"   # VMware Workstation (-T ws)

# vmrun이 '일시적 파일 잠금'으로 실패할 때 나오는 문구들(잠깐 뒤 풀리는 경우가 많음 → 재시도).
# 예: revert 직후·다른 vmrun/GUI 접근과 겹칠 때 "The file is already in use".
_LOCK_HINTS = ("already in use", "failed to lock", "cannot open the disk",
               "resource is in use", "locked")


def _is_lock_error(res: "RunResult") -> bool:
    blob = f"{res.stdout}\n{res.stderr}".lower()
    return any(h in blob for h in _LOCK_HINTS)


def _winquote(arg: str) -> str:
    """Windows cmd 용 최소 따옴표 — 공백 있으면 큰따옴표로 감쌈(경로 역슬래시는 그대로)."""
    return f'"{arg}"' if " " in arg else arg


def build_remote_cmd(argv: Sequence[str]) -> str:
    """vmrun argv를 Windows cmd가 파싱할 한 줄 명령 문자열로(공백 인자만 따옴표)."""
    return " ".join(_winquote(a) for a in argv)


def ssh_runner(ssh_target: str, *, ssh: str = "ssh",
               ssh_opts: Sequence[str] = ()) -> Runner:
    """VM C → Windows 호스트 SSH로 vmrun argv를 실행하는 runner.

    argv 예: ['vmrun','-T','ws','snapshot', r'C:\\...\\VM-B.vmx', 'clean-baseline']
    → Windows cmd용 문자열로 합쳐 `ssh <opts> <target> "<문자열>"`을 로컬 subprocess 실행.
    (subprocess는 shell=False라 로컬 셸 개입 없음 — 따옴표는 그대로 원격 cmd에 전달.)
    """
    def _r(argv: list[str]) -> RunResult:
        import subprocess
        full = [ssh, *ssh_opts, ssh_target, build_remote_cmd(argv)]
        p = subprocess.run(full, capture_output=True, text=True)
        return RunResult(p.returncode, p.stdout, p.stderr)
    return _r


def local_runner() -> Runner:
    """호스트에서 오케스트레이터를 직접 돌릴 때 — 로컬 subprocess로 vmrun 실행."""
    def _r(argv: list[str]) -> RunResult:
        import subprocess
        p = subprocess.run(argv, capture_output=True, text=True)
        return RunResult(p.returncode, p.stdout, p.stderr)
    return _r


def parse_snapshot_list(stdout: str) -> list[str]:
    """`vmrun listSnapshots` 출력에서 스냅샷 이름만 추출.

    출력 예:
        Total snapshots: 2
        clean-baseline
        ep1-r1-postattack
    'Total snapshots:' 헤더·빈 줄은 건너뛰고, 중첩 들여쓰기는 strip으로 무시한다.
    전제: 스냅샷 이름에 공백 없음(우리 명명 규칙 clean-baseline·ep{e}-r{r}-postattack 등).
    """
    names: list[str] = []
    for raw in stdout.splitlines():
        s = raw.strip()
        if not s or s.lower().startswith("total snapshots"):
            continue
        names.append(s.split()[0])
    return names


class VmrunSnapshotManager:
    """vmrun 기반 SnapshotManager. 모든 작업은 vmrun이 완료까지 블로킹(원자성 보장)."""

    def __init__(self, vmx_path: str, *, runner: Runner, vmrun: str = "vmrun",
                 lock_retries: int = 5, lock_backoff_sec: float = 3.0,
                 sleeper: Callable[[float], None] = time.sleep) -> None:
        self.vmx = vmx_path          # 호스트의 VM B .vmx 경로
        self.vmrun = vmrun           # 'vmrun' 또는 전체 경로(PATH에 없을 때)
        self.runner = runner
        self.lock_retries = lock_retries        # 파일 잠금 시 총 시도 횟수(초기 1 + 재시도)
        self.lock_backoff = lock_backoff_sec    # 재시도 사이 대기(초)
        self._sleep = sleeper                   # 테스트에서 주입 가능(실제론 time.sleep)

    def _run(self, op: str, *extra: str) -> RunResult:
        argv = [self.vmrun, "-T", _VMRUN_TYPE, op, self.vmx, *extra]
        res = self.runner(argv)
        attempt = 1
        # 'The file is already in use' 같은 일시적 잠금은 잠깐 뒤 풀리므로 몇 번 재시도.
        while res.returncode != 0 and _is_lock_error(res) and attempt < self.lock_retries:
            self._sleep(self.lock_backoff)
            res = self.runner(argv)
            attempt += 1
        if res.returncode != 0:
            raise SnapshotError(
                f"vmrun {op} 실패(rc={res.returncode}): {(res.stderr or res.stdout).strip()}")
        return res

    def save(self, name: str) -> None:
        # vmrun은 동명 스냅샷을 중복 생성함 → 있으면 지우고 새로.
        if name in self.list():
            self._run("deleteSnapshot", name)
        self._run("snapshot", name)

    def revert_to(self, name: str) -> None:
        self._run("revertToSnapshot", name)
        # 라이브(메모리) 스냅샷 revert 후 VM이 멈춰 있을 수 있어 재개(best-effort).
        # 이미 실행 중이면 vmrun이 에러를 내지만 무시(결과에 영향 없음). 실측상 이 start가
        # 공격 턴이 돌 만큼 VM B를 정상 가동시켰다 → 무조건 호출 유지.
        self.runner([self.vmrun, "-T", _VMRUN_TYPE, "start", self.vmx, "nogui"])

    def delete(self, name: str) -> None:
        if name in self.list():                # 없으면 조용히 무시(정리 best-effort)
            self._run("deleteSnapshot", name)

    def list(self) -> list[str]:
        return parse_snapshot_list(self._run("listSnapshots").stdout)


__all__ = ["RunResult", "Runner", "SnapshotError", "ssh_runner", "local_runner",
           "build_remote_cmd", "parse_snapshot_list", "VmrunSnapshotManager"]
