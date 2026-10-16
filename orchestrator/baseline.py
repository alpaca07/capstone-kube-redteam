"""②' 클러스터 베이스라인 매니저 — VM 스냅샷 대신 k8s 네이티브로 아레나를 리셋한다.

왜 스냅샷을 안 쓰나(A2): 돌아가는 VM을 vmrun 으로 스냅샷/revert 하면 VMware 가 VM 전체를
'stun'(freeze)해 메모리를 디스크에 쓰는데, 이게 수십 초~수 분 걸리며 그동안 SSH·k3s 연결이
끊긴다. 깨어나도 k3s 의 exec/API 스트림이 망가진 채라 kubectl 이 10~120초로 느려지거나 멈춘다
(§8 #1). 재시작/재부팅만 복구됨. → 상태 리셋을 'VM 레벨'이 아니라 'k8s 리소스 레벨'로 하면
stun 자체가 없어진다. 공격이 전부 읽기(파괴 아님)라 선언적 리셋으로 '완전'하다.

리셋이 되돌려야 하는 것 = 방어자 패치 어휘 3종(정확히 이것만):
  - add_networkpolicy  → 타깃 ns 의 NetworkPolicy 전부 삭제(베이스라인엔 NetworkPolicy 0개).
  - restrict_rbac      → 삭제된 과권한 ClusterRoleBinding 복구(killchain 매니페스트 재적용, 멱등).
  - delete_pod         → 발판/서비스 파드는 Deployment 관리라 자동 재생성 + rollout restart 로
                         파일시스템까지 초기화.
공격자는 상태를 안 바꾼다(발판 안에서 읽기/psql SELECT) → 리셋 대상 아님(발판 rollout 로 위생만).

심판(VM C)이 아레나를 리셋한다 — cfg.target.kubeconfig(설계상 'VC god-view용')로 kubectl 직접
실행(govc_snapshot 의 subprocess 패턴과 동일, runner 주입 가능 → 네트워크·클러스터 없이 테스트).

클린 지문(reset 후 매번 검증): 타깃 ns NetworkPolicy 0개 + 과권한 바인딩 존재 + 핵심 Deployment
Ready. 하나라도 어긋나면 ResetError → 오염된 채로 다음 라운드가 돌지 않게 한다.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional, Protocol, runtime_checkable


@runtime_checkable
class ClusterReset(Protocol):
    """verify·시퀀서가 의존하는 최소 계약 — 아레나를 클린 취약 베이스라인으로 되돌린다."""

    def reset_to_clean(self) -> None:
        ...


@dataclass
class RunResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


Runner = Callable[[list[str]], RunResult]


class ResetError(RuntimeError):
    """베이스라인 리셋/지문 검증 실패 — 오염 방지를 위해 라운드 중단 신호."""


def kubectl_runner(kubeconfig: Optional[str] = None,
                   kubectl: str = "kubectl") -> Runner:
    """기본 runner — subprocess 로 kubectl 실행(KUBECONFIG 주입). 지연 import."""
    def _r(args: list[str]) -> RunResult:
        import os
        import subprocess
        env = dict(os.environ)
        if kubeconfig:
            env["KUBECONFIG"] = kubeconfig
        p = subprocess.run([kubectl, *args], capture_output=True, text=True, env=env)
        return RunResult(p.returncode, p.stdout, p.stderr)
    return _r


# 베이스라인 기본값(우리 킬체인 환경). 설정에서 덮어쓸 수 있게 생성자 인자로도 받는다.
_DEFAULT_TARGET_NS = ("frontend", "backend", "database", "internal")
_DEFAULT_MANIFESTS = ("k8s/killchain",)          # 삭제된 과권한 바인딩·발판 복구(멱등 apply)
_DEFAULT_FOOTHOLD = ("frontend", "attacker-foothold")   # (ns, deployment)
_DEFAULT_OVERPERM_BINDING = "admin-tools-binding"       # restrict_rbac 가 지우는 과권한 바인딩
_DEFAULT_READY_DEPLOYS = (("frontend", "attacker-foothold"),)  # rollout status 로 대기할 Deployment


class BaselineManager:
    """k8s 네이티브 아레나 리셋. SnapshotManager 자리에 끼우되(에피소드 init의 revert_to 호환),
    실제 동작은 reset_to_clean()."""

    def __init__(self, *, runner: Runner,
                 target_namespaces: tuple[str, ...] = _DEFAULT_TARGET_NS,
                 manifest_paths: tuple[str, ...] = _DEFAULT_MANIFESTS,
                 foothold: tuple[str, str] = _DEFAULT_FOOTHOLD,
                 overperm_binding: str = _DEFAULT_OVERPERM_BINDING,
                 ready_deploys: tuple[tuple[str, str], ...] = _DEFAULT_READY_DEPLOYS,
                 baseline_name: str = "clean-baseline",
                 rollout_timeout_sec: int = 120) -> None:
        self.runner = runner
        self.target_namespaces = target_namespaces
        self.manifest_paths = manifest_paths
        self.foothold_ns, self.foothold_deploy = foothold
        self.overperm_binding = overperm_binding
        self.ready_deploys = ready_deploys
        self.baseline_name = baseline_name
        self.rollout_timeout_sec = rollout_timeout_sec

    # ───────────── 내부 실행 헬퍼 ─────────────
    def _run(self, args: list[str], *, check: bool = True) -> RunResult:
        r = self.runner(args)
        if check and r.returncode != 0:
            raise ResetError(f"kubectl {' '.join(args)} 실패(rc={r.returncode}): "
                             f"{(r.stderr or r.stdout).strip()[:300]}")
        return r

    # ───────────── 핵심: 클린 베이스라인으로 리셋 ─────────────
    def reset_to_clean(self) -> None:
        """방어자 변경을 역산해 취약 베이스라인으로 되돌리고, 클린 지문을 검증한다."""
        # 1. 방어자 추가 NetworkPolicy 제거(add_networkpolicy 역산) — 없어도 에러 안 나게.
        for ns in self.target_namespaces:
            self._run(["delete", "networkpolicy", "--all", "-n", ns,
                       "--ignore-not-found=true"])
        # 2. killchain 매니페스트 재적용(restrict_rbac 로 삭제된 과권한 바인딩·발판 복구). apply=멱등.
        for path in self.manifest_paths:
            self._run(["apply", "-f", path])
        # 3. 발판 파드 초기화(delete_pod 흔적·파일시스템 리셋). Deployment 아니면 무시(check=False).
        self._run(["rollout", "restart",
                   f"deployment/{self.foothold_deploy}", "-n", self.foothold_ns],
                  check=False)
        # 4. 핵심 Deployment 준비 대기(rollout status 가 Ready 까지 블로킹).
        for ns, dep in self.ready_deploys:
            self._run(["rollout", "status", f"deployment/{dep}", "-n", ns,
                       f"--timeout={self.rollout_timeout_sec}s"], check=False)
        # 5. 클린 지문 검증.
        self._assert_clean_fingerprint()

    def _assert_clean_fingerprint(self) -> None:
        """리셋이 완전했는지 — 타깃 ns NetworkPolicy 0개 + 과권한 바인딩 존재. 어긋나면 ResetError."""
        leftover: list[str] = []
        for ns in self.target_namespaces:
            r = self._run(["get", "networkpolicy", "-n", ns, "-o", "name"])
            names = [ln.strip() for ln in r.stdout.splitlines() if ln.strip()]
            leftover.extend(f"{ns}/{n}" for n in names)
        if leftover:
            raise ResetError(f"리셋 후에도 NetworkPolicy 잔존(취약 베이스라인 아님): {leftover}")
        # 과권한 바인딩이 복구됐나(공격 ② 경로가 열려 있어야 베이스라인) — 없으면 리셋 불완전.
        rb = self._run(["get", "clusterrolebinding", self.overperm_binding,
                        "--ignore-not-found=true", "-o", "name"])
        if self.overperm_binding not in rb.stdout:
            raise ResetError(f"과권한 바인딩 미복구: {self.overperm_binding}")

    # ───────────── SnapshotManager 호환(기존 이음새에 그대로 끼우기) ─────────────
    # verify 는 reset_to_clean() 을 직접 쓰지만, 시퀀서의 에피소드 init(revert_to(baseline))·
    # 정리 호출은 아래 어댑터로 흡수한다. 클린 상태는 하나뿐이라 name 은 무시(안전상 검증).
    def revert_to(self, name: str) -> None:
        self.reset_to_clean()

    def save(self, name: str) -> None:        # A2 엔 '패치후 저장'이 불필요(verify 가 라이브 재생 후 리셋)
        pass

    def delete(self, name: str) -> None:
        pass

    def list(self) -> list[str]:
        return [self.baseline_name]


__all__ = ["RunResult", "Runner", "ResetError", "ClusterReset",
           "kubectl_runner", "BaselineManager"]
