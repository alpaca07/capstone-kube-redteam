"""②' 클러스터 베이스라인 매니저 — VM 스냅샷 대신 k8s 네이티브로 아레나를 리셋한다.

왜 스냅샷을 안 쓰나(A2): 돌아가는 VM을 vmrun 으로 스냅샷/revert 하면 VMware 가 VM 전체를
'stun'(freeze)해 메모리를 디스크에 쓰는데, 이게 수십 초~수 분 걸리며 그동안 SSH·k3s 연결이
끊긴다. 깨어나도 k3s 의 exec/API 스트림이 망가진 채라 kubectl 이 10~120초로 느려지거나 멈춘다
(§8 #1). 재시작/재부팅만 복구됨. → 상태 리셋을 'VM 레벨'이 아니라 'k8s 리소스 레벨'로 하면
stun 자체가 없어진다. 공격이 전부 읽기(파괴 아님)라 선언적 리셋으로 '완전'하다.

리셋이 되돌려야 하는 것 = 방어자 패치 어휘 4종(정확히 이것만):
  - add_networkpolicy     → 타깃 ns 의 NetworkPolicy 전부 삭제(베이스라인엔 NetworkPolicy 0개).
  - restrict_rbac         → 삭제된 과권한 ClusterRoleBinding 복구(killchain 매니페스트 재적용, 멱등).
  - delete_pod            → 발판/서비스 파드는 Deployment 관리라 자동 재생성 + rollout restart 로
                            파일시스템까지 초기화.
  - restrict_pod_security → 방어자가 붙인 PodSecurity enforce 라벨 제거([Wave1], psa_namespaces).
[Wave1] 공격자도 이제 상태를 바꾼다 — T1610 으로 악성 '탈출 파드'를 생성한다. 그래서 리셋이
  공격자 산출물도 지운다: default ns 전 파드 삭제(정상 파드 없음) + created-by=attacker 라벨 파드.
  나머지 공격(발판 안 읽기/psql SELECT)은 여전히 상태 불변 → 발판 rollout 로 위생만.

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
# [Wave2] 네임스페이스 매니페스트 — reset_to_clean() 가 가장 먼저 멱등 apply 로 ns 자체와
#   라벨(app.kubernetes.io/part-of·zone)을 선언 상태로 되돌린다. 과거 PSA 수동 조작 등으로
#   `app.kubernetes.io/part-of=capstone-corp` 나 `zone=<name>` 가 누락되면 corp 네임스페이스
#   간 NetworkPolicy namespaceSelector 가 매칭 실패 → 2-hop corp 체인(dmz→internal→crown) 봉쇄.
#   매니페스트/리소스 부재는 무시(best-effort) — corp 미설치 환경에서도 ShopFlow 리셋은 돈다.
_DEFAULT_NAMESPACE_MANIFESTS = ("k8s/corp/00-namespaces.yaml",)
# [Wave2] ns 라벨 강제 동기화 — kubectl apply 는 기존 리소스의 '사라진 라벨'을 복구하지 못하므로
#   명시 라벨 세트를 `kubectl label --overwrite` 로 2차 보증. yaml 과 의도적 중복 — drift 재발 영구 봉합.
_DEFAULT_NS_LABEL_SYNC = (
    ("corp-ext",      ("app.kubernetes.io/part-of=capstone-corp", "zone=ext")),
    ("corp-dmz",      ("app.kubernetes.io/part-of=capstone-corp", "zone=dmz")),
    ("corp-internal", ("app.kubernetes.io/part-of=capstone-corp", "zone=internal")),
    ("corp-crown",    ("app.kubernetes.io/part-of=capstone-corp", "zone=crown")),
    ("corp-defense",  ("app.kubernetes.io/part-of=capstone-corp", "zone=defense")),
)
_DEFAULT_FOOTHOLD = ("frontend", "attacker-foothold")   # (ns, deployment)
_DEFAULT_OVERPERM_BINDING = "admin-tools-binding"       # restrict_rbac 가 지우는 과권한 바인딩
_DEFAULT_READY_DEPLOYS = (("frontend", "attacker-foothold"),)  # rollout status 로 대기할 Deployment
# [Wave1] restrict_pod_security 가 enforce 라벨을 붙일 수 있는 ns(역산 대상). 공격자 탈출 파드가
#   주로 default 에 뜨므로 default 포함. 앱 ns 는 정상 파드가 baseline 적합이라 라벨 자체는 무해.
_DEFAULT_PSA_NS = ("frontend", "backend", "database", "internal", "default")
# [Wave2] patch_app 역산 — 하드닝된 Deployment·ConfigMap 을 원본(취약) 매니페스트로 되돌린다.
# 각 항목: (매니페스트 경로, 네임스페이스, Deployment 이름). delete+apply 로 ConfigMap data 완전
# 교체(server-side apply 의 field manager 경합 회피). rollout status 로 Ready 까지 대기.
# corp 2종 + ShopFlow 4종 — 방어자의 patch_app 전체 어휘를 자동 복구.
_DEFAULT_PATCH_APP_TARGETS = (
    ("k8s/corp/dmz/50-tomcat.yaml",              "corp-dmz",      "tomcat"),
    ("k8s/corp/internal/42-jenkins.yaml",        "corp-internal", "jenkins"),
    ("k8s/services/backend/21-catalog-api.yaml", "backend",       "catalog-api"),
    ("k8s/services/backend/22-order-api.yaml",   "backend",       "order-api"),
    ("k8s/services/backend/23-auth-service.yaml","backend",       "auth-service"),
    ("k8s/services/internal/41-admin-dashboard.yaml", "internal", "admin-dashboard"),
)


class BaselineManager:
    """k8s 네이티브 아레나 리셋. SnapshotManager 자리에 끼우되(회차 init의 revert_to 호환),
    실제 동작은 reset_to_clean()."""

    def __init__(self, *, runner: Runner,
                 target_namespaces: tuple[str, ...] = _DEFAULT_TARGET_NS,
                 manifest_paths: tuple[str, ...] = _DEFAULT_MANIFESTS,
                 foothold: tuple[str, str] = _DEFAULT_FOOTHOLD,
                 overperm_binding: str = _DEFAULT_OVERPERM_BINDING,
                 ready_deploys: tuple[tuple[str, str], ...] = _DEFAULT_READY_DEPLOYS,
                 psa_namespaces: tuple[str, ...] = _DEFAULT_PSA_NS,
                 patch_app_targets: tuple[tuple[str, str, str], ...] = _DEFAULT_PATCH_APP_TARGETS,
                 namespace_manifests: tuple[str, ...] = _DEFAULT_NAMESPACE_MANIFESTS,
                 ns_label_sync: tuple[tuple[str, tuple[str, ...]], ...] = _DEFAULT_NS_LABEL_SYNC,
                 baseline_name: str = "clean-baseline",
                 rollout_timeout_sec: int = 120,
                 attacker_memory_reset: Optional[Callable[[], None]] = None) -> None:
        self.runner = runner
        self.target_namespaces = target_namespaces
        self.manifest_paths = manifest_paths
        self.foothold_ns, self.foothold_deploy = foothold
        self.overperm_binding = overperm_binding
        self.ready_deploys = ready_deploys
        self.psa_namespaces = psa_namespaces
        self.patch_app_targets = patch_app_targets
        self.namespace_manifests = namespace_manifests   # [Wave2] 네임스페이스 매니페스트 재적용 대상
        self.ns_label_sync = ns_label_sync               # [Wave2] 라벨 강제 동기화 (ns, (라벨키=값, …))
        self.baseline_name = baseline_name
        self.rollout_timeout_sec = rollout_timeout_sec
        self.attacker_memory_reset = attacker_memory_reset   # [Wave2] 공격자 외부 저장소(Neo4j 등)
        #   라운드 간 지식 리셋 콜백 — 없으면 skip(옵션). orchestrator/main.py 에서 config 보고 주입.

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
        # 0. [Wave2] 네임스페이스 매니페스트 멱등 apply — ns 존재·라벨 선언 상태로 1차 복구.
        #    kubectl apply 는 이미 존재하는 ns 에 '빠진 라벨 추가' 는 하지만, '관리 외 라벨 삭제' 는
        #    안 함(merge). 과거 PSA 수동 조작으로 app.kubernetes.io/part-of·zone 이 날아간 ns 에서
        #    이 단계만으로는 완전 복구 보장이 안 돼서 다음 0.5 단계와 함께 쓴다.
        for path in self.namespace_manifests:
            self._run(["apply", "-f", path], check=False)
        # 0.5. [Wave2] ns 라벨 강제 동기화 — kubectl apply 로 보장 안 되는 drift 2차 복구.
        #    corp 네임스페이스 간 NetworkPolicy namespaceSelector(zone=dmz/internal/crown·
        #    app.kubernetes.io/part-of=capstone-corp)가 이 라벨에 의존 — drift 되면 2-hop corp
        #    체인(dmz→internal→crown)이 봉쇄돼 공격자가 crown-read wrapper 를 쳐도 upstream
        #    connect refused 로 실패. 없는 ns 는 silent skip(best-effort).
        for ns, labels in self.ns_label_sync:
            self._run(["label", "namespace", ns, *labels, "--overwrite"], check=False)
        # 1. 방어자 추가 NetworkPolicy 제거(add_networkpolicy 역산) — 없어도 에러 안 나게.
        for ns in self.target_namespaces:
            self._run(["delete", "networkpolicy", "--all", "-n", ns,
                       "--ignore-not-found=true"])
        # 1.4 [Wave1] 공격자 생성 파드 제거(T1610 악성 '탈출 파드'). default ns 전삭제(정상 파드
        #     없음) + created-by=attacker 라벨 파드 전 ns. 멱등(ignore-not-found), best-effort.
        self._run(["delete", "pod", "--all", "-n", "default",
                   "--ignore-not-found=true"], check=False)
        self._run(["delete", "pod", "-l", "app.kubernetes.io/created-by=attacker",
                   "--all-namespaces", "--ignore-not-found=true"], check=False)
        # 1.5 [Wave1] PodSecurity enforce 라벨 역산(restrict_pod_security 되돌리기). 라벨이 없으면
        #     kubectl 이 에러를 내므로 check=False(best-effort) — 클린 베이스라인엔 라벨이 없다.
        for ns in self.psa_namespaces:
            self._run(["label", "namespace", ns,
                       "pod-security.kubernetes.io/enforce-",
                       "pod-security.kubernetes.io/enforce-version-"], check=False)
        # 2. killchain 매니페스트 재적용(restrict_rbac 로 삭제된 과권한 바인딩·발판 복구). apply=멱등.
        for path in self.manifest_paths:
            self._run(["apply", "-f", path])
        # 2.5 [Wave2] patch_app 역산 — 하드닝된 Deployment·ConfigMap 을 원본 매니페스트로 되돌린다.
        #   방어자가 patch_app 으로 교체한 Deployment·ConfigMap 은 baseline revert 어휘 4종으로는
        #   복구되지 않는다(그건 NetworkPolicy·RBAC·Pod·PSA 만 커버). 이 단계가 5번째 어휘.
        #   delete+apply 로 ConfigMap data 완전 교체(server-side apply 의 field manager 경합 회피).
        #   매니페스트/리소스 부재는 무시(best-effort) — corp 미설치 환경에서도 ShopFlow 리셋은 돈다.
        for path, ns, dep in self.patch_app_targets:
            self._run(["delete", "-f", path, "--ignore-not-found=true"], check=False)
            self._run(["apply", "-f", path], check=False)
        # 2.6 [Wave2] patch_app 재적용 후 각 Deployment rollout Ready 대기(ConfigMap 변경 반영 보장).
        for path, ns, dep in self.patch_app_targets:
            self._run(["rollout", "status", f"deployment/{dep}", "-n", ns,
                       f"--timeout={self.rollout_timeout_sec}s"], check=False)
        # 2.7 [Wave2] 공격자 기억 오염 리셋 — 외부 저장소(Neo4j 등)에 남은 라운드 간 지식 삭제.
        #   재시작만으로 안 지워지는 공격자 영구 저장소를 선택적으로 비운다. 실패해도 리셋 전체는
        #   진행(best-effort) — 공격자가 오염된 기억으로 시작해도 공진화는 돌긴 돈다, 측정만 흐려짐.
        if self.attacker_memory_reset is not None:
            try:
                self.attacker_memory_reset()
            except Exception:  # noqa: BLE001 — 외부 저장소 장애가 리셋 전체를 막지 않음
                pass
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
    # verify 는 reset_to_clean() 을 직접 쓰지만, 시퀀서의 회차 init(revert_to(baseline))·
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
