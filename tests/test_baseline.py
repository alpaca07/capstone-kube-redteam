"""BaselineManager(A2) 테스트 — k8s 네이티브 리셋의 kubectl 명령 시퀀스·클린 지문을
fake runner 로 검증(실제 클러스터·kubectl 없이).

    python3 tests/test_baseline.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from orchestrator.baseline import (  # noqa: E402
    BaselineManager, ClusterReset, ResetError, RunResult,
)


class FakeRunner:
    """kubectl 명령을 기록하고, 부분일치 규칙으로 결과를 돌려주는 fake(기본=성공·빈 출력)."""

    def __init__(self, rules=None):
        self.cmds: list[list[str]] = []
        self.rules = rules or {}        # {부분문자열: RunResult}

    def __call__(self, args: list[str]) -> RunResult:
        self.cmds.append(args)
        key = " ".join(args)
        for sub, resp in self.rules.items():
            if sub in key:
                return resp
        return RunResult(0, "", "")

    def joined(self) -> list[str]:
        return [" ".join(c) for c in self.cmds]


# 과권한 바인딩이 존재한다고 응답하는 기본 규칙(지문 통과용)
def _binding_present():
    return {"get clusterrolebinding admin-tools-binding":
            RunResult(0, "clusterrolebinding.rbac.authorization.k8s.io/admin-tools-binding\n")}


def _bm(runner):
    return BaselineManager(runner=runner)       # 기본값(frontend/backend/database/internal, k8s/killchain)


# ───────────── 명령 시퀀스 ─────────────
def test_reset_issues_expected_commands():
    r = FakeRunner(rules=_binding_present())
    _bm(r).reset_to_clean()
    cmds = r.joined()
    # 1. 타깃 ns 마다 NetworkPolicy 전삭제(add_networkpolicy 역산)
    for ns in ("frontend", "backend", "database", "internal"):
        assert any(f"delete networkpolicy --all -n {ns}" in c for c in cmds), f"{ns} netpol 삭제 없음"
    # 2. killchain 매니페스트 재적용(restrict_rbac 로 지운 바인딩 복구)
    assert any("apply -f" in c and "killchain" in c for c in cmds), "killchain 재적용 없음"
    # 3. 발판 rollout restart(파일시스템 초기화)
    assert any("rollout restart deployment/attacker-foothold -n frontend" in c for c in cmds)
    # 4. 준비 대기(rollout status)
    assert any("rollout status deployment/attacker-foothold" in c for c in cmds)
    # 5. 클린 지문(netpol 0 조회 + 과권한 바인딩 존재 조회)
    assert any("get networkpolicy -n database -o name" in c for c in cmds)
    assert any("get clusterrolebinding admin-tools-binding" in c for c in cmds)


def test_reset_reverts_pod_security_and_attacker_pods():
    # [Wave1] restrict_pod_security 역산(enforce 라벨 제거) + 공격자 생성 파드(T1610 탈출 파드) 정리.
    r = FakeRunner(rules=_binding_present())
    _bm(r).reset_to_clean()
    cmds = r.joined()
    # default ns 전 파드 삭제(탈출 파드 정리 — default 엔 정상 파드 없음)
    assert any("delete pod --all -n default" in c for c in cmds), "default 파드 정리 없음"
    # created-by=attacker 라벨 파드 전 ns 삭제
    assert any("delete pod -l app.kubernetes.io/created-by=attacker --all-namespaces" in c
               for c in cmds), "공격자 라벨 파드 정리 없음"
    # PodSecurity enforce 라벨 제거(앱 ns + default)
    for ns in ("frontend", "backend", "database", "internal", "default"):
        assert any(f"label namespace {ns} pod-security.kubernetes.io/enforce-" in c
                   for c in cmds), f"{ns} PSA 라벨 제거 없음"


def test_networkpolicy_delete_precedes_fingerprint():
    # 삭제가 지문 검사보다 먼저여야(안 그러면 방어 패치가 지문에 잡혀 매번 ResetError)
    r = FakeRunner(rules=_binding_present())
    _bm(r).reset_to_clean()
    joined = r.joined()
    first_delete = next(i for i, c in enumerate(joined) if "delete networkpolicy" in c)
    first_fp = next(i for i, c in enumerate(joined) if "get networkpolicy" in c)
    assert first_delete < first_fp


# ───────────── 클린 지문 ─────────────
def test_fingerprint_leftover_networkpolicy_raises():
    # 리셋 후에도 타깃 ns 에 NetworkPolicy 가 남으면(취약 베이스라인 아님) ResetError.
    rules = _binding_present()
    rules["get networkpolicy -n database -o name"] = RunResult(
        0, "networkpolicy.networking.k8s.io/restrict-database-ingress\n")
    r = FakeRunner(rules=rules)
    try:
        _bm(r).reset_to_clean()
    except ResetError as e:
        assert "NetworkPolicy 잔존" in str(e)
    else:
        raise AssertionError("잔존 NetworkPolicy 인데 ResetError 안 남")


def test_fingerprint_missing_overperm_binding_raises():
    # 과권한 바인딩이 복구 안 됐으면(공격 ② 경로가 닫힘 = 베이스라인 아님) ResetError.
    r = FakeRunner(rules={"get clusterrolebinding admin-tools-binding": RunResult(0, "")})
    try:
        _bm(r).reset_to_clean()
    except ResetError as e:
        assert "바인딩 미복구" in str(e)
    else:
        raise AssertionError("바인딩 없는데 ResetError 안 남")


def test_kubectl_failure_raises():
    # check=True 명령(delete/apply/get)이 실패하면 ResetError 로 올려 라운드 중단.
    r = FakeRunner(rules={"delete networkpolicy": RunResult(1, "", "the server could not ...")})
    try:
        _bm(r).reset_to_clean()
    except ResetError as e:
        assert "실패" in str(e)
    else:
        raise AssertionError("kubectl rc=1 인데 ResetError 안 남")


# ───────────── 이음새 호환 ─────────────
def test_satisfies_cluster_reset_and_revert_adapter():
    r = FakeRunner(rules=_binding_present())
    bm = _bm(r)
    assert isinstance(bm, ClusterReset)
    before = len(r.cmds)
    bm.revert_to("clean-baseline")        # SnapshotManager 호환 → reset_to_clean 과 동일 동작
    assert len(r.cmds) > before           # 실제 리셋 명령이 나갔다
    assert bm.list() == ["clean-baseline"]


# ───────────── [Wave2] patch_app 역산 ─────────────
def test_reset_reapplies_patch_app_manifests_with_delete_plus_apply():
    """[Wave2] patch_app 역산 — 하드닝된 Deployment·ConfigMap 을 원본 매니페스트로 되돌린다.

    각 매니페스트에 대해 delete -f (--ignore-not-found) + apply -f 가 순서대로 호출되는지
    확인. default 에 corp 2종 + ShopFlow 4종 포함.
    """
    r = FakeRunner(rules=_binding_present())
    _bm(r).reset_to_clean()
    cmds = r.joined()
    expected_targets = [
        ("50-tomcat.yaml",           "corp-dmz",      "tomcat"),
        ("42-jenkins.yaml",          "corp-internal", "jenkins"),
        ("21-catalog-api.yaml",      "backend",       "catalog-api"),
        ("22-order-api.yaml",        "backend",       "order-api"),
        ("23-auth-service.yaml",     "backend",       "auth-service"),
        ("41-admin-dashboard.yaml",  "internal",      "admin-dashboard"),
    ]
    for manifest_tail, ns, dep in expected_targets:
        # delete -f + apply -f 쌍이 매니페스트마다 호출됨
        assert any(f"delete -f" in c and manifest_tail in c and "--ignore-not-found=true" in c
                   for c in cmds), f"{manifest_tail} delete 없음"
        assert any(f"apply -f" in c and manifest_tail in c for c in cmds), \
            f"{manifest_tail} apply 없음"
        # 재적용 후 rollout status 대기
        assert any(f"rollout status deployment/{dep} -n {ns}" in c for c in cmds), \
            f"{ns}/{dep} rollout status 없음"


def test_reset_patch_app_is_best_effort_on_missing_manifest():
    """매니페스트 파일이 없거나 리소스 부재여도 전체 리셋은 계속 진행(check=False best-effort).

    delete·apply 실패가 ResetError 로 올라오지 않아야 한다 — corp 미설치 환경에서도
    ShopFlow 쪽 리셋은 돌아가야 하므로.
    """
    r = FakeRunner(rules={
        **_binding_present(),
        "delete -f": RunResult(1, "", "error: no matches for kind"),
        "apply -f k8s/corp": RunResult(1, "", "error: path not found"),
    })
    _bm(r).reset_to_clean()         # 예외 없어야 통과


def test_reset_can_customize_patch_app_targets():
    """patch_app_targets 를 비우면 2.5·2.6 단계가 전부 skip 돼 명령에 안 나타난다."""
    r = FakeRunner(rules=_binding_present())
    bm = BaselineManager(runner=r, patch_app_targets=())
    bm.reset_to_clean()
    cmds = r.joined()
    assert not any("50-tomcat.yaml" in c for c in cmds), "tomcat 매니페스트 손 안 댔어야"
    assert not any("rollout status deployment/tomcat" in c for c in cmds)


# ───────────── [Wave2] 공격자 기억 오염 리셋 ─────────────
def test_reset_calls_attacker_memory_reset_when_provided():
    """attacker_memory_reset 콜백이 주어지면 reset_to_clean 안에서 정확히 1번 호출된다."""
    r = FakeRunner(rules=_binding_present())
    calls: list[int] = []

    def _memreset() -> None:
        calls.append(1)

    BaselineManager(runner=r, attacker_memory_reset=_memreset).reset_to_clean()
    assert sum(calls) == 1, f"기억 리셋 콜백 호출 횟수 이상: {sum(calls)}"


def test_reset_silently_skips_when_attacker_memory_reset_is_none():
    """attacker_memory_reset=None 이면 그 단계가 skip — 리셋 전체는 정상 진행."""
    r = FakeRunner(rules=_binding_present())
    BaselineManager(runner=r, attacker_memory_reset=None).reset_to_clean()
    # 예외 없이 완료 + killchain 재적용·rollout 은 정상(기본 어휘 보존)
    assert any("apply -f" in c and "killchain" in c for c in r.joined())


def test_reset_silently_ignores_attacker_memory_reset_exception():
    """콜백이 예외 던져도 리셋 전체는 계속 진행(best-effort — Neo4j 장애가 run 전체 막지 않음)."""
    r = FakeRunner(rules=_binding_present())

    def _bad() -> None:
        raise RuntimeError("Neo4j 접속 불가")

    BaselineManager(runner=r, attacker_memory_reset=_bad).reset_to_clean()
    # 예외 안 올라와야 통과 + 후속 단계(발판 rollout) 도 수행
    assert any("rollout restart deployment/attacker-foothold" in c for c in r.joined())


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
    print("── BaselineManager(A2) 테스트 ──")
    sys.exit(_run())
