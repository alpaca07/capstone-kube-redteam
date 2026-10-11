"""kubectl 클러스터 어댑터 테스트 — 실제 kubectl 없이 명령 생성·파싱만 fake runner로.

    python3 tests/test_defender_kubectl.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from defender.kubectl_cluster import KubectlCluster, RunResult  # noqa: E402


class _FakeRunner:
    def __init__(self, result=None, by_sub=None):
        self.calls = []                       # (args, stdin)
        self.result = result or RunResult(0, "", "")
        self.by_sub = by_sub or {}

    def __call__(self, args, stdin=None):
        self.calls.append((args, stdin))
        sub = args[1] if len(args) > 1 else ""
        return self.by_sub.get(sub, self.result)

    def last_args(self):
        return self.calls[-1][0]


def test_apply_builds_command_and_stdin():
    r = _FakeRunner()
    ok = KubectlCluster(runner=r).apply("MANIFEST-YAML")
    assert r.last_args() == ["kubectl", "apply", "-f", "-"]
    assert r.calls[-1][1] == "MANIFEST-YAML"      # stdin
    assert ok.ok


def test_apply_dry_run_flag():
    r = _FakeRunner()
    KubectlCluster(runner=r).apply("m", dry_run=True)
    assert "--dry-run=server" in r.last_args()


def test_delete_builds_command():
    r = _FakeRunner()
    KubectlCluster(runner=r).delete("pod", "web-xyz", "frontend")
    assert r.last_args() == ["kubectl", "delete", "pod", "web-xyz", "--ignore-not-found", "-n", "frontend"]


def test_apply_failure_reported():
    r = _FakeRunner(result=RunResult(1, "", "admission denied"))
    res = KubectlCluster(runner=r).apply("m")
    assert not res.ok and "denied" in res.detail


def test_can_i_parses_yes_no():
    assert KubectlCluster(runner=_FakeRunner(RunResult(0, "yes\n"))).can_i(
        "get", "secrets", as_user="system:serviceaccount:internal:admin-sa", all_namespaces=True)
    r = _FakeRunner(RunResult(1, "no\n"))
    assert not KubectlCluster(runner=r).can_i("get", "secrets")
    assert r.last_args()[:4] == ["kubectl", "auth", "can-i", "get"]


def test_get_parses_items():
    items = {"items": [{"metadata": {"name": "np1"}}, {"metadata": {"name": "np2"}}]}
    c = KubectlCluster(runner=_FakeRunner(RunResult(0, json.dumps(items))))
    got = c.get("networkpolicy", namespace="database")
    assert len(got) == 2 and got[0]["metadata"]["name"] == "np1"


def test_get_empty_on_error():
    assert KubectlCluster(runner=_FakeRunner(RunResult(1, "", "not found"))).get("networkpolicy") == []


def test_find_text_scans_and_matches():
    r = _FakeRunner(RunResult(0, "data:\n  url: postgresql://appuser:pw@postgres:5432/db\n"))
    found = KubectlCluster(runner=r).find_text("postgresql://", kinds=["configmap"], namespaces=["internal"])
    assert found


def test_healthcheck_detects_not_ready():
    deploys = {"items": [
        {"metadata": {"name": "web", "namespace": "frontend"},
         "spec": {"replicas": 1}, "status": {"readyReplicas": 1}},
        {"metadata": {"name": "catalog", "namespace": "backend"},
         "spec": {"replicas": 2}, "status": {"readyReplicas": 0}},   # 죽음
        {"metadata": {"name": "noise", "namespace": "kube-system"},
         "spec": {"replicas": 1}, "status": {"readyReplicas": 0}},    # 앱NS 아님 → 무시
    ]}
    res = KubectlCluster(runner=_FakeRunner(RunResult(0, json.dumps(deploys)))).healthcheck()
    assert not res.ok and "backend/catalog" in res.detail


def test_healthcheck_all_ready():
    deploys = {"items": [{"metadata": {"name": "web", "namespace": "frontend"},
                          "spec": {"replicas": 1}, "status": {"readyReplicas": 1}}]}
    assert KubectlCluster(runner=_FakeRunner(RunResult(0, json.dumps(deploys)))).healthcheck().ok


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
    print("── kubectl 클러스터 어댑터 테스트 ──")
    sys.exit(_run())
