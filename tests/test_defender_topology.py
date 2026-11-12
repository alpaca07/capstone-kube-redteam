"""방어 토폴로지 열거 테스트 — ClusterReader.get 으로 재구성한 지도.

    python3 tests/test_defender_topology.py        # 자체 러너
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from defender.topology import enumerate_topology  # noqa: E402


class FakeReader:
    """get(kind, *, namespace="", name="") -> list[dict] 흉내(canned k8s JSON items)."""

    def __init__(self, data: dict) -> None:
        self.data = data            # {(kind, namespace): [items]}

    def get(self, kind, *, namespace="", name=""):
        return list(self.data.get((kind, namespace), []))


def _svc(name, type="ClusterIP", port=80, selector=None):
    return {"metadata": {"name": name},
            "spec": {"type": type, "ports": [{"port": port}], "selector": selector or {"app": name}}}


def _dep(name, replicas=1):
    return {"metadata": {"name": name}, "spec": {"replicas": replicas}}


def _np(name):
    return {"metadata": {"name": name}}


def _ns(name):
    return {"metadata": {"name": name}}


# ───────────── 열거 ─────────────
def test_enumerate_given_namespaces():
    reader = FakeReader({
        ("services", "frontend"): [_svc("web", "NodePort", 30080)],
        ("deployments", "frontend"): [_dep("web", 2)],
        ("networkpolicies", "frontend"): [],
        ("services", "database"): [_svc("postgres", port=5432)],
        ("deployments", "database"): [_dep("postgres")],
        ("networkpolicies", "database"): [_np("restrict-db")],
    })
    topo = enumerate_topology(reader, namespaces=["frontend", "database"])
    assert topo["generated"] is True
    by = {n["name"]: n for n in topo["namespaces"]}
    assert set(by) == {"frontend", "database"}
    assert by["frontend"]["services"][0]["name"] == "web"
    assert by["frontend"]["services"][0]["ports"] == [30080]
    assert by["frontend"]["has_network_policy"] is False      # NP 없음 = 경계 없음
    assert by["database"]["has_network_policy"] is True       # NP 있음 = 경계 생김
    assert by["database"]["network_policies"] == ["restrict-db"]


def test_empty_namespace_skipped():
    reader = FakeReader({
        ("services", "frontend"): [_svc("web")],
        # backend 는 아무것도 없음 → 결과에서 빠짐
    })
    topo = enumerate_topology(reader, namespaces=["frontend", "backend"])
    assert [n["name"] for n in topo["namespaces"]] == ["frontend"]


def test_discovers_namespaces_when_not_given():
    reader = FakeReader({
        ("namespaces", ""): [_ns("frontend"), _ns("kube-system"), _ns("database")],
        ("services", "frontend"): [_svc("web")],
        ("services", "database"): [_svc("postgres", port=5432)],
    })
    topo = enumerate_topology(reader)                         # namespaces=None → 발견 경로
    names = {n["name"] for n in topo["namespaces"]}
    assert names == {"frontend", "database"}                 # kube-system 은 제외(시스템 NS)


def test_reader_without_get():
    class Bare:
        pass
    topo = enumerate_topology(Bare())
    assert topo["generated"] is False and topo["namespaces"] == []


def test_get_raises_is_visibility_gap_not_crash():
    class Boom:
        def get(self, kind, *, namespace="", name=""):
            raise RuntimeError("권한 없음(RBAC)")
    # 조회가 터져도 크래시 아님 — 방어자 가시성 한계로 간주(빈 결과)
    topo = enumerate_topology(Boom(), namespaces=["frontend"])
    assert topo["generated"] is True and topo["namespaces"] == []


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
    print("── 방어 토폴로지 테스트 ──")
    sys.exit(_run())
