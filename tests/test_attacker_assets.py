"""자산 그래프(인메모리) 테스트 — 추가·name dedup·CPE 승격·계층·조회·동시성.

    python3 tests/test_attacker_assets.py
"""
from __future__ import annotations

import sys
import threading
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.assets import merge_asset_fields, AssetNode  # noqa: E402
from attacker.assets_fake import InMemoryAssetGraph  # noqa: E402


# ── 추가 + 기본 조회 ──
def test_add_and_get():
    g = InMemoryAssetGraph(episode=1)
    a = g.add_asset("service", "postgres.database.svc", attrs={"port": 5432})
    n = g.get_asset(a)
    assert n.kind == "service" and n.name == "postgres.database.svc"
    assert n.attrs["port"] == 5432 and n.episode == 1
    assert n.identified is False          # CPE 없음 → 미식별


# ── name dedup: 같은 자산 두 번 관측 → 노드 하나 ──
def test_dedup_by_name_merges():
    g = InMemoryAssetGraph()
    a1 = g.add_asset("service", "pg", confidence="inferred")
    a2 = g.add_asset("service", "pg", attrs={"port": 5432}, confidence="observed")
    assert a1 == a2                        # 같은 노드
    assert len(g.assets()) == 1
    n = g.get_asset(a1)
    assert n.attrs["port"] == 5432         # attrs 합쳐짐
    assert n.confidence == "observed"      # 더 센 신뢰값


# ── CPE 승격: 처음엔 미식별, 나중 관측에서 CPE 붙으면 식별로 ──
def test_cpe_promotion():
    g = InMemoryAssetGraph()
    a = g.add_asset("service", "wiki")     # CPE 없음
    assert g.get_asset(a).identified is False
    g.add_asset("service", "wiki", cpe="cpe:2.3:a:mediawiki:mediawiki:1.39")
    n = g.get_asset(a)
    assert n.identified is True and "mediawiki" in n.cpe
    # 이미 CPE 있으면 다른 CPE로 안 덮음
    g.add_asset("service", "wiki", cpe="cpe:2.3:a:other:x")
    assert "mediawiki" in g.get_asset(a).cpe


# ── 계층: parent로 CONTAINS 엣지 ──
def test_contains_hierarchy():
    g = InMemoryAssetGraph()
    host = g.add_asset("host", "10.0.0.5")
    svc = g.add_asset("service", "admin-dashboard", parent=host)
    ep = g.add_asset("endpoint", "/secret", parent=svc)
    assert {c.id for c in g.children(host)} == {svc}
    assert {c.id for c in g.children(svc)} == {ep}


# ── find_by_name: 앵커 해소용 ──
def test_find_by_name():
    g = InMemoryAssetGraph()
    a = g.add_asset("service", "postgres.database.svc")
    assert g.find_by_name("postgres.database.svc").id == a
    assert g.find_by_name("없는거") is None


# ── find_by_cpe: KG 조인용(빈 CPE는 매칭 안 함) ──
def test_find_by_cpe():
    g = InMemoryAssetGraph()
    g.add_asset("service", "a", cpe="cpe:x")
    g.add_asset("service", "b", cpe="cpe:x")
    g.add_asset("service", "c")            # CPE 없음
    assert len(g.find_by_cpe("cpe:x")) == 2
    assert g.find_by_cpe("") == []         # 빈 CPE → 매칭 안 함


# ── unidentified: CPE 없는 = 정찰 필요 후보 ──
def test_unidentified():
    g = InMemoryAssetGraph()
    g.add_asset("service", "known", cpe="cpe:x")
    g.add_asset("service", "unknown1")
    g.add_asset("service", "unknown2")
    names = {n.name for n in g.unidentified()}
    assert names == {"unknown1", "unknown2"}


# ── 병합 규칙(순수) ──
def test_merge_asset_fields_rule():
    n = AssetNode(id=1, kind="", name="x", cpe="", confidence="inferred", attrs={"a": 1})
    merge_asset_fields(n, kind="service", cpe="cpe:y", confidence="observed", attrs={"b": 2})
    assert n.kind == "service" and n.cpe == "cpe:y"
    assert n.confidence == "observed" and n.attrs == {"a": 1, "b": 2}


# ── 반환은 사본(바깥 변이가 저장소 안 건드림) ──
def test_returns_copies():
    g = InMemoryAssetGraph()
    a = g.add_asset("service", "x", attrs={"p": 1})
    n = g.get_asset(a)
    n.attrs["p"] = 999
    n.cpe = "hacked"
    assert g.get_asset(a).attrs["p"] == 1 and g.get_asset(a).cpe == ""


# ── 동시성: 여러 워커가 같은 자산 관측 → 노드 하나, 중복 없음 ──
def test_concurrent_dedup():
    g = InMemoryAssetGraph()
    start = threading.Event()

    def observe():
        start.wait()
        for k in range(20):
            g.add_asset("service", f"svc{k%5}", attrs={"seen": True})

    threads = [threading.Thread(target=observe) for _ in range(6)]
    for t in threads:
        t.start()
    start.set()
    for t in threads:
        t.join()
    # svc0..svc4 = 5개만(여러 번 관측돼도 dedup)
    assert len(g.assets()) == 5


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
    print("── 자산 그래프 테스트 ──")
    sys.exit(_run())
