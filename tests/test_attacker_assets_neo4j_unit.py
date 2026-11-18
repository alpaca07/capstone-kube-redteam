"""Neo4j 자산 어댑터 '순수 부분' 단위 테스트 — 드라이버·DB 불필요.

매핑(props↔AssetNode)·Cypher 상수 핵심(CPE 조인·미식별 필터·리셋 스코프)만. 실 DB 정합은
tests/test_attacker_graph_neo4j_contract.py(자산 파트 포함)가 담당.

    python3 tests/test_attacker_assets_neo4j_unit.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.assets_neo4j import _asset_from_props, _asset_set_props  # noqa: E402
from attacker.assets import AssetNode  # noqa: E402
from attacker import assets_neo4j as an  # noqa: E402


def test_asset_props_roundtrip():
    node = AssetNode(id=5, kind="service", name="pg", cpe="cpe:x",
                     confidence="observed", attrs={"port": 5432}, episode=2)
    p = _asset_set_props(node)
    props = {**p, "id": 5, "episode": 2}
    back = _asset_from_props(props)
    assert back.id == 5 and back.kind == "service" and back.name == "pg"
    assert back.cpe == "cpe:x" and back.confidence == "observed"
    assert back.attrs == {"port": 5432} and back.identified is True


def test_asset_from_props_empty_attrs():
    n = _asset_from_props({"id": 1, "kind": "host", "name": "h", "attrs_json": None})
    assert n.attrs == {} and n.identified is False


def test_set_props_flattens_attrs_to_json():
    p = _asset_set_props(AssetNode(id=1, kind="k", name="n", attrs={"a": [1, 2]}))
    assert json.loads(p["attrs_json"]) == {"a": [1, 2]}


def test_bycpe_cypher_matches_episode_and_cpe():
    assert "Asset {episode:$episode, cpe:$cpe}" in an._BY_CPE


def test_unidentified_cypher_filters_empty_cpe():
    # CPE 빈 문자열 또는 없음 = 미식별
    assert "n.cpe = ''" in an._UNID and "n.cpe IS NULL" in an._UNID


def test_reset_scoped_to_asset_episode():
    assert "n:Asset {episode:$episode}" in an._RESET and "DETACH DELETE" in an._RESET


def test_contains_uses_merge_not_duplicate():
    # CONTAINS는 MERGE라 같은 계층 엣지 중복 안 생김
    assert "MERGE (p)-[:CONTAINS]->(c)" in an._CONTAINS


# ── closure ──
def test_closure_fields_roundtrip():
    node = AssetNode(id=7, kind="endpoint", name="solr/demo", episode=1,
                     closed_at_round=17, closure_reason="schema read; no PII")
    p = _asset_set_props(node)
    # set_props 는 closure 를 포함 안 해도 됨(별도 Cypher 로 세팅) — 복원 경로는 반드시 전달
    full = {**p, "id": 7, "episode": 1,
            "closed_at_round": 17, "closure_reason": "schema read; no PII"}
    back = _asset_from_props(full)
    assert back.is_closed and back.closed_at_round == 17
    assert back.closure_reason == "schema read; no PII"


def test_asset_from_props_no_closure_defaults():
    # 과거 데이터(폐쇄 필드 없음) 는 '안 닫힘' 으로 복원
    n = _asset_from_props({"id": 9, "kind": "k", "name": "n"})
    assert n.is_closed is False and n.closed_at_round == 0


def test_closure_cypher_idempotent_guard():
    # 최초 닫힘만 신뢰 — WHERE coalesce(closed_at_round,0)=0 가드로 재진입 막힘
    assert "coalesce(n.closed_at_round, 0) = 0" in an._CLOSE
    # 결과 반환으로 '실제 닫혔는지' 판정
    assert "RETURN n.id AS id" in an._CLOSE


def test_closures_cypher_orders_by_round_desc():
    assert "ORDER BY n.closed_at_round DESC" in an._CLOSED
    assert "coalesce(n.closed_at_round,0) > 0" in an._CLOSED


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
    print("── Neo4j 자산 어댑터 단위 테스트(순수) ──")
    sys.exit(_run())
