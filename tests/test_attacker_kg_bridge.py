"""자산↔KG 다리(attacker/kg_bridge.py) 스모크 — 용어 추출 + 콜백 렌더.

Neo4j·실 자산그래프 없이 fake(duck typing)로 로직만 검증.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.kg_bridge import (  # noqa: E402
    _tokenize, asset_terms, make_kg_lookup, make_procedure_lookup)


class _A:
    """AssetNode 흉내(asset_terms 가 getattr 로 읽는 필드만)."""
    def __init__(self, name="", kind="", cpe=""):
        self.name, self.kind, self.cpe = name, kind, cpe


class _AG:
    def __init__(self, items):
        self._items = items

    def assets(self, limit=50):
        return self._items[:limit]


class _QSess:
    """knowledge.query 계약(run)을 쿼리 패턴으로 분기하는 fake. Product 경로 우선 반영."""
    def run(self, q, **p):
        if "IDENTIFIED_BY" in q and "EXPLOITED_BY" in q:       # techniques_for_product (direct)
            return ([{"technique": "T1190", "name": "Exploit", "category": "exploitation_technique",
                      "source": "curated", "cves": ["CVE-2021-22205"]}]
                    if "gitlab" in (p.get("t") or "").lower() else [])
        if "IDENTIFIED_BY" in q:                               # techniques_for_product (bridge)
            return []
        if "CONTAINS" in q:                                    # cves_for_term (폴백)
            return [{"id": "CVE-2021-22205"}] if "gitlab" in (p.get("t") or "").lower() else []
        if "EXPLOITED_BY" in q:                                # techniques_for_cve
            return [{"technique": "T1190", "name": "Exploit", "category": "exploitation_technique",
                     "source": "curated"}]
        return []


def test_tokenize_strips_version_and_stopwords():
    assert _tokenize("gitlab 13.10.3") == ["gitlab"]            # 버전 숫자 제외
    assert _tokenize("cpe:2.3:a:gitlab:gitlab") == ["gitlab", "gitlab"]  # cpe/숫자 제거, dedup은 상위
    assert _tokenize("web service") == []                       # 전부 불용어


def test_asset_terms_dedup_and_identified_first():
    ag = _AG([_A(name="webthing", kind="service"),              # 미식별(cpe 없음)
              _A(name="GitLab", cpe="gitlab:gitlab")])          # 식별(cpe 보유)
    terms = asset_terms(ag)
    assert "gitlab" in terms and "webthing" in terms
    assert terms.index("gitlab") < terms.index("webthing")     # 식별 자산 용어 먼저
    assert terms.count("gitlab") == 1                            # 중복 제거


def test_asset_terms_none_and_empty():
    assert asset_terms(None) == []
    assert asset_terms(_AG([])) == []


def test_make_kg_lookup_renders_candidates():
    lookup = make_kg_lookup(_QSess())
    block = lookup(_AG([_A(name="gitlab", cpe="gitlab:gitlab")]))
    assert "T1190" in block and "gitlab" in block               # 후보 기법 + 매칭 용어


def test_make_kg_lookup_no_terms_returns_empty():
    # 용어가 안 나오면 session 접근 없이 빈 블록
    lookup = make_kg_lookup(_QSess())
    assert lookup(_AG([])) == ""
    assert lookup(_AG([_A(name="web", kind="service")])) == ""  # 전부 불용어 → 빈 용어


def test_make_procedure_lookup():
    """기법 → 핵심층 절차 블록(2차 워커용). REALIZED_BY 질의를 fake 로 흉내."""
    class _PS:
        def run(self, q, **p):
            if "REALIZED_BY" in q:
                return [{"procedure": "PROC-x", "name": "n", "description": "do X", "env": "struts2",
                         "cve": None, "cwe": None, "status": None, "preconditions": [],
                         "expected_results": [{"id": "ER", "name": "host file read", "kind": "crown"}]}]
            return []
    lookup = make_procedure_lookup(_PS())
    block = lookup("T1190")
    assert "PROC-x [struts2]: do X" in block and "goal: host file read" in block
    assert lookup("") == ""                    # 기법 없으면 조회 안 하고 빈 블록


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
    print("── 자산↔KG 다리 스모크 ──")
    sys.exit(_run())
