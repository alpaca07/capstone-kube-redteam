"""지식 그래프 조회(knowledge/query.py) 스모크 — 자산→KG LLM 바인딩 공급 포함.

Neo4j 없이 fake session(쿼리 패턴으로 분기)으로 로직만 검증.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from knowledge.query import (  # noqa: E402
    cve_facts, cves_for_term, knowledge_for_terms, render_kg_candidates,
    techniques_for_cve)


class FakeSession:
    """knowledge.query 가 쓰는 run(q, **p) 계약을 쿼리 문자열로 분기해 흉내낸다."""
    def __init__(self, *, cve_by_term=None, direct_by_cve=None, bridge_by_cve=None,
                 facts_by_cve=None):
        self.cve_by_term = cve_by_term or {}        # {term_lower: [cve_id]}
        self.direct_by_cve = direct_by_cve or {}    # {cve_id: [row]}
        self.bridge_by_cve = bridge_by_cve or {}    # {cve_id: [row]}
        self.facts_by_cve = facts_by_cve or {}      # {cve_id: [row]}

    def run(self, q, **p):
        if "CONTAINS" in q:                         # cves_for_term
            return [{"id": c} for c in self.cve_by_term.get((p["t"] or "").lower(), [])]
        if "EXPLOITED_BY" in q:                     # techniques_for_cve (direct)
            return self.direct_by_cve.get(p["id"], [])
        if "HAS_ATTACK_PATTERN" in q:               # techniques_for_cve (bridge fallback)
            return self.bridge_by_cve.get(p["id"], [])
        if "CLASSIFIED_AS" in q:                    # cve_facts
            return self.facts_by_cve.get(p["id"], [])
        return []


def _curated(tid, name):
    return {"technique": tid, "name": name, "category": "exploitation_technique", "source": "curated"}


# ───────────── 기존 조회 스모크 ─────────────
def test_techniques_for_cve_direct_wins():
    s = FakeSession(direct_by_cve={"CVE-2021-22205": [_curated("T1190", "Exploit Public-Facing App")]},
                    bridge_by_cve={"CVE-2021-22205": [{"technique": "T9999"}]})
    out = techniques_for_cve(s, "CVE-2021-22205")
    assert [t["technique"] for t in out] == ["T1190"]     # 직접 매핑 있으면 브리지 무시
    assert out[0]["via"] == "direct" and out[0]["confidence"] == 0.95


def test_techniques_for_cve_bridge_fallback():
    s = FakeSession(bridge_by_cve={"CVE-X": [
        {"technique": "T1059", "name": "Cmd", "via_cwe": "CWE-94", "via_capec": "CAPEC-242"}]})
    out = techniques_for_cve(s, "CVE-X")
    assert out and out[0]["via"] == "bridge" and out[0]["confidence"] == 0.40


# ───────────── 자산→KG 느슨 진입 ─────────────
def test_cves_for_term_matches_description():
    s = FakeSession(cve_by_term={"gitlab": ["CVE-2021-22205"]})
    assert cves_for_term(s, "GitLab") == ["CVE-2021-22205"]   # 대소문자 무시
    assert cves_for_term(s, "  ") == []                        # 빈 용어


def test_knowledge_for_terms_aggregates():
    s = FakeSession(
        cve_by_term={"gitlab": ["CVE-2021-22205"]},
        direct_by_cve={"CVE-2021-22205": [_curated("T1190", "Exploit"), _curated("T1059", "Cmd")]})
    kn = knowledge_for_terms(s, ["gitlab"])
    assert kn["by_term"]["gitlab"] == ["CVE-2021-22205"]
    techs = {a["technique"] for a in kn["aggregate"]}
    assert techs == {"T1190", "T1059"}
    assert kn["aggregate"][0]["terms"] == ["gitlab"]
    assert kn["aggregate"][0]["cves"] == ["CVE-2021-22205"]


def test_knowledge_for_terms_dedup_same_cve_two_terms():
    # 두 용어가 같은 CVE 로 가도 기법·CVE 는 한 번만(terms 엔 둘 다)
    s = FakeSession(
        cve_by_term={"gitlab": ["CVE-2021-22205"], "exiftool": ["CVE-2021-22205"]},
        direct_by_cve={"CVE-2021-22205": [_curated("T1190", "Exploit")]})
    kn = knowledge_for_terms(s, ["gitlab", "exiftool"])
    a = kn["aggregate"][0]
    assert a["cves"] == ["CVE-2021-22205"]            # 중복 안 쌓임
    assert set(a["terms"]) == {"gitlab", "exiftool"}  # 매칭 용어는 둘 다


def test_knowledge_for_terms_empty_and_blank():
    s = FakeSession()
    assert knowledge_for_terms(s, [])["aggregate"] == []
    assert knowledge_for_terms(s, ["", "  "])["aggregate"] == []


def test_render_kg_candidates():
    kn = {"aggregate": [{"technique": "T1190", "name": "Exploit", "confidence": 0.95,
                         "cves": ["CVE-2021-22205"], "terms": ["gitlab"]}]}
    txt = render_kg_candidates(kn)
    assert "T1190" in txt and "gitlab" in txt and "CVE-2021-22205" in txt
    assert render_kg_candidates({"aggregate": []}) == ""   # 히트 없으면 빈 블록
    assert render_kg_candidates({}) == ""


# ───────────────────── 자체 러너 ─────────────────────
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
    print("── 지식 그래프 조회 스모크 ──")
    sys.exit(_run())
