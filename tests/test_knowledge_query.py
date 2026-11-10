"""지식 그래프 조회(knowledge/query.py) 스모크 — Product 경로 + 자산→KG 바인딩 공급.

Neo4j 없이 fake session(쿼리 패턴으로 분기)으로 로직만 검증.
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from knowledge.query import (  # noqa: E402
    cve_facts, cves_for_term, knowledge_for_terms, procedure_for_technique,
    render_kg_candidates, render_procedures, techniques_for_cve, techniques_for_product)


class FakeSession:
    """knowledge.query 가 쓰는 run(q, **p) 계약을 쿼리 문자열로 분기해 흉내낸다.

    분기 순서 주의: Product 경로 쿼리(IDENTIFIED_BY 포함)를 CVE 레벨 분기보다 먼저 본다.
    """
    def __init__(self, *, cve_by_term=None, direct_by_cve=None, bridge_by_cve=None,
                 facts_by_cve=None, product_direct=None, product_bridge=None, procs_by_tech=None):
        self.cve_by_term = cve_by_term or {}        # {term_lower: [cve_id]}
        self.direct_by_cve = direct_by_cve or {}    # {cve_id: [row]}
        self.bridge_by_cve = bridge_by_cve or {}    # {cve_id: [row]}
        self.facts_by_cve = facts_by_cve or {}      # {cve_id: [row]}
        self.product_direct = product_direct or {}  # {term: [row(+cves)]}
        self.product_bridge = product_bridge or {}  # {term: [row(+cves)]}
        self.procs_by_tech = procs_by_tech or {}    # {tech_id: [procedure row]}

    def run(self, q, **p):
        if "IDENTIFIED_BY" in q and "EXPLOITED_BY" in q:        # techniques_for_product (direct)
            return self.product_direct.get(p.get("t"), [])
        if "IDENTIFIED_BY" in q and "HAS_ATTACK_PATTERN" in q:  # techniques_for_product (bridge)
            return self.product_bridge.get(p.get("t"), [])
        if "CONTAINS" in q:                                     # cves_for_term
            return [{"id": c} for c in self.cve_by_term.get((p.get("t") or "").lower(), [])]
        if "EXPLOITED_BY" in q:                                 # techniques_for_cve (direct)
            return self.direct_by_cve.get(p.get("id"), [])
        if "HAS_ATTACK_PATTERN" in q:                           # techniques_for_cve (bridge)
            return self.bridge_by_cve.get(p.get("id"), [])
        if "CLASSIFIED_AS" in q:                                # cve_facts
            return self.facts_by_cve.get(p.get("id"), [])
        if "REALIZED_BY" in q:                                  # procedure_for_technique
            qid = p.get("id") or ""                            # 부모→하위 상속 모사(실그래프 Cypher 와 동일 규칙)
            base = qid.split(".")[0]
            merged = []
            for k, rows in self.procs_by_tech.items():
                if k == qid or (qid == base and k.startswith(base + ".")):
                    merged += rows
            return merged
        return []


def _curated(tid, name):
    return {"technique": tid, "name": name, "category": "exploitation_technique", "source": "curated"}


def _prod(tid, name, cves):
    return {"technique": tid, "name": name, "category": "exploitation_technique",
            "source": "curated", "cves": cves}


# ───────────── CVE 단위 조회(기존) ─────────────
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
    assert out and out[0]["via"] == "bridge" and out[0]["confidence"] == 0.20


# ───────────── Product 경로(신규) ─────────────
def test_techniques_for_product_direct():
    s = FakeSession(product_direct={"gitlab": [_prod("T1190", "Exploit", ["CVE-2021-22205"])]})
    out = techniques_for_product(s, "gitlab")
    assert out[0]["technique"] == "T1190" and out[0]["via"] == "product-direct"
    assert out[0]["cves"] == ["CVE-2021-22205"] and out[0]["confidence"] == 0.95


def test_techniques_for_product_bridge_fallback():
    s = FakeSession(product_bridge={"redis": [{"technique": "T1059", "name": "Cmd", "cves": ["CVE-Y"]}]})
    out = techniques_for_product(s, "redis")
    assert out[0]["via"] == "product-bridge" and out[0]["confidence"] == 0.20
    assert out[0]["cves"] == ["CVE-Y"]


def test_techniques_for_product_none():
    assert techniques_for_product(FakeSession(), "nothing") == []
    assert techniques_for_product(FakeSession(), "  ") == []


# ───────────── 자산→KG 느슨 진입(기존) ─────────────
def test_cves_for_term_matches_description():
    s = FakeSession(cve_by_term={"gitlab": ["CVE-2021-22205"]})
    assert cves_for_term(s, "GitLab") == ["CVE-2021-22205"]   # 대소문자 무시
    assert cves_for_term(s, "  ") == []


# ───────────── knowledge_for_terms: Product 우선 + 폴백 ─────────────
def test_knowledge_for_terms_prefers_product_path():
    # Product 경로 히트 → description(CVE-9999)은 안 씀
    s = FakeSession(product_direct={"gitlab": [_prod("T1190", "Exploit", ["CVE-2021-22205"])]},
                    cve_by_term={"gitlab": ["CVE-9999"]})
    kn = knowledge_for_terms(s, ["gitlab"])
    assert kn["aggregate"][0]["technique"] == "T1190"
    assert kn["aggregate"][0]["via"] == "product-direct"
    assert kn["by_term"]["gitlab"] == ["CVE-2021-22205"]      # Product 경로 cve
    assert "CVE-9999" not in kn["by_term"]["gitlab"]          # description 폴백 안 탐


def test_knowledge_for_terms_description_fallback():
    # Product 히트 없으면 description 검색으로 폴백(기존 동작)
    s = FakeSession(cve_by_term={"gitlab": ["CVE-2021-22205"]},
                    direct_by_cve={"CVE-2021-22205": [_curated("T1190", "Exploit"), _curated("T1059", "Cmd")]})
    kn = knowledge_for_terms(s, ["gitlab"])
    assert kn["by_term"]["gitlab"] == ["CVE-2021-22205"]
    assert {a["technique"] for a in kn["aggregate"]} == {"T1190", "T1059"}
    assert kn["aggregate"][0]["terms"] == ["gitlab"]


def test_knowledge_for_terms_empty_and_blank():
    s = FakeSession()
    assert knowledge_for_terms(s, [])["aggregate"] == []
    assert knowledge_for_terms(s, ["", "  "])["aggregate"] == []


def test_render_kg_candidates():
    kn = {"aggregate": [{"technique": "T1190", "name": "Exploit", "confidence": 0.95,
                         "cves": ["CVE-2021-22205"], "terms": ["gitlab"]}]}
    txt = render_kg_candidates(kn)
    assert "T1190" in txt and "gitlab" in txt and "CVE-2021-22205" in txt
    assert render_kg_candidates({"aggregate": []}) == ""
    assert render_kg_candidates({}) == ""


# ───────────────────── 자체 러너 ─────────────────────
# ───────────── 핵심층 절차 질의(워커용) ─────────────
def test_procedure_for_technique():
    s = FakeSession(procs_by_tech={"T1059": [{
        "procedure": "PROC-postgres-copy-program", "name": "COPY FROM PROGRAM", "description": "DB 서버 명령실행",
        "env": "postgres", "cve": "CVE-2019-9193", "cwe": None, "status": "AUTHORED",
        "preconditions": [{"name": "슈퍼유저 권한", "description": "d",
                           "config_key": "copy_program_enabled", "expected_value": "true"},
                          {"name": None, "description": None, "config_key": None, "expected_value": None}],
        "expected_results": [{"id": "ER-crown", "name": "민감 read", "kind": "crown"},
                             {"id": None, "name": None, "kind": None}]}]})
    out = procedure_for_technique(s, "T1059")
    assert len(out) == 1
    p = out[0]
    assert p["procedure"] == "PROC-postgres-copy-program" and p["env"] == "postgres"
    assert len(p["preconditions"]) == 1 and p["preconditions"][0]["config_key"] == "copy_program_enabled"  # null 제거
    assert len(p["expected_results"]) == 1 and p["expected_results"][0]["kind"] == "crown"


def test_procedure_for_technique_empty():
    assert procedure_for_technique(FakeSession(), "T9999") == []
    assert procedure_for_technique(FakeSession(), "") == []


def test_procedure_for_technique_parent_inherits_subtech():
    # 부모 기법(T1552)으로 질의 → 하위기법(T1552.001) 절차 상속(ATT&CK 계층; killchain-1 되살림)
    s = FakeSession(procs_by_tech={"T1552.001": [{
        "procedure": "PROC-kc1-wiki-cred-harvest", "name": "자격증명 수확", "description": "민감파일 수확",
        "env": "killchain-1", "cve": None, "cwe": None, "status": "AUTHORED",
        "preconditions": [], "expected_results": [{"id": "ER-kc1", "name": "크라운", "kind": "crown"}]}]})
    assert procedure_for_technique(s, "T1552")[0]["procedure"] == "PROC-kc1-wiki-cred-harvest"   # 부모→하위 상속
    assert procedure_for_technique(s, "T1552.001")[0]["env"] == "killchain-1"                      # 하위 자기 자신
    assert procedure_for_technique(s, "T1078") == []                                               # 무관 기법 안 샘


def test_render_procedures():
    block = render_procedures([{
        "procedure": "PROC-x", "name": "n", "description": "do the thing", "env": "struts2",
        "preconditions": [{"name": "취약 버전", "config_key": None, "expected_value": None}],
        "expected_results": [{"id": "ER", "name": "host file read", "kind": "crown"}]}])
    assert "PROC-x [struts2]: do the thing" in block
    assert "requires: 취약 버전" in block and "goal: host file read" in block
    assert render_procedures([]) == ""


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
