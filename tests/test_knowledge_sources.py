"""지식 그래프 소스 파서(knowledge/sources.py) 스모크 — 바닥층 enrich 중심.

Neo4j 없이 순수 함수(raw dict -> (nodes, rels))만 검증한다.
parse_attack 의 Platform 속성, parse_nvd 의 AttackVector·C/I/A 영향·공개 익스플로잇 플래그가
실제로 노드 속성으로 떨어지는지 확인(A 자동 enrich 검증).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from knowledge import schema  # noqa: E402
from knowledge.sources import parse_allowlist, parse_attack, parse_nvd  # noqa: E402


def _node(nodes, label, nid):
    for n in nodes:
        if n["label"] == label and n["id"] == nid:
            return n
    raise AssertionError(f"노드 못 찾음: {label} {nid}")


# ───────────── 샘플 원본 ─────────────
ATTACK_SAMPLE = {"objects": [
    {"type": "x-mitre-tactic", "x_mitre_shortname": "initial-access", "name": "Initial Access",
     "external_references": [{"source_name": "mitre-attack", "external_id": "TA0001"}]},
    {"type": "attack-pattern", "id": "attack-pattern--t1190", "name": "Exploit Public-Facing Application",
     "description": "RCE via public app", "x_mitre_platforms": ["Containers", "Linux", "Windows"],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1190"}],
     "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}]},
    {"type": "attack-pattern", "id": "attack-pattern--t1078004", "name": "Cloud Accounts",
     "x_mitre_is_subtechnique": True, "x_mitre_platforms": ["IaaS"],
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1078.004"}]},
    {"type": "attack-pattern", "id": "attack-pattern--t1046", "name": "Network Service Discovery",
     "description": "no platforms field here",
     "external_references": [{"source_name": "mitre-attack", "external_id": "T1046"}]},
    {"type": "relationship", "relationship_type": "subtechnique-of",
     "source_ref": "attack-pattern--t1078004", "target_ref": "attack-pattern--t1190"},
]}

NVD_SAMPLE = {"vulnerabilities": [
    {"cve": {
        "id": "CVE-2017-5638", "published": "2017-03-10T21:59:00.000",
        "descriptions": [{"lang": "en", "value": "Apache Struts 2 OGNL injection"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "baseScore": 9.8, "baseSeverity": "CRITICAL", "attackVector": "NETWORK",
            "confidentialityImpact": "HIGH", "integrityImpact": "HIGH", "availabilityImpact": "HIGH"}}]},
        "weaknesses": [{"description": [{"value": "CWE-755"}]}],
        "references": [
            {"url": "https://ex/advisory", "tags": ["Vendor Advisory"]},
            {"url": "https://ex/exploit", "tags": ["Exploit", "Third Party Advisory"]}],
    }},
    {"cve": {   # exploit 태그 없음 + CVSS v2 만(accessVector 폴백 경로)
        "id": "CVE-2000-0001",
        "descriptions": [{"lang": "en", "value": "legacy"}],
        "metrics": {"cvssMetricV2": [{"baseSeverity": "MEDIUM", "cvssData": {
            "baseScore": 5.0, "accessVector": "NETWORK",
            "confidentialityImpact": "PARTIAL", "integrityImpact": "NONE", "availabilityImpact": "NONE"}}]},
        "references": [{"url": "https://ex/patch", "tags": ["Patch"]}],
    }},
]}

ALLOWLIST_SAMPLE = {
    "service_types": {"database": {"name": "데이터베이스"},
                      "web-server": {"name": "웹서버·리버스프록시"}},
    "products": [
        {"product": "mysql", "vendors": ["oracle"], "service_type": "database"},
        {"product": "nginx", "vendors": ["f5", "nginx"], "service_type": "web-server"},
    ],
}


# ───────────── parse_attack: Platform 속성 ─────────────
def test_attack_technique_has_platforms():
    nodes, _ = parse_attack(ATTACK_SAMPLE)
    t = _node(nodes, "Technique", "T1190")
    assert t["props"]["platforms"] == ["Containers", "Linux", "Windows"]
    assert t["props"]["description"] == "RCE via public app"


def test_attack_subtechnique_has_platforms():
    nodes, _ = parse_attack(ATTACK_SAMPLE)
    s = _node(nodes, "SubTechnique", "T1078.004")
    assert s["props"]["platforms"] == ["IaaS"]


def test_attack_no_platforms_field_omits_key():
    nodes, _ = parse_attack(ATTACK_SAMPLE)
    t = _node(nodes, "Technique", "T1046")
    assert "platforms" not in t["props"]        # 필드 없으면 속성도 없음(빈 리스트 안 박음)


# ───────────── parse_nvd: AttackVector · C/I/A · exploit 플래그 ─────────────
def test_nvd_cve_v31_enrich():
    nodes, _ = parse_nvd(NVD_SAMPLE)
    p = _node(nodes, "CVE", "CVE-2017-5638")["props"]
    assert p["attack_vector"] == "NETWORK"
    assert (p["impact_conf"], p["impact_integ"], p["impact_avail"]) == ("HIGH", "HIGH", "HIGH")
    assert p["has_public_exploit"] is True
    assert p["cvss_score"] == 9.8 and p["cvss_severity"] == "CRITICAL"


def test_nvd_cve_v2_accessvector_fallback():
    nodes, _ = parse_nvd(NVD_SAMPLE)
    p = _node(nodes, "CVE", "CVE-2000-0001")["props"]
    assert p["attack_vector"] == "NETWORK"          # v2 accessVector 폴백
    assert p["impact_conf"] == "PARTIAL"
    assert "has_public_exploit" not in p            # Exploit 태그 없으면 플래그 없음
    assert p["cvss_score"] == 5.0 and p["cvss_severity"] == "MEDIUM"


def test_nvd_classified_as_still_works():
    _, rels = parse_nvd(NVD_SAMPLE)
    edges = [(r["from_id"], r["to_id"]) for r in rels if r["type"] == "CLASSIFIED_AS"]
    assert ("CVE-2017-5638", "CWE-755") in edges    # enrich 가 기존 관계를 안 깨뜨림


# ───────────── parse_allowlist: Product · ServiceType · PROVIDES_SERVICE ─────────────
def test_allowlist_product_and_servicetype():
    nodes, rels = parse_allowlist(ALLOWLIST_SAMPLE)
    mysql = _node(nodes, "Product", "mysql")["props"]
    assert mysql["cpe_vendor_product"] == ["oracle:mysql"]          # 직관불일치 vendor 교정
    nginx = _node(nodes, "Product", "nginx")["props"]
    assert nginx["cpe_vendor_product"] == ["f5:nginx", "nginx:nginx"]   # 한 제품 여러 vendor
    assert _node(nodes, "ServiceType", "database")["props"]["name"] == "데이터베이스"
    provides = [(r["from_id"], r["to_id"]) for r in rels if r["type"] == "PROVIDES_SERVICE"]
    assert ("mysql", "database") in provides and ("nginx", "web-server") in provides


def test_allowlist_makes_no_cpe_nodes():
    nodes, _ = parse_allowlist(ALLOWLIST_SAMPLE)
    assert not any(n["label"] == "CPE" for n in nodes)             # 설계 안-가: CPE 노드 안 만듦


def test_allowlist_real_file_loads_and_valid():
    path = _ROOT / "knowledge" / "cpe_allowlist.json"
    raw = json.loads(path.read_text(encoding="utf-8"))
    nodes, rels = parse_allowlist(raw)
    for n in nodes:
        schema.check_node(n)
    for r in rels:
        schema.check_rel(r)
    # 전수대조로 교정한 대표 조인키 몇 개가 실제로 들어갔나
    joins = {n["id"]: n["props"]["cpe_vendor_product"]
             for n in nodes if n["label"] == "Product"}
    assert joins.get("mysql") == ["oracle:mysql"]
    assert joins.get("kong_gateway") == ["konghq:kong_gateway"]
    assert "f5:nginx" in joins.get("nginx", []) and "nginx:nginx" in joins.get("nginx", [])
    prod_count = sum(1 for n in nodes if n["label"] == "Product")
    assert prod_count >= 30                                        # 재생성본 규모 하한


# ───────────── 스키마 적합성(enrich 가 잘못된 라벨/관계 안 만들었나) ─────────────
def test_all_nodes_and_rels_pass_schema():
    for raw, parse in [(ATTACK_SAMPLE, parse_attack), (NVD_SAMPLE, parse_nvd),
                       (ALLOWLIST_SAMPLE, parse_allowlist)]:
        nodes, rels = parse(raw)
        for n in nodes:
            schema.check_node(n)
        for r in rels:
            schema.check_rel(r)


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
    print("── 지식 그래프 소스 파서 스모크 ──")
    sys.exit(_run())
