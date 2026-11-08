"""지식 그래프 조회(Retrieval) — 플래너가 KG 에서 공격 기법을 추론할 때 쓰는 읽기 API.

핵심 설계: CVE→기법은 **직접 매핑 우선, 브리지 폴백**.
  1) 직접: (CVE)-[:EXPLOITED_BY]->(Technique)  — KEV/큐레이트. 정확.
  2) 폴백: (CVE)-[:CLASSIFIED_AS]->(CWE)-[:HAS_ATTACK_PATTERN]->(CAPEC)-[:MAPS_TO]->(Technique)
          단 generic CWE(is_generic=true)는 노이즈라 제외.
결과엔 via(direct/bridge)·source·confidence 를 달아 플래너가 가중치를 줄 수 있게 한다.

세션은 graph_writer.Session 과 같은 최소 계약(run(query, **params) -> 행들). **읽기 전용**(MATCH/RETURN).
반환은 전부 평범한 dict/list(JSON 직렬화 가능) — LLM/플래너가 바로 소비.
라벨·관계는 전부 고정 상수로만 쿼리에 들어가고, 입력(cve_id 등)은 파라미터 바인딩(주입 차단).
"""
from __future__ import annotations

from typing import Iterable

from .graph_writer import Session   # Protocol: run(query, **params)

# 직접 매핑 출처별 신뢰도(플래너 가중치용). 브리지는 0.4 고정.
_SOURCE_CONF = {"curated": 0.95, "kev": 0.90, "ctid": 0.70, "llm": 0.50}
_BRIDGE_CONF = 0.40


def _rows(result) -> list[dict]:
    """neo4j Result(행=Record, .data() 보유) 또는 dict 리스트를 dict 리스트로 통일."""
    out = []
    for r in result:
        out.append(r.data() if hasattr(r, "data") else dict(r))
    return out


def cve_facts(session: Session, cve_id: str) -> dict | None:
    """CVE 사실: 설명·심각도·분류 CWE. 없으면 None."""
    q = ("MATCH (c:CVE {id:$id}) "
         "OPTIONAL MATCH (c)-[:CLASSIFIED_AS]->(w:CWE) "
         "RETURN c.id AS id, c.description AS description, c.cvss_score AS cvss_score, "
         "c.cvss_severity AS cvss_severity, collect(DISTINCT w.id) AS cwes")
    rows = _rows(session.run(q, id=cve_id))
    return rows[0] if rows and rows[0].get("id") is not None else None


def techniques_for_cve(session: Session, cve_id: str) -> list[dict]:
    """CVE → 후보 기법. 직접 매핑 있으면 그것만(정확), 없으면 브리지 폴백(generic 제외).
    반환: [{technique, name, via, category|via_cwe/via_capec, source, confidence}] 신뢰도 내림차순."""
    direct = _rows(session.run(
        "MATCH (c:CVE {id:$id})-[e:EXPLOITED_BY]->(t) "
        "RETURN t.id AS technique, t.name AS name, e.category AS category, e.source AS source",
        id=cve_id))
    if direct:
        out = [{"technique": r["technique"], "name": r.get("name"), "via": "direct",
                "category": r.get("category"), "source": r.get("source"),
                "confidence": _SOURCE_CONF.get(r.get("source"), 0.6)} for r in direct]
        out.sort(key=lambda x: x["confidence"], reverse=True)
        return out

    bridge = _rows(session.run(
        "MATCH (c:CVE {id:$id})-[:CLASSIFIED_AS]->(w:CWE)-[:HAS_ATTACK_PATTERN]->(cap:CAPEC)-[:MAPS_TO]->(t) "
        "WHERE NOT coalesce(w.is_generic,false) "
        "RETURN DISTINCT t.id AS technique, t.name AS name, w.id AS via_cwe, cap.id AS via_capec",
        id=cve_id))
    return [{"technique": r["technique"], "name": r.get("name"), "via": "bridge",
             "source": "cwe-capec", "via_cwe": r.get("via_cwe"), "via_capec": r.get("via_capec"),
             "confidence": _BRIDGE_CONF} for r in bridge]


def technique_detail(session: Session, tech_id: str) -> dict | None:
    """기법 상세: 이름·전술·상위/하위 기법. Technique/SubTechnique 공용."""
    q = ("MATCH (t {id:$id}) WHERE t:Technique OR t:SubTechnique "
         "OPTIONAL MATCH (t)-[:SUPPORTS_TACTIC]->(ta:Tactic) "
         "OPTIONAL MATCH (parent:Technique)-[:HAS_SUBTECHNIQUE]->(t) "
         "OPTIONAL MATCH (t)-[:HAS_SUBTECHNIQUE]->(sub:SubTechnique) "
         "RETURN t.id AS id, t.name AS name, labels(t) AS labels, "
         "collect(DISTINCT ta.id) AS tactics, collect(DISTINCT parent.id) AS parents, "
         "collect(DISTINCT sub.id) AS subtechniques")
    rows = _rows(session.run(q, id=tech_id))
    return rows[0] if rows and rows[0].get("id") is not None else None


def techniques_for_target(session: Session, cve_ids: Iterable[str]) -> dict:
    """여러 타깃 CVE → CVE별 후보 + 집계(플래너가 타깃 전체를 한 번에 추론).
    반환: {by_cve:{cve:[...]}, aggregate:[{technique, name, confidence, cves:[...]}]}."""
    by_cve: dict[str, list] = {}
    agg: dict[str, dict] = {}
    for cve in cve_ids:
        techs = techniques_for_cve(session, cve)
        by_cve[cve] = techs
        for t in techs:
            a = agg.setdefault(t["technique"], {"technique": t["technique"], "name": t.get("name"),
                                                "confidence": 0.0, "cves": []})
            a["confidence"] = max(a["confidence"], t["confidence"])
            if cve not in a["cves"]:
                a["cves"].append(cve)
    aggregate = sorted(agg.values(), key=lambda x: x["confidence"], reverse=True)
    return {"by_cve": by_cve, "aggregate": aggregate}


def _demo() -> None:
    """데모 CLI: python -m knowledge.query --cve CVE-2021-44228"""
    import argparse
    import json
    import os
    ap = argparse.ArgumentParser(prog="knowledge.query", description="지식 그래프 조회 데모")
    ap.add_argument("--cve", required=True, help="조회할 CVE id (예: CVE-2021-44228)")
    ap.add_argument("--uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    ap.add_argument("--user", default=os.environ.get("NEO4J_USER", "neo4j"))
    ap.add_argument("--password", default=os.environ.get("NEO4J_PASSWORD"))
    a = ap.parse_args()
    if not a.password:
        raise SystemExit("NEO4J_PASSWORD (또는 --password) 필요")
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(a.uri, auth=(a.user, a.password))
    with driver.session() as s:
        out = {"cve": cve_facts(s, a.cve), "techniques": techniques_for_cve(s, a.cve)}
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _demo()
