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


def cves_for_term(session: Session, term: str, limit: int = 25) -> list[str]:
    """관측 용어(서비스명·배너·제품 키워드)가 설명에 든 CVE id 들 — 자산→KG 느슨 진입.

    자산은 CPE 식별 전엔 기계 조인이 안 되므로(1차 플래너/KG 가 식별), 관측된 용어로 CVE
    설명을 느슨 검색해 후보를 연다. 입력은 파라미터 바인딩(주입 차단), 라벨은 고정 상수.
    """
    t = (term or "").strip()
    if not t:
        return []
    rows = _rows(session.run(
        "MATCH (c:CVE) WHERE c.description IS NOT NULL "
        "AND toLower(c.description) CONTAINS toLower($t) "
        "RETURN c.id AS id LIMIT $lim", t=t, lim=limit))
    return [r["id"] for r in rows if r.get("id")]


def techniques_for_product(session: Session, term: str) -> list[dict]:
    """제품 용어(이름·벤더·id 조각) → Product 노드 → CPE → CVE → 기법(직접매핑 우선, 브리지 폴백).

    자산을 Product 노드로 조인하는 '정확 경로' — CVE 설명 텍스트 검색(cves_for_term)보다 정확·빠르다
    (그래프 조인). 기법에 안 닿는 끊긴 CVE 는 자동 제외된다. 반환은 techniques_for_cve 와 같은 모양에
    근거 cves(제품의 어느 CVE 를 통했나, 최대 5개)를 더 단다. 입력은 파라미터 바인딩(주입 차단).
    """
    t = (term or "").strip()
    if not t:
        return []
    direct = _rows(session.run(
        "MATCH (p:Product)-[:IDENTIFIED_BY]->(:CPE)-[:AFFECTED_BY]->(c:CVE)-[e:EXPLOITED_BY]->(tech) "
        "WHERE p.name=$t OR p.vendor=$t OR toLower(p.id) CONTAINS toLower($t) "
        "RETURN DISTINCT tech.id AS technique, tech.name AS name, e.category AS category, "
        "e.source AS source, collect(DISTINCT c.id)[..5] AS cves", t=t))
    if direct:
        out = [{"technique": r["technique"], "name": r.get("name"), "via": "product-direct",
                "category": r.get("category"), "source": r.get("source"),
                "confidence": _SOURCE_CONF.get(r.get("source"), 0.6), "cves": r.get("cves") or []}
               for r in direct]
        out.sort(key=lambda x: x["confidence"], reverse=True)
        return out
    bridge = _rows(session.run(
        "MATCH (p:Product)-[:IDENTIFIED_BY]->(:CPE)-[:AFFECTED_BY]->(c:CVE)-[:CLASSIFIED_AS]->(w:CWE)"
        "-[:HAS_ATTACK_PATTERN]->(:CAPEC)-[:MAPS_TO]->(tech) "
        "WHERE (p.name=$t OR p.vendor=$t OR toLower(p.id) CONTAINS toLower($t)) "
        "AND NOT coalesce(w.is_generic,false) "
        "RETURN DISTINCT tech.id AS technique, tech.name AS name, collect(DISTINCT c.id)[..5] AS cves",
        t=t))
    return [{"technique": r["technique"], "name": r.get("name"), "via": "product-bridge",
             "source": "cwe-capec", "confidence": _BRIDGE_CONF, "cves": r.get("cves") or []}
            for r in bridge]


def knowledge_for_terms(session: Session, terms: Iterable[str]) -> dict:
    """여러 관측 용어 → 후보 기법 집계(플래너 situation 공급, LLM 바인딩용).

    각 용어마다 ① Product 그래프 경로(techniques_for_product, 정확)를 먼저 시도하고, 히트가 없으면
    ② CVE 설명 텍스트 검색(cves_for_term, 거침)으로 폴백한다. 플래너 LLM 이 자산과 이 후보를 묶어
    intent 의 technique 를 고른다(둘 다 비면 자기 지식 폴백 — 기계 조인에 안 가둠).
    반환: {by_term:{term:[cve..]}, aggregate:[{technique,name,confidence,via,cves,terms}]}
    (aggregate 는 신뢰도 내림차순). 같은 (CVE,기법)은 한 번만 센다.
    """
    by_term: dict[str, list] = {}
    agg: dict[str, dict] = {}
    seen_cve_tech: set[tuple] = set()      # (cve, technique) 중복 집계 방지

    def _accum(tech: dict, term: str) -> None:
        a = agg.setdefault(tech["technique"], {
            "technique": tech["technique"], "name": tech.get("name"),
            "confidence": 0.0, "via": tech.get("via"), "cves": [], "terms": []})
        a["confidence"] = max(a["confidence"], tech["confidence"])
        for cve in tech.get("cves") or []:
            if (cve, tech["technique"]) not in seen_cve_tech:
                seen_cve_tech.add((cve, tech["technique"]))
                if cve not in a["cves"]:
                    a["cves"].append(cve)
        if term not in a["terms"]:
            a["terms"].append(term)

    for term in terms:
        t = (term or "").strip()
        if not t or t in by_term:
            continue
        # ① Product 그래프 경로 우선(정확): Product→CPE→CVE→기법
        techs = techniques_for_product(session, t)
        if techs:
            by_term[t] = sorted({c for th in techs for c in (th.get("cves") or [])})
            for tech in techs:
                _accum(tech, t)
            continue
        # ② description 텍스트 검색 폴백(거침): CVE 설명에 용어가 든 것
        cids = cves_for_term(session, t)
        by_term[t] = cids
        for cve in cids:
            for tech in techniques_for_cve(session, cve):
                tech = dict(tech)
                tech["cves"] = [cve]          # 통일(techniques_for_cve 는 단일 cve 조회)
                _accum(tech, t)
    aggregate = sorted(agg.values(), key=lambda x: x["confidence"], reverse=True)
    return {"by_term": by_term, "aggregate": aggregate}


def render_kg_candidates(knowledge: dict, *, limit: int = 12) -> str:
    """knowledge_for_terms 결과 → 플래너 프롬프트용 텍스트 블록(없으면 빈 문자열).

    플래너가 LLM 으로 자산과 바인딩하도록 '후보 기법+근거 CVE+매칭 용어'를 간결히 나열한다.
    기계적 '정답'이 아니라 '참고 후보'임을 분명히(플래너가 취사선택).
    """
    agg = (knowledge or {}).get("aggregate", [])[:limit]
    if not agg:
        return ""
    lines = []
    for a in agg:
        name = f" {a['name']}" if a.get("name") else ""
        terms = ", ".join(a.get("terms", []))
        cves = ", ".join(a.get("cves", [])[:3])
        conf = a.get("confidence", 0.0)
        lines.append(f"- {a['technique']}{name} (conf {conf:.2f}; matches: {terms}; via {cves})")
    return "\n".join(lines)


def _demo() -> None:
    """데모 CLI:
      python -m knowledge.query --product gitlab   # 제품→기법(플래너가 받을 후보 + 실제 블록)
      python -m knowledge.query --cve CVE-2021-44228
    """
    import argparse
    import json
    import os
    ap = argparse.ArgumentParser(prog="knowledge.query", description="지식 그래프 조회 데모")
    ap.add_argument("--cve", help="CVE id 로 조회 (CVE→기법)")
    ap.add_argument("--product", help="제품 용어로 조회 (Product→CPE→CVE→기법, 플래너가 받을 후보)")
    ap.add_argument("--uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    ap.add_argument("--user", default=os.environ.get("NEO4J_USER", "neo4j"))
    ap.add_argument("--password", default=os.environ.get("NEO4J_PASSWORD"))
    a = ap.parse_args()
    if not a.cve and not a.product:
        raise SystemExit("--product 또는 --cve 중 하나를 줘라")
    if not a.password:
        raise SystemExit("NEO4J_PASSWORD (또는 --password) 필요")
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(a.uri, auth=(a.user, a.password))
    with driver.session() as s:
        if a.product:
            kn = knowledge_for_terms(s, [a.product])
            out = {"product_term": a.product, "candidates": kn["aggregate"],
                   "planner_block": render_kg_candidates(kn)}   # 플래너 situation 에 들어갈 실제 텍스트
        else:
            out = {"cve": cve_facts(s, a.cve), "techniques": techniques_for_cve(s, a.cve)}
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _demo()
