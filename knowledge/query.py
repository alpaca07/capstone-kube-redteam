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

# 직접 매핑 출처별 신뢰도(플래너 가중치용).
_SOURCE_CONF = {"curated": 0.95, "kev": 0.90, "ctid": 0.70, "llm": 0.50}
# 브리지(약점→공격패턴→기법)는 '가능성 범위'라 노이즈가 섞인다 → 낮게(약한 힌트). 플래너가
# 자산에 명백히 맞을 때만 쓰고 아니면 무시하도록, 직접 매핑과 큰 차를 둔다.
_BRIDGE_CONF = 0.20


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
        "MATCH (c:CVE {id:$id})-[e:EXPLOITED_BY]->(mapped) "
        "OPTIONAL MATCH (parent:Technique)-[:HAS_SUBTECHNIQUE]->(mapped) "
        "WITH coalesce(parent, mapped) AS t, "
        "     collect(DISTINCT e.category)[0] AS category, collect(DISTINCT e.source)[0] AS source "
        "WHERE t:Technique "   # 세부기법은 부모로 승격, 부모 없는 고아는 제외
        "RETURN t.id AS technique, t.name AS name, category, source",
        id=cve_id))
    if direct:
        out = [{"technique": r["technique"], "name": r.get("name"), "via": "direct",
                "category": r.get("category"), "source": r.get("source"),
                "confidence": _SOURCE_CONF.get(r.get("source"), 0.6)} for r in direct]
        out.sort(key=lambda x: x["confidence"], reverse=True)
        return out

    bridge = _rows(session.run(
        "MATCH (c:CVE {id:$id})-[:CLASSIFIED_AS]->(w:CWE)-[:HAS_ATTACK_PATTERN]->(cap:CAPEC)-[:MAPS_TO]->(mapped) "
        "WHERE NOT coalesce(w.is_generic,false) "
        "OPTIONAL MATCH (parent:Technique)-[:HAS_SUBTECHNIQUE]->(mapped) "
        "WITH coalesce(parent, mapped) AS t, "
        "     collect(DISTINCT w.id)[0] AS via_cwe, collect(DISTINCT cap.id)[0] AS via_capec "
        "WHERE t:Technique "
        "RETURN t.id AS technique, t.name AS name, via_cwe, via_capec",
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
        "MATCH (p:Product)-[:IDENTIFIED_BY]->(:CPE)-[:AFFECTED_BY]->(c:CVE)-[e:EXPLOITED_BY]->(mapped) "
        "WHERE p.name=$t OR p.vendor=$t OR toLower(p.id) CONTAINS toLower($t) "
        "OPTIONAL MATCH (parent:Technique)-[:HAS_SUBTECHNIQUE]->(mapped) "
        "WITH coalesce(parent, mapped) AS tech, collect(DISTINCT c.id)[..5] AS cves, "
        "     collect(DISTINCT e.category)[0] AS category, collect(DISTINCT e.source)[0] AS source "
        "WHERE tech:Technique "
        "RETURN tech.id AS technique, tech.name AS name, category, source, cves", t=t))
    if direct:
        out = [{"technique": r["technique"], "name": r.get("name"), "via": "product-direct",
                "category": r.get("category"), "source": r.get("source"),
                "confidence": _SOURCE_CONF.get(r.get("source"), 0.6), "cves": r.get("cves") or []}
               for r in direct]
        out.sort(key=lambda x: x["confidence"], reverse=True)
        return out
    bridge = _rows(session.run(
        "MATCH (p:Product)-[:IDENTIFIED_BY]->(:CPE)-[:AFFECTED_BY]->(c:CVE)-[:CLASSIFIED_AS]->(w:CWE)"
        "-[:HAS_ATTACK_PATTERN]->(:CAPEC)-[:MAPS_TO]->(mapped) "
        "WHERE (p.name=$t OR p.vendor=$t OR toLower(p.id) CONTAINS toLower($t)) "
        "AND NOT coalesce(w.is_generic,false) "
        "OPTIONAL MATCH (parent:Technique)-[:HAS_SUBTECHNIQUE]->(mapped) "
        "WITH coalesce(parent, mapped) AS tech, collect(DISTINCT c.id)[..5] AS cves "
        "WHERE tech:Technique "
        "RETURN tech.id AS technique, tech.name AS name, cves", t=t))
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


def procedure_for_technique(session: Session, tech_id: str) -> list[dict]:
    """기법/하위기법 → 그 기법을 실현하는 Procedure(들) + 전제·예상결과(핵심층 ④⑤ 질의).

    1차 planner 가 고른 technique 로 '이 기법을 실제로 어떻게 수행하나'(절차·전제·목표)를 KG 에서 꺼낸다 —
    워커가 payload 를 쓸 때 참고한다. 여러 환경이 같은 기법을 실현하면(예: T1190→struts2/gitlab/spring) 모두
    반환하고 워커 LLM 이 관측에 맞는 걸 고른다(기계적 '정답' 아님). Technique·SubTechnique 공용.
    부모 기법(T1552)으로 질의하면 하위기법(T1552.001) 절차도 상속해 반환한다(ATT&CK 계층 — 1차 후보가
    부모 입자로 와도 하위 핵심층 절차가 안 묻히게. 하위로 질의하면 그 하위 자신만, 형제·부모는 미포함).
    반환: [{procedure, name, description, env, cve, cwe, status,
            preconditions:[{name, description, config_key, expected_value}], expected_results:[{id, name, kind}]}]
    """
    t = (tech_id or "").strip()
    if not t:
        return []
    rows = _rows(session.run(
        "WITH $id AS qid, split($id,'.')[0] AS base "
        "MATCH (tech)-[:REALIZED_BY]->(p:Procedure) "
        "WHERE (tech:Technique OR tech:SubTechnique) AND "
        "(tech.id = qid OR (qid = base AND tech.id STARTS WITH (base + '.'))) "
        "OPTIONAL MATCH (p)-[:REQUIRES]->(pre:Precondition) "
        "OPTIONAL MATCH (pre)-[rc:REQUIRES_CONFIGURATION]->(cfg:Configuration) "
        "OPTIONAL MATCH (p)-[:PRODUCES]->(er:ExpectedResult) "
        "OPTIONAL MATCH (p)-[:REVERSED_BY]->(cl:CleanupAction) "
        "RETURN p.id AS procedure, p.name AS name, p.description AS description, "
        "p.env AS env, p.cve AS cve, p.cwe AS cwe, p.status AS status, "
        "collect(DISTINCT {name: pre.name, description: pre.description, "
        "config_key: cfg.config_key, expected_value: rc.expected_value}) AS preconditions, "
        "collect(DISTINCT {id: er.id, name: er.name, kind: er.kind}) AS expected_results, "
        "collect(DISTINCT {name: cl.name, description: cl.description}) AS cleanup",
        id=t))
    out = []
    for r in rows:
        if not r.get("procedure"):
            continue
        pres = [pp for pp in (r.get("preconditions") or []) if pp.get("name")]       # null 전제 제거
        ers = [ee for ee in (r.get("expected_results") or []) if ee.get("id")]
        cleans = [cc for cc in (r.get("cleanup") or []) if cc.get("name")]   # null 정리 제거
        out.append({"procedure": r["procedure"], "name": r.get("name"),
                    "description": r.get("description"), "env": r.get("env"),
                    "cve": r.get("cve"), "cwe": r.get("cwe"), "status": r.get("status"),
                    "preconditions": pres, "expected_results": ers, "cleanup": cleans})
    return out


def render_procedures(procedures: list[dict], *, limit: int = 6) -> str:
    """procedure_for_technique 결과 → 워커 프롬프트용 텍스트 블록(없으면 빈 문자열).

    '이 기법의 알려진 절차+전제+목표'를 간결히 나열 — 워커가 관측에 맞는 걸 골라 payload 작성에 참고
    (참고 절차일 뿐, 실제 명령은 워커가 스스로 쓴다).
    """
    procs = (procedures or [])[:limit]
    if not procs:
        return ""
    lines = []
    for p in procs:
        env = f" [{p['env']}]" if p.get("env") else ""
        desc = p.get("description") or p.get("name") or ""
        lines.append(f"- {p['procedure']}{env}: {desc}")
        for pre in (p.get("preconditions") or [])[:3]:
            cond = f" (needs {pre['config_key']}={pre.get('expected_value')})" if pre.get("config_key") else ""
            lines.append(f"    requires: {pre.get('name', '')}{cond}")
        goals = [e.get("name") for e in (p.get("expected_results") or []) if e.get("kind") == "crown"]
        if goals:
            lines.append(f"    goal: {', '.join(g for g in goals if g)}")
        cleans = [c.get("name") for c in (p.get("cleanup") or []) if c.get("name")]
        if cleans:
            lines.append(f"    cleanup: {', '.join(cleans)}")
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
    ap.add_argument("--product", help="제품 용어로 조회 (Product→CPE→CVE→기법, 1차 플래너가 받을 후보)")
    ap.add_argument("--technique", help="기법 id 로 조회 (Technique→Procedure 절차·전제·목표, 워커가 받을 블록)")
    ap.add_argument("--uri", default=os.environ.get("NEO4J_URI", "bolt://localhost:7687"))
    ap.add_argument("--user", default=os.environ.get("NEO4J_USER", "neo4j"))
    ap.add_argument("--password", default=os.environ.get("NEO4J_PASSWORD"))
    a = ap.parse_args()
    if not (a.cve or a.product or a.technique):
        raise SystemExit("--product / --cve / --technique 중 하나를 줘라")
    if not a.password:
        raise SystemExit("NEO4J_PASSWORD (또는 --password) 필요")
    from neo4j import GraphDatabase
    driver = GraphDatabase.driver(a.uri, auth=(a.user, a.password))
    with driver.session() as s:
        if a.product:
            kn = knowledge_for_terms(s, [a.product])
            out = {"product_term": a.product, "candidates": kn["aggregate"],
                   "planner_block": render_kg_candidates(kn)}   # 1차 플래너 situation 에 들어갈 실제 텍스트
        elif a.technique:
            procs = procedure_for_technique(s, a.technique)
            out = {"technique": a.technique, "procedures": procs,
                   "worker_block": render_procedures(procs)}     # 워커가 받을 절차 블록
        else:
            out = {"cve": cve_facts(s, a.cve), "techniques": techniques_for_cve(s, a.cve)}
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    _demo()
