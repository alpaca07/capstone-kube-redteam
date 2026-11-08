"""소스별 파서 — raw 데이터 -> (nodes, rels).

각 parse_* 는 공식 데이터를 우리 KG 노드/관계 딕셔너리로 바꾼다(모양은 schema.py 참고).
raw 는 그 소스의 로드 결과:
  attack : ATT&CK STIX 번들 dict (enterprise-attack.json 등을 json.load 한 것)
  capec  : CAPEC STIX 번들 dict (stix-capec.json)
  cwe    : CWE XML 루트 Element (cwec_latest.xml 을 ElementTree 로 파싱한 루트)
  nvd    : NVD API 응답 dict (대상 CPE 로 필터)  — 뼈대, 타깃 확정 후

데이터 출처:
  ATT&CK  github.com/mitre-attack/attack-stix-data  enterprise-attack/enterprise-attack.json
  CAPEC   github.com/mitre/cti                        capec/2.1/stix-capec.json
  CWE     cwe.mitre.org/data/xml/cwec_latest.xml.zip
  NVD     services.nvd.nist.gov/rest/json/cves/2.0
"""
from __future__ import annotations

from . import schema

Node = dict
Rel = dict


def knowledge_source_node(source: str) -> Node:
    ks = schema.KNOWLEDGE_SOURCES[source]
    return {"label": "KnowledgeSource", "id": ks["id"],
            "props": {"name": ks["name"], "source_type": ks["source_type"], "url": ks["url"]}}


def _supported_by(source: str, label: str, nid: str) -> Rel:
    ks = schema.KNOWLEDGE_SOURCES[source]
    return {"type": "SUPPORTED_BY", "from_label": label, "from_id": nid,
            "to_label": "KnowledgeSource", "to_id": ks["id"],
            "props": {"source_type": ks["source_type"]}}


def _attack_external_id(obj: dict) -> str | None:
    """STIX 객체에서 mitre-attack external_id (T####, TA####) 뽑기."""
    for r in obj.get("external_references", []):
        if r.get("source_name") == "mitre-attack" and r.get("external_id"):
            return r["external_id"]
    return None


def _is_live(obj: dict) -> bool:
    return not obj.get("revoked") and not obj.get("x_mitre_deprecated")


def _tech_label(attack_id: str) -> str:
    """ATT&CK id 로 Technique/SubTechnique 구분(서브는 점 포함: T1078.004)."""
    return "SubTechnique" if "." in attack_id else "Technique"


# --- ATT&CK ------------------------------------------------------------------
def parse_attack(raw: dict) -> tuple[list[Node], list[Rel]]:
    """STIX 번들 -> Tactic / Technique / SubTechnique + SUPPORTS_TACTIC / HAS_SUBTECHNIQUE."""
    objs = raw["objects"]
    nodes: list[Node] = [knowledge_source_node("attack")]
    rels: list[Rel] = []

    shortname_to_tactic: dict[str, str] = {}   # x_mitre_shortname -> TA####
    stix_to_attack: dict[str, str] = {}        # STIX id -> T#### (attack-pattern)

    # 1) Tactic
    for o in objs:
        if o.get("type") == "x-mitre-tactic" and _is_live(o):
            ta = _attack_external_id(o)
            if not ta:
                continue
            shortname_to_tactic[o.get("x_mitre_shortname", "")] = ta
            nodes.append({"label": "Tactic", "id": ta, "props": {"name": o.get("name", "")}})
            rels.append(_supported_by("attack", "Tactic", ta))

    # 2) Technique / SubTechnique
    for o in objs:
        if o.get("type") != "attack-pattern" or not _is_live(o):
            continue
        tid = _attack_external_id(o)
        if not tid:
            continue
        stix_to_attack[o["id"]] = tid
        label = "SubTechnique" if o.get("x_mitre_is_subtechnique") else "Technique"
        props = {"name": o.get("name", "")}
        if label == "Technique":
            props["description"] = o.get("description", "")
        nodes.append({"label": label, "id": tid, "props": props})
        rels.append(_supported_by("attack", label, tid))
        # Technique -> Tactic (서브는 부모를 통해 전술에 닿으므로 생략)
        if label == "Technique":
            for ph in o.get("kill_chain_phases", []):
                ta = shortname_to_tactic.get(ph.get("phase_name"))
                if ta:
                    rels.append({"type": "SUPPORTS_TACTIC", "from_label": "Technique",
                                 "from_id": tid, "to_label": "Tactic", "to_id": ta, "props": {}})

    # 3) HAS_SUBTECHNIQUE : subtechnique-of 관계(source=sub, target=parent) 뒤집기
    for o in objs:
        if o.get("type") == "relationship" and o.get("relationship_type") == "subtechnique-of":
            sub = stix_to_attack.get(o.get("source_ref"))
            parent = stix_to_attack.get(o.get("target_ref"))
            if sub and parent:
                rels.append({"type": "HAS_SUBTECHNIQUE", "from_label": "Technique", "from_id": parent,
                             "to_label": "SubTechnique", "to_id": sub, "props": {}})
    return nodes, rels


# --- CAPEC -------------------------------------------------------------------
def parse_capec(raw: dict) -> tuple[list[Node], list[Rel]]:
    """CAPEC STIX -> CAPEC 노드 + (CAPEC)-MAPS_TO->(Technique/SubTechnique)
       + (CWE)-HAS_ATTACK_PATTERN->(CAPEC). CWE/Technique 노드는 각 소스가 생성, 여기선 관계만."""
    objs = raw["objects"]
    nodes: list[Node] = [knowledge_source_node("capec")]
    rels: list[Rel] = []

    for o in objs:
        if o.get("type") != "attack-pattern":
            continue
        if (o.get("x_capec_status") or "").lower() == "deprecated":
            continue
        refs = o.get("external_references", [])
        capec_id = next((r["external_id"] for r in refs
                         if r.get("source_name") == "capec" and r.get("external_id")), None)
        if not capec_id:
            continue
        nodes.append({"label": "CAPEC", "id": capec_id,
                      "props": {"name": o.get("name", ""), "description": o.get("description", "")}})
        rels.append(_supported_by("capec", "CAPEC", capec_id))
        for r in refs:
            src, ext = r.get("source_name"), r.get("external_id")
            if not ext:
                continue
            if src == "ATTACK":
                # CAPEC -> MAPS_TO -> Technique/SubTechnique (공식 매핑)
                rels.append({"type": "MAPS_TO", "from_label": "CAPEC", "from_id": capec_id,
                             "to_label": _tech_label(ext), "to_id": ext,
                             "props": {"mapping_type": "OFFICIAL"}})
            elif src == "cwe":
                # (CWE) -HAS_ATTACK_PATTERN-> (CAPEC)
                rels.append({"type": "HAS_ATTACK_PATTERN", "from_label": "CWE", "from_id": ext,
                             "to_label": "CAPEC", "to_id": capec_id, "props": {}})
    return nodes, rels


# --- CWE ---------------------------------------------------------------------
# CWE XML(cwec) 네임스페이스
_CWE_NS = {"c": "http://cwe.mitre.org/cwe-7"}


def parse_cwe(raw) -> tuple[list[Node], list[Rel]]:
    """CWE XML 루트 Element -> CWE 노드(id, name, description).

    cwec 스키마: <Weaknesses><Weakness ID="79" Name="..."><Description>...</Description>...
    네임스페이스 버전이 바뀌면 _CWE_NS 의 7 을 맞춰주면 된다(태그 지역명 기준으로 폭넓게 탐색).
    """
    nodes: list[Node] = [knowledge_source_node("cwe")]
    rels: list[Rel] = []

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1]  # 네임스페이스 떼고 지역명

    for el in raw.iter():
        if local(el.tag) != "Weakness":
            continue
        wid = el.get("ID")
        if not wid:
            continue
        cwe_id = f"CWE-{wid}"
        name = el.get("Name", "")
        desc = ""
        for child in el:
            if local(child.tag) == "Description":
                desc = "".join(child.itertext()).strip()
                break
        nodes.append({"label": "CWE", "id": cwe_id, "props": {"name": name, "description": desc}})
        rels.append(_supported_by("cwe", "CWE", cwe_id))
    return nodes, rels


# --- NVD (뼈대, 대상 소프트웨어 확정 후) -------------------------------------
def parse_nvd(raw) -> tuple[list[Node], list[Rel]]:
    """NVD API 응답 -> CVE / CPE + AFFECTED_BY / CLASSIFIED_AS.

    TODO(적재 세션, VulHub 타깃 확정 후):
      - raw['vulnerabilities'][].cve -> CVE(id, description)
      - configurations..cpeMatch.criteria -> CPE(cpe_uri) + (CPE)-AFFECTED_BY->(CVE){version_range,...}
      - weaknesses..value(CWE-###) -> (CVE)-CLASSIFIED_AS->(CWE)
      - EXPLOITED_BY(->Technique)는 NVD에 직접 매핑 없음 → 보류
    """
    nodes: list[Node] = [knowledge_source_node("nvd")]
    rels: list[Rel] = []
    return nodes, rels


PARSERS = {
    "attack": parse_attack,
    "capec": parse_capec,
    "cwe": parse_cwe,
    "nvd": parse_nvd,
}
