"""KG 스키마 허용목록 + 공식 소스 → KG 매핑 계약.

여기가 ETL의 '설계'다. 실제 파서(sources.py)는 이 매핑대로 필드를 뽑아
graph_writer 가 받는 node/rel 딕셔너리로 만든다.

node 딕셔너리 모양:  {"label": <LABELS 중 하나>, "id": <str>, "props": {<str>: <scalar>}}
rel  딕셔너리 모양:  {"type": <RELATIONSHIPS 중 하나>,
                     "from_label": <LABELS>, "from_id": <str>,
                     "to_label": <LABELS>,   "to_id": <str>,
                     "props": {<str>: <scalar>}}
label/type 는 반드시 아래 허용목록 안의 값이어야 한다(그래야 라벨을 쿼리에 안전하게 끼움).
"""
from __future__ import annotations

# --- 지식 그래프 라벨 허용목록 (kg-schema-registry.yaml 과 일치) ---
LABELS: frozenset[str] = frozenset({
    # d01 Asset & Technology
    "Product", "CPE", "Platform", "Technology", "ServiceType", "Configuration",
    # d02 Vulnerability
    "CVE", "CWE", "Advisory",
    # d03 Attack Knowledge
    "CAPEC", "Tactic", "Technique", "SubTechnique", "AttackVector",
    # d04 Attack Procedure
    "Procedure", "Precondition", "CleanupAction",
    # d05 Expected Outcome
    "AttackOutcome", "ExpectedResult", "ResultCondition", "EvidenceType",
    # d06 Knowledge Provenance
    "KnowledgeSource", "KnowledgeRevision", "VerificationRecord", "EvidenceReference",
})

# --- 관계 타입 허용목록 ---
RELATIONSHIPS: frozenset[str] = frozenset({
    "IDENTIFIED_BY", "RUNS_ON", "USES_TECHNOLOGY", "PROVIDES_SERVICE",
    "AFFECTED_BY", "CLASSIFIED_AS", "DOCUMENTED_IN",
    "HAS_ATTACK_PATTERN", "EXPLOITED_BY", "MAPS_TO",
    "SUPPORTS_TACTIC", "HAS_SUBTECHNIQUE", "USES_VECTOR", "REALIZED_BY",
    "REQUIRES", "REQUIRES_CONFIGURATION", "REVERSED_BY", "PRODUCES",
    "HAS_OUTCOME", "CONSTRAINED_BY", "EVIDENCED_BY",
    "SUPPORTED_BY", "REFERENCES", "HAS_REVISION", "SUPERSEDES", "DERIVED_FROM",
})

# 적재 때 모든 소스 노드가 공유하는 출처(Provenance) — 소스별 KnowledgeSource id
KNOWLEDGE_SOURCES = {
    "attack": {"id": "KS-mitre-attack", "name": "MITRE ATT&CK", "source_type": "OFFICIAL",
               "url": "https://attack.mitre.org/"},
    "capec":  {"id": "KS-mitre-capec",  "name": "MITRE CAPEC",  "source_type": "OFFICIAL",
               "url": "https://capec.mitre.org/"},
    "cwe":    {"id": "KS-mitre-cwe",    "name": "MITRE CWE",    "source_type": "OFFICIAL",
               "url": "https://cwe.mitre.org/"},
    "nvd":    {"id": "KS-nvd",          "name": "NVD",          "source_type": "OFFICIAL",
               "url": "https://nvd.nist.gov/"},
    # CVE -> ATT&CK 직접 매핑 출처 (EXPLOITED_BY)
    "ctid":    {"id": "KS-ctid-cve-attack", "name": "CTID CVE→ATT&CK(2021 CSV)", "source_type": "COMMUNITY",
                "url": "https://github.com/center-for-threat-informed-defense/mappings-explorer"},
    "kev":     {"id": "KS-cisa-kev-attack", "name": "CISA KEV→ATT&CK(CTID)", "source_type": "COMMUNITY",
                "url": "https://github.com/center-for-threat-informed-defense/mappings-explorer"},
    "curated": {"id": "KS-curated-cve-attack", "name": "직접 큐레이트 CVE→ATT&CK", "source_type": "CURATED",
                "url": ""},
}

# =============================================================================
# 매핑 계약 — 각 소스의 무엇이 어떤 KG 노드/관계가 되는가
# (실제 필드 추출은 sources.py 가 아래 'extract' 키들을 따라 구현)
# =============================================================================

# ATT&CK STIX (enterprise/mobile/ics 번들, github: mitre-attack/attack-stix-data)
ATTACK_MAPPING = {
    # STIX object type -> KG label
    "object_to_label": {
        "x-mitre-tactic": "Tactic",
        "attack-pattern": "Technique",       # x_mitre_is_subtechnique=true 면 SubTechnique
    },
    # 노드 속성 추출 키
    "technique": {"label": "Technique", "id_from": "external_id (ATT&CK ID, 예 T1190)",
                  "props": {"name": "name", "description": "description"}},
    "subtechnique": {"label": "SubTechnique", "id_from": "external_id (예 T1078.004)",
                     "props": {"name": "name"}},
    "tactic": {"label": "Tactic", "id_from": "external_id (예 TA0001)",
               "props": {"name": "name"}},
    # 관계 추출
    "relationships": [
        # Technique -> Tactic : attack-pattern.kill_chain_phases[].phase_name(=tactic shortname) 로 tactic 매칭
        {"type": "SUPPORTS_TACTIC", "from": "Technique", "to": "Tactic",
         "via": "kill_chain_phases.phase_name -> x-mitre-tactic.x_mitre_shortname"},
        # Technique -> SubTechnique : STIX relationship 'subtechnique-of' (source=sub, target=parent) 뒤집어
        {"type": "HAS_SUBTECHNIQUE", "from": "Technique", "to": "SubTechnique",
         "via": "relationship type=subtechnique-of (reverse)"},
    ],
}

# CAPEC (github: mitre/cti capec STIX, 또는 capec.mitre.org XML/CSV)
CAPEC_MAPPING = {
    "capec": {"label": "CAPEC", "id_from": "CAPEC-<ID>",
              "props": {"name": "name", "description": "summary"}},
    "relationships": [
        # CAPEC -> Technique : CAPEC 의 ATT&CK 분류 매핑(Taxonomy_Mappings, taxonomy=ATTACK)
        {"type": "MAPS_TO", "from": "CAPEC", "to": "Technique",
         "via": "Taxonomy_Mappings[ATTACK].Entry_ID -> T<ID>",
         "props": {"mapping_type": "OFFICIAL"}},
        # CWE -> CAPEC : CAPEC 의 Related_Weaknesses(CWE_ID) 를 뒤집어 CWE 쪽에서 건다
        {"type": "HAS_ATTACK_PATTERN", "from": "CWE", "to": "CAPEC",
         "via": "Related_Weaknesses.CWE_ID (reverse)"},
    ],
}

# CWE (cwe.mitre.org XML, 또는 csv)
CWE_MAPPING = {
    "cwe": {"label": "CWE", "id_from": "CWE-<ID>",
            "props": {"name": "Name", "description": "Description"}},
    # CWE 자체 관계는 초기엔 적재 안 함(CWE->CAPEC 는 CAPEC 쪽에서 건다). 확장시 ChildOf 등 추가 가능.
}

# NVD CVE/CPE (services.nvd.nist.gov API) — parse_nvd 구현됨(타깃 CVE/CPE 로 질의, sources.py)
NVD_MAPPING = {
    "cve": {"label": "CVE", "id_from": "cve.id", "props": {"description": "descriptions[en]"}},
    "cpe": {"label": "CPE", "id_from": "cpe-name slug", "props": {"cpe_uri": "criteria"}},
    "relationships": [
        {"type": "AFFECTED_BY", "from": "CPE", "to": "CVE",
         "via": "configurations[].nodes[].cpeMatch[].criteria",
         "props": {"confidence": 1.0, "source_type": "OFFICIAL",
                   "version_range": "versionStartIncluding..versionEndExcluding"}},
        {"type": "CLASSIFIED_AS", "from": "CVE", "to": "CWE",
         "via": "weaknesses[].description[].value (CWE-<ID>)"},
        {"type": "EXPLOITED_BY", "from": "CVE", "to": "Technique",
         "via": "별도 매핑 필요(NVD엔 ATT&CK 직접 매핑 없음) — 보류/후순위",
         "props": {"validation_level": "UNKNOWN"}},
    ],
}

SOURCE_MAPPINGS = {
    "attack": ATTACK_MAPPING,
    "capec": CAPEC_MAPPING,
    "cwe": CWE_MAPPING,
    "nvd": NVD_MAPPING,
}


def check_node(node: dict) -> None:
    """적재 전 라벨 허용목록 검사(안전하게 쿼리에 라벨을 끼우기 위함)."""
    if node["label"] not in LABELS:
        raise ValueError(f"unknown label: {node['label']!r}")


def check_rel(rel: dict) -> None:
    if rel["type"] not in RELATIONSHIPS:
        raise ValueError(f"unknown relationship: {rel['type']!r}")
    for key in ("from_label", "to_label"):
        if rel[key] not in LABELS:
            raise ValueError(f"unknown label in rel: {rel[key]!r}")
