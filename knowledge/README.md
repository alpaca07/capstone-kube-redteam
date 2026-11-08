# knowledge — 지식 그래프 ETL

공식 분류체계(MITRE ATT&CK · CAPEC · CWE, 나중에 NVD CVE/CPE)를 우리 KG 스키마로
Neo4j에 적재한다. **대상 안 가리는 재사용 지식 라이브러리** — 심어둔 킬체인에 맞추지 않는다.
1차 플래너가 이 그래프를 검색해 어떤 타깃이든 공격 기법을 추론한다.

## 구성
| 파일 | 역할 |
|---|---|
| `schema.py` | KG 라벨·관계 허용목록 + 공식 소스→KG 매핑 계약(이 파일이 설계 핵심) |
| `graph_writer.py` | 라벨별 `UNWIND` 멱등 `MERGE` 적재 엔진(파라미터 바인딩, 세션 주입) |
| `sources.py` | 소스별 `parse_*(raw) -> (nodes, rels)` — ATT&CK/CAPEC 실데이터 검증, CWE 포맷 검증, NVD 뼈대 |
| `__main__.py` | CLI — 받기(fetch)·접속(connect)·적재 |

## 실행 (VM-A, 개발모드 인터넷 ON)
```bash
pip install neo4j
export NEO4J_PASSWORD='<password>'
python -m knowledge --sources cwe,attack,capec          # 순서 중요: cwe → attack → capec
```
`kg-bootstrap.cypher`의 제약조건·색인을 먼저 적용해 두면 적재가 빠르고 중복이 안 생긴다.

## 로컬 파일로 적재 (인터넷 제한 환경)
미리 받아두고 `--data-dir` 로 가리킨다. 파일명 규칙: `enterprise-attack.json` / `stix-capec.json` / `cwec*.xml(.zip)`
```bash
# 예: git clone 으로 받아두기
git clone --depth1 --filter=blob:none --sparse https://github.com/mitre-attack/attack-stix-data
# attack-stix-data: git sparse-checkout set enterprise-attack
git clone --depth1 --filter=blob:none --sparse https://github.com/mitre/cti
# cti: git sparse-checkout set capec/2.1
python -m knowledge --sources attack,capec --data-dir ./kg_data --dry-run   # 건수만 먼저 확인
```

## 데이터 출처
- ATT&CK: `github.com/mitre-attack/attack-stix-data` → `enterprise-attack/enterprise-attack.json`
- CAPEC: `github.com/mitre/cti` → `capec/2.1/stix-capec.json`
- CWE: `cwe.mitre.org/data/xml/cwec_latest.xml.zip`
- NVD: `services.nvd.nist.gov/rest/json/cves/2.0` (VulHub 타깃 CPE 확정 후 `parse_nvd` 채움)

## 검증 결과 (실데이터)
- ATT&CK: Technique 227 · SubTechnique 479 · Tactic 15 / 관계 1459
- CAPEC: 559개 / `MAPS_TO`(→기법) 272 · `HAS_ATTACK_PATTERN`(CWE→CAPEC) 1214

## 주의
- 적재 순서 `cwe → attack → capec`: CAPEC의 `HAS_ATTACK_PATTERN`(CWE→CAPEC)은 CWE 노드가 있어야 붙는다(없으면 조용히 스킵).
- 라벨·관계는 `schema.LABELS`/`RELATIONSHIPS` 허용목록으로 검사 후에만 쿼리에 끼운다(주입 차단).
- 세 그래프(지식/자산/탐색)가 같은 Neo4j를 공유 — 지식 노드엔 `episode_id`를 붙이지 않아 에피소드 리셋에 안 지워진다.
