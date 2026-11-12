# knowledge — 지식 그래프 ETL

공식 분류체계(MITRE ATT&CK · CAPEC · CWE · NVD CVE)와 CVE→ATT&CK 직접 매핑(CISA KEV · 큐레이트)을 우리 KG 스키마로
Neo4j에 적재한다. **대상 안 가리는 재사용 지식 라이브러리** — 심어둔 킬체인에 맞추지 않는다.
1차 플래너가 이 그래프를 검색해 어떤 타깃이든 공격 기법을 추론한다.

## 구성
| 파일 | 역할 |
|---|---|
| `schema.py` | KG 라벨·관계 허용목록 + 공식 소스→KG 매핑 계약 + 제약조건 생성(이 파일이 설계 핵심) |
| `bootstrap.cypher` | 라벨 id 유일성 제약·색인 — `schema.LABELS`에서 자동생성(`--bootstrap` 로도 적용) |
| `graph_writer.py` | 라벨별 `UNWIND` 멱등 `MERGE` 적재 엔진(파라미터 바인딩, 세션 주입) |
| `sources.py` | 소스별 `parse_*(raw) -> (nodes, rels)` — ATT&CK/CAPEC/NVD/cve_attack. generic CWE 꼬리표·NVD CPE 토글도 여기 |
| `__main__.py` | CLI — 받기(fetch)·접속(connect)·적재 |
| `query.py` | 조회(Retrieval) 읽기 API — 플래너가 CVE→기법 추론할 때 호출. 직접매핑 우선·브리지 폴백 |
| `cve_attack.example.json` | CVE→Technique 큐레이트 매핑 템플릿(복사해서 VM-B 타깃으로 채움) |
| `cve_attack.vulhub.json` | VulHub 4 타깃(Struts2·GitLab·Spring·PostgreSQL) 실제 CVE→Technique 매핑 — 끊긴 CWE→CAPEC 사슬을 직접 메움 |

## 실행 (VM-A, 개발모드 인터넷 ON)
```bash
pip install neo4j
export NEO4J_PASSWORD=네_실제_비번
python -m knowledge --bootstrap                          # 1) 제약조건·색인 먼저(1회)
python -m knowledge --sources cwe,attack,capec           # 2) 기반: cwe → attack → capec
# 3) VulHub 4 타깃(바닥층 CVE/CPE → 직접 매핑). attack 적재 뒤에 돌려야 Technique 노드에 붙는다.
python -m knowledge --sources nvd       --nvd-targets knowledge/nvd_targets.vulhub.json
python -m knowledge --sources cve_attack --cve-map    knowledge/cve_attack.vulhub.json
```
제약조건·색인은 `python -m knowledge --bootstrap`(또는 `cypher-shell -u neo4j -p $NEO4J_PASSWORD < knowledge/bootstrap.cypher`)으로 적재 전 1회. 25개 라벨의 id 유일성(=조회 색인 겸용)이라 적재가 빠르고 중복이 안 생긴다. `bootstrap.cypher`는 `schema.LABELS`에서 자동 생성(수정 말고 재생성).

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

## NVD (취약점 사실 층)
CVE를 "이 타깃에 이런 취약점이 있다"는 사실로 적재한다(설명·심각도·CWE 분류). 대상 안 가리는 다른 소스와 달리 **NVD만 타깃을 받는다** — VM-B 에 심은 취약점 기준:
```bash
# (가) 정확히 그 CVE만 — VulHub 는 보통 CVE 단위라 id 를 알 때
python -m knowledge --sources nvd --nvd-cve CVE-2021-44228,CVE-2021-45046
# (나) 그 제품의 CVE 전부
python -m knowledge --sources nvd --nvd-cpe cpe:2.3:a:apache:log4j
# (다) 목록이 길면 파일로:  {"cve_ids":[...], "cpe_matches":[...]}
python -m knowledge --sources nvd --nvd-targets ./kg_data/nvd_targets.json
```
- **CPE 열거는 기본 미적재.** 한 CVE가 영향 준 수백 벤더 제품 CPE는 노이즈라 안 넣는다. VM-B 스택 매칭을 CPE 노드로 하고 싶으면 `--nvd-cpe-nodes` 로 켠다.
- CVE→기법은 CWE 브리지가 아니라 **아래 `cve_attack` 직접 매핑**을 쓴다(이유는 그 섹션).
- 적재는 **cwe 다음**이어야 `CLASSIFIED_AS`(CVE→CWE)가 붙는다. 레이트리밋: `export NVD_API_KEY=<키>` 주면 빠름.
- 오프라인/재현: `<data-dir>/nvd-raw.json` 에 API 응답을 덤프해두면 그걸 그대로 적재한다.

## CVE→ATT&CK 직접 매핑 (cve_attack)
**왜 필요한가**: `CVE→CWE→CAPEC→Technique` 브리지는 NVD가 generic CWE(예 `CWE-20`)를 자주 달아 엉뚱한 기법으로 샌다(실측: Log4Shell → `CWE-20 → T1539` 쿠키탈취). 그래서 **전문가가 매긴 CVE→Technique 직접 매핑**(`EXPLOITED_BY`)을 우선 경로로 둔다. 소스 셋을 있으면 합쳐 쓴다:

| 소스 | 내용 | 최신성 |
|---|---|---|
| **KEV**(권장) | CISA 실악용 CVE → ATT&CK (CTID 매핑) | 2025판 · ATT&CK v16.1 · Log4Shell·2024 CVE 포함 |
| 큐레이트 | 직접 채운 `cve_attack.json`(공백 메움) | 수동 |
| CTID CSV | 범용 839개 | 2021판(레거시) |

```bash
# KEV 매핑 받기(권장) — mappings/kev 만 얇게
git clone --depth 1 --filter=blob:none --sparse https://github.com/center-for-threat-informed-defense/mappings-explorer /tmp/ctid
cd /tmp/ctid && git sparse-checkout set mappings/kev && cd /home/vm-a/capstone
# data-dir 로 주면 최신 스냅샷 자동 선택(또는 --kev-json 로 파일 직접)
python -m knowledge --sources cve_attack --data-dir /tmp/ctid/mappings/kev
```
- **최신 유지**: CTID가 KEV 스냅샷을 주기적으로 갱신 → 가끔 위 clone 다시 돌려 재적재하면 반영.
- generic CWE 노드엔 `is_generic=true` 꼬리표 → 플래너 질의가 브리지에서 뺄 때 `WHERE NOT coalesce(w.is_generic,false)`.
- 적재는 **attack 다음**(Technique 노드 선행). 전체: `--sources cwe,attack,capec,nvd,cve_attack`.
- 검증: KEV 2025-07판 419개 CVE / `EXPLOITED_BY` 1177건(ATT&CK v16.1).

## 조회 (query) — 플래너 읽기 API
적재한 그래프를 플래너가 질의하는 **읽기 전용 API**(`knowledge/query.py`). 라벨은 고정 상수, 입력은 파라미터 바인딩(주입 차단), 반환은 전부 JSON 직렬화 가능한 dict/list. 핵심은 **직접매핑 우선·브리지 폴백** 패턴을 함수에 박아둔 것:
```python
from knowledge import query
from neo4j import GraphDatabase
s = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", pw)).session()

query.cve_facts(s, "CVE-2021-44228")            # 설명·심각도·CWE
query.techniques_for_cve(s, "CVE-2021-44228")   # 후보 기법: 직접(EXPLOITED_BY) 있으면 그것만, 없으면 브리지(generic 제외)
query.technique_detail(s, "T1190")              # 기법 이름·전술·상/하위
query.techniques_for_target(s, ["CVE-2017-5638","CVE-2019-9193"])  # 다중 CVE 집계(by_cve + aggregate)
```
- 각 후보엔 `via`(direct/bridge)·`source`·`confidence`(curated 0.95 / kev 0.90 / ctid 0.70 / llm 0.50 / bridge 0.40)가 붙어 플래너가 가중치를 준다.
- 데모 CLI: `python -m knowledge.query --cve CVE-2021-44228` (NEO4J_PASSWORD 환경변수).
- 플래너 통합 지점 — 이 함수들이 반환하는 dict 를 그대로 LLM 컨텍스트에 넣거나, 팀원 플래너가 자체 Text2Cypher 를 쓰면 이걸 "올바른 질의 패턴" 레퍼런스로 삼으면 된다.

## 데이터 출처
- ATT&CK: `github.com/mitre-attack/attack-stix-data` → `enterprise-attack/enterprise-attack.json`
- CAPEC: `github.com/mitre/cti` → `capec/2.1/stix-capec.json`
- CWE: `cwe.mitre.org/data/xml/cwec_latest.xml.zip`
- NVD: `services.nvd.nist.gov/rest/json/cves/2.0` (타깃 CVE/CPE 로 질의 — 위 "NVD" 섹션)
- CISA KEV→ATT&CK(권장): `github.com/center-for-threat-informed-defense/mappings-explorer` → `mappings/kev/attack-16.1/kev-07.28.2025/enterprise/...json`
- CTID CVE→ATT&CK(레거시 2021): 같은 저장소 → `src/mapex_convert/mappings/Att&ckToCveMappings.csv`

## 검증 결과 (실데이터)
- ATT&CK: Technique 227 · SubTechnique 479 · Tactic 15 / 관계 1459
- CAPEC: 559개 / `MAPS_TO`(→기법) 272 · `HAS_ATTACK_PATTERN`(CWE→CAPEC) 1214
- 적재 후 실측(VM-A, Neo4j): `MAPS_TO` 256 · `HAS_ATTACK_PATTERN` 1212 (짝 없는 id 는 조용히 스킵 — 정상)
- NVD: Log4Shell 표본으로 파서 검증 — CPE 기본 미적재(토글 on 시 `AFFECTED_BY` 생성), `vulnerable:false`·비표준 CWE 제외, 버전대 병합
- cve_attack(KEV 실데이터): 2025-07판 419개 CVE / `EXPLOITED_BY` 1177건 적재(ATT&CK v16.1), 최신 스냅샷 자동선택·출처 태깅 확인. Log4Shell → `T1190`(+4)
- generic CWE(`CWE-20` 등 10종) `is_generic` 태깅 확인 — 브리지 노이즈 제외용

## 주의
- 적재 순서 `cwe → attack → capec`(→ `nvd` → `cve_attack`): 각 관계는 양쪽 끝 노드가 있어야 붙는다(없으면 조용히 스킵).
- CVE→기법은 `cve_attack`(EXPLOITED_BY) 우선. CWE 브리지는 generic CWE 노이즈 때문에 `is_generic` 빼고 "참고"로만.
- NVD CPE 열거는 기본 미적재(`--nvd-cpe-nodes` 로 켬) — 벤더 제품 수백 개 노이즈 차단.
- 라벨·관계는 `schema.LABELS`/`RELATIONSHIPS` 허용목록으로 검사 후에만 쿼리에 끼운다(주입 차단).
- 세 그래프(지식/자산/탐색)가 같은 Neo4j를 공유 — 지식 노드엔 `episode_id`를 붙이지 않아 회차 리셋에 안 지워진다.
