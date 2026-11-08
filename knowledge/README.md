# knowledge — 지식 그래프 ETL

공식 분류체계(MITRE ATT&CK · CAPEC · CWE · NVD CVE)와 CVE→ATT&CK 직접 매핑(CTID/큐레이트)을 우리 KG 스키마로
Neo4j에 적재한다. **대상 안 가리는 재사용 지식 라이브러리** — 심어둔 킬체인에 맞추지 않는다.
1차 플래너가 이 그래프를 검색해 어떤 타깃이든 공격 기법을 추론한다.

## 구성
| 파일 | 역할 |
|---|---|
| `schema.py` | KG 라벨·관계 허용목록 + 공식 소스→KG 매핑 계약(이 파일이 설계 핵심) |
| `graph_writer.py` | 라벨별 `UNWIND` 멱등 `MERGE` 적재 엔진(파라미터 바인딩, 세션 주입) |
| `sources.py` | 소스별 `parse_*(raw) -> (nodes, rels)` — ATT&CK/CAPEC/NVD/cve_attack. generic CWE 꼬리표·NVD CPE 토글도 여기 |
| `__main__.py` | CLI — 받기(fetch)·접속(connect)·적재 |
| `cve_attack.example.json` | CVE→Technique 큐레이트 매핑 템플릿(복사해서 VM-B 타깃으로 채움) |

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
**왜 필요한가**: `CVE→CWE→CAPEC→Technique` 브리지는 NVD가 generic CWE(예 `CWE-20`)를 자주 달아서 엉뚱한 기법으로 샌다. 실측에서 Log4Shell이 `CWE-20 → T1539`(쿠키 탈취) 같은 무관한 경로만 냈다. 그래서 **전문가가 매긴 CVE→Technique 직접 매핑**(`EXPLOITED_BY`)을 우선 경로로 둔다.
```bash
# 큐레이트(권장): VM-B 타깃 CVE 의 정확한 기법. cve_attack.example.json 복사해서 채움
python -m knowledge --sources cve_attack --cve-map ./kg_data/cve_attack.json
# + 재사용 베이스라인: CTID CSV(839개 CVE, 2021판) 를 data-dir 에 두면 함께 적재
python -m knowledge --sources cve_attack --data-dir ./kg_data   # <data-dir>/Att&ckToCveMappings.csv
```
- CTID CSV 받기: `git clone --depth 1 github.com/center-for-threat-informed-defense/mappings-explorer` → `src/mapex_convert/mappings/Att&ckToCveMappings.csv` 복사.
- **CTID는 2021판이라 Log4Shell이 없다** → 최신·누락 CVE는 큐레이트 파일로 메운다.
- generic CWE 노드엔 `is_generic=true` 꼬리표가 붙는다 → 플래너 질의가 브리지에서 뺄 때 `WHERE NOT coalesce(w.is_generic,false)`.
- 적재는 **attack 다음**(Technique 노드 선행). 전체: `--sources cwe,attack,capec,nvd,cve_attack`.

## 데이터 출처
- ATT&CK: `github.com/mitre-attack/attack-stix-data` → `enterprise-attack/enterprise-attack.json`
- CAPEC: `github.com/mitre/cti` → `capec/2.1/stix-capec.json`
- CWE: `cwe.mitre.org/data/xml/cwec_latest.xml.zip`
- NVD: `services.nvd.nist.gov/rest/json/cves/2.0` (타깃 CVE/CPE 로 질의 — 위 "NVD" 섹션)
- CTID CVE→ATT&CK: `github.com/center-for-threat-informed-defense/mappings-explorer` → `src/mapex_convert/mappings/Att&ckToCveMappings.csv`

## 검증 결과 (실데이터)
- ATT&CK: Technique 227 · SubTechnique 479 · Tactic 15 / 관계 1459
- CAPEC: 559개 / `MAPS_TO`(→기법) 272 · `HAS_ATTACK_PATTERN`(CWE→CAPEC) 1214
- 적재 후 실측(VM-A, Neo4j): `MAPS_TO` 256 · `HAS_ATTACK_PATTERN` 1212 (짝 없는 id 는 조용히 스킵 — 정상)
- NVD: Log4Shell 표본으로 파서 검증 — CPE 기본 미적재(토글 on 시 `AFFECTED_BY` 생성), `vulnerable:false`·비표준 CWE 제외, 버전대 병합
- cve_attack: 큐레이트+CTID 표본으로 `EXPLOITED_BY` 생성·카테고리/출처 태깅 검증. generic CWE(`CWE-20` 등 10종) `is_generic` 태깅 확인

## 주의
- 적재 순서 `cwe → attack → capec`(→ `nvd` → `cve_attack`): 각 관계는 양쪽 끝 노드가 있어야 붙는다(없으면 조용히 스킵).
- CVE→기법은 `cve_attack`(EXPLOITED_BY) 우선. CWE 브리지는 generic CWE 노이즈 때문에 `is_generic` 빼고 "참고"로만.
- NVD CPE 열거는 기본 미적재(`--nvd-cpe-nodes` 로 켬) — 벤더 제품 수백 개 노이즈 차단.
- 라벨·관계는 `schema.LABELS`/`RELATIONSHIPS` 허용목록으로 검사 후에만 쿼리에 끼운다(주입 차단).
- 세 그래프(지식/자산/탐색)가 같은 Neo4j를 공유 — 지식 노드엔 `episode_id`를 붙이지 않아 에피소드 리셋에 안 지워진다.
