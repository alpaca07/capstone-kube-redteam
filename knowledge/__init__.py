"""knowledge — 지식 그래프 구축(ETL) 패키지 뼈대.

공식 분류체계(ATT&CK·CAPEC·CWE, 나중에 NVD CVE/CPE)를 우리 KG 스키마로 옮겨
Neo4j에 적재한다. '대상 안 가리는 재사용 지식'이 목적 — 심어둔 킬체인에 맞추지 않는다.

구성:
  schema.py        KG 라벨·관계 허용목록 + 공식 소스→KG 매핑 계약(이 파일이 핵심 설계)
  graph_writer.py  (label/type별) 멱등 MERGE 적재 엔진 — Neo4j 세션 이음새
  sources.py       소스별 parse(raw) -> (nodes, rels) — 실제 필드 추출은 적재 세션에서 채움
  __main__.py      CLI: python -m knowledge --sources attack,capec,cwe [--dry-run]

이 패키지는 '틀'이다. 실제 데이터 다운로드·적재 실행은 개발모드(인터넷 ON) 다른 세션에서.
"""

__all__ = ["schema", "graph_writer", "sources"]
