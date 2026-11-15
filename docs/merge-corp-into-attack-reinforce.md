# 병합 정리사항 — corp-vuln-island → attack-reinforce

- 날짜: 2026-11-15
- 방향 결정: A안 (attack-reinforce 를 단일 최신 작업 브랜치로)
- 정리·실행: 컨테이너 세션

## 결론
- 세 브랜치는 완전 선형이다: `main` ─(+165)─▶ `attack-reinforce`(e30cc61) ─(+46)─▶ `corp-vuln-island`(395a731).
- `corp-vuln-island` 가 `attack-reinforce` 를 통째로 포함한 채 46커밋 앞섰다(corp 쪽이 그간 attack-reinforce 를 2회 통합: d98e19f, ed5d3e2).
- 따라서 병합은 **fast-forward**, git 충돌 0.
- **A안**: `attack-reinforce` 를 `corp-vuln-island` 로 fast-forward → attack-reinforce 가 단일 최신 작업 브랜치. (소스 수정 = attack-reinforce 규약 유지)
- 병합 후 코드 상태에서 전체 테스트 49개 파일 전부 통과.

## 46커밋이 가져온 것 (net 34파일 +1368 / -43)
- `k8s/corp/` 신규 14파일(+1020): 취약 사내망 서버 — DMZ(Tomcat/Solr Log4Shell), 내부 존(Samba·Redis·Jenkins), 크라운 PostgreSQL 11.2, 취약 WAF(ModSecurity+CRS 3.3.0)·IDS(Suricata), 존 격리 NetworkPolicy, corp 발판(corp-ext).
- 방어/오케스트레이터/대시보드 corp 배선: 방어 관측 corp(service)+ShopFlow(app) 병존, 대시보드 타깃 선택·침투 진척 지표, corp 크라운 채점(ops_secrets)·DB로그 동기화, KG 자동저작·CVSS.
- `scripts/vmc-sync-corp-services.sh`: corp 서비스(postgres·samba·waf) 로그 sync.

## 되돌릴 점
- 없음. (아래 WAF 는 '유지' 결정)

## 결정 기록
- **WAF: DetectionOnly 유지.** 현재 `k8s/corp/dmz/60-waf.yaml:59` = `MODSEC_RULE_ENGINE=DetectionOnly`(탐지·로깅만, 차단 안 함). 넣은 커밋 0367e8a 는 "end-to-end 크라운 체인 확인용 일시 완화". 검증 단계라 유지.
  - **TODO(실공방 런 전)**: `MODSEC_RULE_ENGINE=On`(차단)으로 전환해야 WAF 가 공격자 우회 대상 방어장비로 작동한다.
- **발판 "순수 네트워크" 확정.** 11b04f6: corp 발판 파드에서 in-pod API 토큰 미마운트(`automountServiceAccountToken: false`) + recon ClusterRole 제거. net: VM A 가 밖에서 `corp-foothold-sa` 토큰으로 exec 만, 파드 안엔 토큰 없음. (초기 d0f0b3f 의 열거권한 부여를 뒤집은 최종본)
- **:8080 WAF 넛지 유지.** 395a731: Tomcat=8080 추론 공격(PUT 웹셸 CVE-2017-12615)도 WAF 단일 진입점으로 받음.
- **corp→ShopFlow egress 차단 유지.** 1506b1a: 교차 시나리오에서 공격자 집중.
- **공격 백엔드 핑거프린트 유지.** bd0b473: `attacker/asset_extract.py` 에 WAF 뒤 제품(tomcat·solr) 배너 핑거프린트, `attacker/intent_runner.py` 에 배선(실사용). 공격쪽 영역.

## 이미 정리됨 (참고)
- 공격 입력취약점 넛지(e9abab4 "플래너 입력취약점 intent", 5eec423 "정찰 입력취약점 유도") → 롤백(89af9f3, 41fe47a). net 0, 정찰 프롬프트에 잔존 없음.
- 구 target-aware 대시보드 헬퍼 → d8b3dbf 제거.

## 병합 후 상태
- `attack-reinforce` = 395a731 + 본 정리사항 커밋. 단일 최신 작업 브랜치.
- `corp-vuln-island`(395a731)는 attack-reinforce 에 완전 포함 → 삭제하거나 historical 로 보존 가능(코드 차이 없음).
- 반영 경로: 컨테이너 push → VM A·B·C·호스트(spartzros)는 pull.
