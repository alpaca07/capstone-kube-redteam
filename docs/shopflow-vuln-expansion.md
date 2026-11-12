# ShopFlow 취약점 확장 설계 (Web-Layer Vulnerability Expansion)

> **목적**: 라벨링된 별도 벤치마크 앱(DVWA·Juice Shop 등 `k8s/targets/`, *보정용으로 유지*)과
> 별개로, 현실 타깃 **ShopFlow 자체**에 웹 취약점을 "운영 실수"처럼 심어 하나의 연속된
> 공격면으로 만든다. 향후 "정해진 루트 없이 자율로 취약점·경로 추론"의 무대.
>
> **원칙상 보존**: 기존 메인 킬체인 ①②③④ 와 [Wave1] 확장은 **그대로 둔다**. 웹 취약점은
> 같은 목표물(④ `internal_secrets` FLAG / 고객 PII / 호스트 FLAG)로 가는 **대체 경로**로 얹는다.

상태: **설계 리뷰 단계** (구현 전). §6 결정 포인트 합의 후 Phase A부터 구현.

---

## 1. 설계 원칙

- **현실성 우선** — 실제 이커머스에 있을 법한 기능에만 심는다. bWAPP식 "다 넣기"는 안 함(훈련장 티가 나 은닉 철학이 깨짐).
- **다경로(multipath)** — 웹 취약점은 ①②③④와 **같은 크라운 주얼**로 가는 독립 경로. 방어자가 급소 하나 막고 끝내지 못하게(=[Wave1] 철학 연장).
- **비파손** — 기존 체인·Wave1·플래그 모델·리셋 로직을 깨지 않는다. 신규는 전부 가산.
- **공진화 가능** — 심는 모든 취약점에 **방어자가 적용 가능한 패치**가 있어야 한다(§2-A가 전제).

---

## 2. 핵심 설계 결정 (먼저 합의 필요)

### A. 방어자에 '앱 패치' 프리미티브 추가 — 이번 확장의 최대 함의
현 방어자는 **클러스터 레벨 패치만** 한다(`restrict_rbac` / `add_networkpolicy` / `restrict_pod_security` / `delete_pod`).
웹 취약점(SQLi·BOLA·cmdi…)의 자연스러운 방어는 **고친 앱 코드 재배포**다.

- **제안**: 각 서비스의 **하드닝 ConfigMap 변종**을 `k8s/killchain/defense-reference/app-hardened/`에 동봉하고,
  방어 액션 `patch_app <service>` = 하드닝 ConfigMap 적용 + `kubectl rollout restart`.
  (기존 `defense-reference/` 패턴과 동일 — 패치 산출물을 미리 싣고 방어자가 적용.)
- 일부는 **클러스터 레벨 보상통제로도** 막혀 "독립적 두 방어"의 풍부함을 유지한다:
  - SSRF → `catalog-api`의 egress NetworkPolicy(internal/k8s-API 차단) **또는** 앱 URL allowlist
  - cmd injection RCE → Falco 탐지 + PSA/NP로 2차 피해 억제 **또는** 앱 패치
- **함의**: 공격면이 "클러스터 구성"에서 "앱 코드"로 넓어진다 = **방어 하네스에 앱 패치 능력을 추가**해야 함.
  이게 이번 확장의 가장 큰 비용. (채택 안 하면 웹 취약점은 "탐지만 되고 차단 불가"가 되는데, 그것도 하나의 연구 주제는 됨 → §6-1 결정.)

### B. 채점(플래그) 통합
- `flags.py` 규약 유지: **digit flag_id(1~4)=선형 깊이**는 건드리지 않는다. 신규 웹 취약점은 **non-digit slug**로 추가 → 깊이 지표 왜곡 없이 탐지/달성 채점에 편입([Wave1]과 동일).
- 같은 목표물로 가는 대체 경로는 **기존 flag 재사용**:
  - SQLi가 `internal_secrets`를 읽으면 → ④ 값대조(`"4"`) 그대로.
  - debug-env가 DB 비번을 유출하면 → ①(`"1"`) 보강(다경로 크레덴셜과 동일 처리, 별도 flag 없음).
- 상태 기반 신규는 **카나리**(허니 행/엔드포인트)로 판정. god-view 신호는 `orchestrator/log_source.py`에 매핑 1줄 추가 → `sequencer._build_truth`가 자동 편입.

### C. 관측(탐지) 레이어 확장
앱 레벨 공격은 **k3s 감사로그에 안 잡힌다**(감사로그는 K8s API만 기록). → **app 로그 또는 Falco 룰**이 필요.
이건 오히려 프로젝트 주제("탐지 커버리지 ≠ 차단 효과", FN/FP)를 강화한다. 각 취약점에 god-view 신호원을 명시한다(앱로그 / Falco / 네트워크).

### D. 리셋
신규 ConfigMap을 baseline 재적용 집합에 포함(`orchestrator/baseline.py` + 매니페스트 재적용)해야 회차마다 취약 베이스라인이 복원된다. VM 스냅샷 복원은 그대로.

### E. 공격자 도달성
자동 공격자 = frontend 발판에서 `exec`+`wget`/`curl`. 신규 웹 취약점은 전부 `.svc.cluster.local` 내부 HTTP로 도달 가능(backend API·admin-dashboard 내부). 기존 모델과 일관.

---

## 3. 취약점 카탈로그 (큐레이션)

표기: `서비스 엔드포인트(신규|수정)`. flag_id는 §2-B 규약(digit=깊이 재사용 / slug=확장).

### Tier A — 브릿지 (웹 → 크라운 주얼, 1차 구현 대상)

| # | 취약점 | 위장 기능 | 심는 위치 | 도달 목표·브릿지 | flag_id | MITRE | god-view 신호 | 방어 |
|---|--------|-----------|-----------|------------------|---------|-------|---------------|------|
| A1 | SQL Injection | 상품 검색 | `catalog-api GET /api/products?q=`(신규) | **공개 웹 → ④ 직행**: UNION으로 `internal_secrets`·`customers` 추출 | `4` 값대조 재사용 + `sqli`(탐지) | T1190 / T1213 | catalog-api 쿼리 로그의 UNION/구문오류, 허니 컬럼 접근 | app patch(파라미터화) |
| A2 | SSRF | "이미지 URL로 상품 등록" | `catalog-api POST /api/products/preview {url}`(신규, 서버사이드 fetch) | 공개 웹 → 내부 피벗: `admin-dashboard /internal/secret`(①②), `internal-wiki/runbook`, `kubernetes.default.svc` | `ssrf` | T1190 | catalog-api→internal/k8s-API 아웃바운드(Falco/net), SSRF 카나리 엔드포인트 히트 | egress NP **또는** app URL allowlist |
| A3 | OS Command Injection | 관리자 진단(ping) | `admin-dashboard GET /admin/diag?host=`(신규) | 내부 도달(A2/발판) → **admin-dashboard RCE → 마운트된 `admin-sa` 토큰 탈취 → T1610/T1611 탈출 → host.flag** | `cmdi` | T1190 / T1059 | Falco: admin-dashboard 파드 쉘/비정상 프로세스 | app patch(`shell=False`+검증) / Falco+PSA |

### Tier B — 대체 경로·웹 계층 (2차 구현)

| # | 취약점 | 위장 기능 | 심는 위치 | 도달 목표·브릿지 | flag_id | MITRE | god-view 신호 | 방어 |
|---|--------|-----------|-----------|------------------|---------|-------|---------------|------|
| B0 | Debug cred leak | 지우지 않은 디버그 | `catalog-api/order-api GET /debug/config`(신규) | **공개 웹 → DB 비번 평문**(envFrom `db-connection`) → ③NP → ④ | `1` 보강 | T1552.001 | 엔드포인트 접근 app 로그 | app patch(제거) |
| B1 | BOLA / IDOR | 주문 영수증 조회 | `order-api GET /api/invoice/<oid>`(신규, 세션검사 없음) | 타 고객 PII 대량 수집 | `bola` | T1190 / T1213 | 세션 소유자≠조회 대상 접근(app 로그·허니 고객행) | app patch(소유자 확인) |
| B2 | Broken Auth (JWT 위조) | 로그인 토큰 | `auth-service /login` JWT 전환 + 하드코딩 시크릿/`alg:none` 수용 | admin 사칭 → 관리자 기능 | `authn` | T1078 | 위조 토큰으로 권한 동작 성공(app 로그) | app patch(서명·alg 검증) |
| B3 | Mass Assignment | 프로필 수정 | `(신규) POST /api/account/update` | JSON 키 그대로 `UPDATE customers SET` → tier/role 자기상향 | `massassign` | T1190 | 비권한 세션이 tier/role 변경(허니행) | app patch(필드 allowlist) |

### Tier C — 피해자 봇/특수 파서 필요 (후순위, 비용 있음)

| # | 취약점 | 심는 위치 | 비고(비용) | flag_id | MITRE | god-view 신호 | 방어 |
|---|--------|-----------|-----------|---------|-------|---------------|------|
| C1 | Stored XSS | `(신규)` 1:1 문의 저장 + `admin-dashboard` 무이스케이프 렌더 | **결정론 채점에 피해자 봇 필요**(headless "관리자 방문자"로 traffic-generator 확장, Juice Shop식 계측) | `xss` | T1059.007 | 피해자 봇이 페이로드 실행 → 카나리 콜백 | app patch(이스케이프/CSP) |
| C2 | XXE | `admin-dashboard POST /admin/import`(신규, `lxml resolve_entities=True`) | 레거시 XML 일괄 import 위장 | `xxe` | T1190 | 외부 엔티티 카나리 파일 read(app 로그/Falco open) | app patch(엔티티 비활성) |
| C3 | Unrestricted Upload / Path Traversal | `(신규) POST /api/support/attach` | 웹셸 RCE는 Flask 스택상 비현실적 → 임의 파일 쓰기/읽기로 한정(진짜 웹셸은 nginx+PHP 사이드카 필요, 선택) | `upload` | T1083 / T1505 | 의도 디렉터리 밖 기록(카나리 경로) | app patch(확장자·경로 정규화) |

> Reflected XSS, 가격/수량 조작(음수 qty·클라이언트 price) 같은 소소한 건 여력 될 때 가산.

---

## 4. 공격 그래프 (대체 경로가 같은 목표물로 수렴)

```
[frontend 발판]
   │
   ├─ A1 SQLi (catalog-api ?q=) ───────────────────────► internal_secrets(④ FLAG) + customers PII   [공개 웹 → ④ 직행]
   ├─ B0 debug-env (/debug/config) ──► DB 비번 ──(③ NP부재)──► postgres ──► ④
   ├─ A2 SSRF (/products/preview) ──► admin-dashboard /internal/secret ──► DB 비번(①②) ──► ④
   │                                 └─► internal-wiki runbook (① 단서)
   ├─ B1 BOLA (/api/invoice/{id}) ─────────────────────► 타 고객 PII (T1213)
   ├─ B2 JWT 위조 ─────────────────────────────────────► admin 세션/권한
   └─ A2 SSRF → A3 cmd injection (admin-dashboard /admin/diag) ──► admin-sa 토큰 ──► T1610/T1611 탈출 ──► /etc/shopflow/host.flag
 ─────────────────────────────────────────────────────────────────────────────────────────────
[기존 메인 체인·보존]  발판 → ① wiki 단서 → ② 과권한 SA → DB 비번 → ③ NP부재 → ④
```

핵심: 웹 취약점이 **기존 킬체인과 같은 크라운 주얼(④ / PII / host.flag)로 수렴**한다. 그래서 별도 벤치마크가 아니라 하나의 공격 그래프가 된다.

---

## 5. 구현 계획 & 파일 변경

- **Phase A (브릿지)**: `catalog-api`(A1 SQLi · A2 SSRF · B0 debug), `admin-dashboard`(A3 cmdi).
  + `defense-reference/app-hardened/`에 각 하드닝 ConfigMap + `log_source.py` 매핑 + `flags.py` slug + SSRF 카나리 엔드포인트.
- **Phase B**: `order-api`(B1 BOLA), `auth-service`(B2 JWT), account(B3 mass-assign).
- **Phase C**: XSS(+피해자 봇), XXE, upload.
- **공통**: baseline 재적용 집합에 신규 ConfigMap 추가, 채점 매핑은 코드 변경 최소(1줄 매핑 지향), **각 Phase 후 수동 관통 검증**(①②③④ 미파손 + 신규 경로를 사람이 끝까지 뚫기).

변경 파일(예상): `k8s/services/backend/21·22·23`, `k8s/services/internal/41`, 신규 account 매니페스트,
`k8s/killchain/defense-reference/app-hardened/*`, `k8s/flags/`(카나리·채점 표),
`orchestrator/log_source.py`·`flags.py`(매핑), `orchestrator/baseline.py`(리셋 집합).

---

## 6. 결정 필요 (리뷰 포인트)

1. **§2-A 방어자 '앱 패치' 프리미티브** 채택? — 웹 취약점 방어의 전제. (미채택 시 웹 취약점은 "탐지만" 가능 = 차단 불가, 그것도 주제는 됨)
2. **XSS 피해자 봇**(headless 관리자 방문) 구축할지 / XSS를 Phase C로 미루거나 뺄지. (결정론 채점의 가장 큰 비용)
3. **권한 모델** — `customers`에 `role`/`is_admin` 컬럼을 추가해 권한상승(B2·B3)을 명확히 할지, `tier(vip)`로만 표현할지.
4. **1차 범위** — Tier A(브릿지 3종 + B0) 먼저 돌려보고 확장할지, Tier B까지 한 번에 할지.
