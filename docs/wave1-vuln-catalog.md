# Wave 1 취약점 카탈로그 — 정의 · 위치 · 유형

> 오늘(Wave 1) 추가한 취약점을 "무엇인지 · 어느 단/축에 있는지 · 어떤 종류인지" 기준으로 정리.
> 설계 의도·배선 방법은 [wave1-design.md](wave1-design.md), 변천사는 [CHANGELOG.md](CHANGELOG.md).
> 정답지 원본은 `orchestrator/flags.py`, 실제 취약 구성은 `k8s/killchain/`.

---

## 0. 먼저 — "단"이 아니라 "분기·축"이다

메인 킬체인은 **선형 4단**(DB 한 줄 털기)이고, 이건 그대로다:

```
 ①T1552.001  ──▶  ②T1078   ──▶  ③T1210      ──▶  ④T1213
 크레덴셜 노출       과권한 SA        NetworkPolicy 부재     내부 Secret 탈취
 (평문 단서)        (admin-sa)      (DB 측면이동)          = DB FLAG(값)
```

Wave 1 이 더한 건 **⑤⑥⑦ 같은 새 선형 단이 아니라**, 기존 단에서 갈라지는 분기와
선형 깊이와 무관한 별도 축이다. 한눈에:

```
 ①T1552.001 ──▶ ②T1078 ──▶ ③T1210 ──▶ ④T1213 = DB FLAG(값, 크라운주얼)
      │            │
      │            └─▶ [호스트 탈출 분기]  T1610 ──▶ T1611 ──▶ T1005 = host FLAG(값, 크라운주얼)
      │                                   파드 배포   호스트 탈출  노드 데이터 수집
      │
      └─ (①단 보강) 평문 ConfigMap 경로도 같은 T1552.001

 [별도 축 — 선형 깊이 ①~④ 를 흐리지 않음]
   • 크라운 주얼(objective, 값 기반):  ④ DB FLAG  ·  host 노드 FLAG
   • Discovery(탐지 전용, 차단 패치 없음):  T1046  ·  T1613  ·  T1069
```

**핵심 구분 — 2가지 유형**
- **차단 가능(blockable)**: 방어자가 패치로 길을 막을 수 있다 → "차단 효과"를 측정.
- **탐지 전용(detect-only)**: 정상 조회와 구분이 어려워 전용 차단이 없다 → 방어자는
  **보고만** 하는 게 정답. "탐지는 되지만 못 막는" 위협으로, **탐지 커버리지 ≠ 차단 효과**
  라는 프로젝트 주제를 보이는 장치(+ 방어자의 과잉 패치=오탐을 시험).

---

## 1. 요약 표

| 기법 | 위치 (단/축) | 유형 | 한 줄 정의 | 방어 패치 |
|------|-------------|------|-----------|----------|
| **T1610** Deploy Container | ②에서 분기 ①단계 | 차단 가능 | 탈취한 admin-sa 토큰으로 k8s API 에 악성 파드를 생성 | `restrict_rbac` |
| **T1611** Escape to Host | ②에서 분기 ②단계 | 차단 가능 | privileged/hostPath 파드로 노드(호스트) 파일시스템 접근 | `restrict_pod_security`(+`delete_pod`) |
| **T1005** Data from Local System | 탈출 분기의 목표 | 크라운 주얼(값) | 노드 파일 `/etc/shopflow/host.flag` 를 읽어 host FLAG 획득 | (상위 T1610/T1611 차단 시 봉쇄) |
| **T1552.001** (ConfigMap) | ①단 보강 | 차단 가능 | DB 접속정보가 Secret 아닌 **평문 ConfigMap** 에 노출 | `restrict_rbac` |
| **T1046** Network Service Discovery | Discovery 축 | 탐지 전용 | 발판에서 내부 서비스 포트 스캔 | — (보고만) |
| **T1613** Container/Resource Discovery | Discovery 축 | 탐지 전용 | 탈취 토큰으로 네임스페이스/리소스 열거 | — (보고만) |
| **T1069** Permission Groups Discovery | Discovery 축 | 탐지 전용 | `auth can-i`(self-subject review)로 권한 열거 | — (보고만) |

> 이 외에 탈출 분기를 "가능하게 만드는" 구성요소(과권한 보강·비만료 토큰·confused-deputy·호스트 FLAG 설치)는 §4.

---

## 2. 호스트 탈출 분기 (②에서 갈라짐)

과권한 SA(②)에서 갈라져 **컨테이너를 벗어나 노드(호스트)를 장악**하는 경로. 두 기법이
순서대로 엮인다: 파드를 띄우고(T1610) → 그 파드로 호스트를 읽는다(T1611) → 노드 데이터를
수집(T1005)해 host FLAG 를 얻는다.

### 2-1. T1610 — Deploy Container (악성 파드 배포)
- **위치/유형**: ②에서 분기한 첫 단계 · 차단 가능
- **정의**: 과권한 `admin-tools` ClusterRole 에 `pods: create` 가 붙어 있어, 탈취한 admin-sa
  토큰으로 k8s API 에 파드를 직접 POST 할 수 있다. (`k8s/killchain/10-admin-overperm-rbac.yaml`)
- **공격 경로**: admin-sa 토큰 → `POST /api/v1/namespaces/default/pods` 로 privileged·hostPath 파드 생성.
- **god-view 신호**: 감사로그 `admin-sa create pods` (정상 트래픽엔 없는 공격자 전용 신호).
- **방어**: `restrict_rbac` — `admin-tools` 바인딩을 삭제하면 `pods create` 가 403 → 봉쇄.

### 2-2. T1611 — Escape to Host (호스트 탈출)
- **위치/유형**: 탈출 분기 둘째 단계 · 차단 가능
- **정의**: 네임스페이스에 PodSecurity `enforce` 가 없어 **privileged/hostPath 파드가 admission
  을 통과**한다. 노드 루트 `/` 를 파드 `/host` 로 마운트하면 컨테이너 경계를 넘어 노드 파일을 읽는다.
- **공격 경로**: 2-1 에서 띄운 파드가 `hostPath: /` → `/host` 로 노드 파일시스템 접근.
- **god-view 신호**: Falco `Escape to host filesystem`(규칙으로 탐지).
- **방어**: `restrict_pod_security` — 네임스페이스에 PodSecurity `enforce=baseline` 라벨.
  baseline 은 privileged/hostPath/host-네임스페이스를 거부하되 **정상 ShopFlow 파드(비-privileged,
  hostPath 없음)는 통과** → 가용성 유지하며 탈출 파드만 차단. (`restricted` 를 넓게 걸면 정상
  파드까지 깨지는 과잉차단 함정이라 baseline 이 기본값.) 보조로 `delete_pod`.

### 2-3. T1005 — Data from Local System (노드 데이터 수집 = host FLAG)
- **위치/유형**: 탈출 분기의 **목표(크라운 주얼, 값 기반)**
- **정의**: 노드 로컬 파일 `/etc/shopflow/host.flag`(600, root 전용)에 심어둔 랜덤 `FLAG{...}`.
  T1611 로 호스트에 닿아야만 읽을 수 있다. ④의 T1213(정보저장소 수집)과 짝 — "③측면이동→④수집"
  처럼 "T1611탈출→T1005수집".
- **채점**: `FlagSpec(flag_id="host", VALUE, mitre=T1005)`. 공격자가 보고한 '값'을 심어둔 값과
  대조(`match_value`)해 달성 판정. 비-digit id 라 선형 깊이 ①~④ 를 바꾸지 않는다.

---

## 3. 다경로 크레덴셜 (①단 보강)

### 3-1. T1552.001 — Unsecured Credentials: Credentials In Files (평문 ConfigMap)
- **위치/유형**: ①단 **보강**(새 flag 없이 기존 flag "1" 강화) · 차단 가능
- **정의**: 레거시 백엔드가 DB 접속정보를 Secret 이 아니라 **평문 ConfigMap**
  `backend/legacy-db-config` 에 박아뒀다(`appuser/devpassword123`, Secret 과 동일한 진짜 크레덴셜).
  (`k8s/killchain/20-plaintext-configmap-creds.yaml`)
- **공격 경로**: ①의 기존 경로(런북→admin-dashboard 로 Secret 읽기)와 **독립된 둘째 열쇠**.
  과권한 admin-sa(`configmaps get/list` 보유)로 이 ConfigMap 을 API 로 직접 읽어 같은 DB 비번 획득.
- **god-view 신호**: 감사로그 `admin-sa get/list configmaps`(admin-dashboard 는 configmap 을
  볼륨 마운트로 쓰지 API 로 조회하지 않으므로 공격자 전용 신호).
- **방어**: `restrict_rbac`. **교훈**: 과권한은 Secret 만의 문제가 아니다(ConfigMap 으로도 샌다)
  → Secret 잠금만으론 부족하고 조회 권한 자체를 줄여야 두 경로가 함께 막힌다.

---

## 4. 탈출 분기를 "가능하게 만드는" 구성요소

취약점 자체는 아니지만, 위 분기가 성립하려면 필요한 받침돌들(모두 `10-admin-overperm-rbac.yaml`
+ 환경에 포함):

- **`admin-tools` ClusterRole 과권한 보강** — 기존 `secrets/services/configmaps/namespaces get/list`
  에 더해 `pods [get,list,create]` 와 `pods/log [get]` 추가. `pods/log` 는 탈출 파드가 호스트 파일을
  stdout 으로 흘릴 때 그 로그를 회수하는 유일한 비대화식 경로(exec 는 SPDY 라 wget 불가).
- **`admin-sa-token` classic(비만료) Secret** — 공격자가 재사용 가능한 Bearer 토큰을 손에 넣어야
  API 로 파드를 만든다. 파드에 자동 마운트되는 bound 토큰은 파드 안에만 있어 못 꺼냄 → classic 필요.
- **admin-dashboard confused-deputy** — `/internal/secret/<ns>/<name>` 엔드포인트가 권한 검사 없이
  Secret 을 대신 읽어줌. 이걸로 `internal/admin-sa-token` 을 읽어 토큰 JWT 를 탈취.
- **호스트 FLAG 설치** — `k8s/flags/generate-flags.sh` 가 노드 `/etc/shopflow/host.flag` 에 랜덤
  FLAG 를 심고(sudo, 600), 같은 값을 VM C 심판이 읽을 `flag-values.secret` 에도 기록(값 대조용).

> 시너지 포인트: 방어 `restrict_rbac`(바인딩 삭제) 하나가 ②(secret 조회) + T1610(pods create) +
> T1552.001 ConfigMap 경로 + T1613(열거)를 **한 번에** 끊는다. 그래서 방어자의 "한 수"가 공격면
> 여러 개를 동시에 닫는 공진화가 관찰된다.

---

## 5. Discovery 축 (탐지 전용)

정찰은 정상 조회와 구분이 어렵고 전용 차단 패치가 없다 → **방어자는 보고만 하는 게 정답**.
억지로 패치하면 오탐(정밀도↓). 방어자의 과잉 반응을 시험하는 장치.

| 기법 | 정의 | god-view 신호 |
|------|------|--------------|
| **T1046** Network Service Discovery | 발판에서 내부 서비스 포트 스캔(nc/nmap) | Falco `Port scan from foothold` |
| **T1613** Container and Resource Discovery | 탈취 토큰으로 네임스페이스/리소스 열거 | 감사 `admin-sa list namespaces` |
| **T1069** Permission Groups Discovery | `auth can-i`(self-subject review)로 자기 권한 열거 | 감사 `create selfsubject*reviews` |

> 채점은 `orchestrator/log_source.py` 의 기법 매핑만으로 자동 동작한다(전용 차단 없음).
> `flags.py` 의 disc-* 는 god-view 답안지 문서화·귀속용.

---

## 6. 유형별 정리 (한 장)

**차단 가능 (방어가 길을 막음 → 차단 효과 측정)**
- T1610 Deploy Container → `restrict_rbac`
- T1611 Escape to Host → `restrict_pod_security`(+`delete_pod`)
- T1552.001 ConfigMap → `restrict_rbac`
- (기존) T1078 과권한 SA → `restrict_rbac` / T1210 NetPol → `add_networkpolicy`

**탐지 전용 (못 막음 → 보고만이 정답, 과잉 패치=오탐)**
- T1046 / T1613 / T1069 Discovery

**크라운 주얼 objective (값으로 '달성' 판정, 선형 깊이와 별개)**
- ④ DB FLAG (T1213) · host 노드 FLAG (T1005)

**방어 어휘(패치) 전체**: `add_networkpolicy`(③) · `restrict_rbac`(②·T1610·T1552.001·T1613) ·
`restrict_pod_security`(T1611, Wave1 신규) · `delete_pod`(보조)
