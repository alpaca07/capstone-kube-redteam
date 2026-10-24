# Wave 1 취약점 카탈로그 — 정의 · 위치 · 유형

> 오늘(Wave 1) 추가한 취약점을 메인 킬체인 ①②③④ 문서와 **같은 카드 양식**
> (정의 / MITRE / 우리 환경 구현 / 왜 위험·악용 / 방어)으로 정리.
> 정답지 원본 `orchestrator/flags.py`, 실제 구성 `k8s/killchain/`, 설계 의도 [wave1-design.md](wave1-design.md).

---

## 한눈에 — "단"이 아니라 "분기·축"

메인 킬체인은 **선형 4단**(DB 한 줄 털기)이고 그대로다. Wave 1 은 ⑤⑥⑦ 새 단이 아니라,
②에서 갈라지는 **분기**와 선형 깊이와 무관한 **별도 축**을 더했다:

```
 ①T1552.001 ──▶ ②T1078 ──▶ ③T1210 ──▶ ④T1213 = DB FLAG (값, 크라운주얼)
      │            │
      │            └─▶ [호스트 탈출 분기]  T1610 ──▶ T1611 ──▶ T1005 = host FLAG (값, 크라운주얼)
      │                                   파드 배포   호스트 탈출  노드 데이터 수집
      │
      └─ (①단 보강) 평문 ConfigMap 경로도 같은 T1552.001

 [별도 축 — 선형 깊이 ①~④ 를 흐리지 않음]
   • 크라운 주얼(objective, 값 기반):  ④ DB FLAG · host 노드 FLAG
   • Discovery(탐지 전용, 차단 패치 없음):  T1046 · T1613 · T1069
```

**두 유형 구분** — ① **차단 가능**: 방어가 패치로 길을 막음(차단 효과 측정). ② **탐지 전용**:
정상 조회와 구분이 어려워 전용 차단이 없음 → 방어자는 **보고만** 하는 게 정답. "탐지 커버리지 ≠
차단 효과"라는 프로젝트 주제를 드러내는 장치(+ 방어자 과잉 패치=오탐 시험).

| 기법 | 위치 (단/축) | 유형 | 한 줄 정의 | 방어 |
|------|-------------|------|-----------|------|
| **T1610** Deploy Container | ② 분기 ①단계 | 차단 가능 | 탈취 토큰으로 k8s API 에 악성 파드 생성 | `restrict_rbac` |
| **T1611** Escape to Host | ② 분기 ②단계 | 차단 가능 | privileged/hostPath 파드로 노드 파일시스템 접근 | `restrict_pod_security`(+`delete_pod`) |
| **T1005** Data from Local System | 탈출 분기 목표 | 크라운 주얼(값) | 노드 `/etc/shopflow/host.flag` 읽어 host FLAG 획득 | (상위 T1610/T1611 차단) |
| **T1552.001** (ConfigMap) | ①단 보강 | 차단 가능 | DB 비번이 Secret 아닌 평문 ConfigMap 에 노출 | `restrict_rbac` |
| **T1046** Network Svc Discovery | Discovery 축 | 탐지 전용 | 발판에서 내부 서비스 포트 스캔 | — (보고만) |
| **T1613** Container/Resource Discovery | Discovery 축 | 탐지 전용 | 탈취 토큰으로 네임스페이스/리소스 열거 | — (보고만) |
| **T1069** Permission Groups Discovery | Discovery 축 | 탐지 전용 | `auth can-i` 로 자기 권한 열거 | — (보고만) |

---

# 호스트 탈출 분기 (②에서 갈라짐)

과권한 SA(②)에서 갈라져 **컨테이너를 벗어나 노드(호스트)를 장악**하는 경로. 파드를 띄우고
(T1610) → 그 파드로 호스트를 읽고(T1611) → 노드 데이터를 수집(T1005)해 host FLAG 를 얻는다.

## T1610 · Deploy Container — 악성 파드 배포

**정의**: 공격자가 (훔친) 자격증명으로 쿠버네티스 API 에 **직접 파드(컨테이너)를 생성**하는 것.
소프트웨어 익스플로잇이 아니라 **과한 권한으로 API 를 정상 호출**해 '무기화된' 파드를 띄우는 게
핵심. `pods: create` 권한이 공격자 손에 들어가면 성립.

**MITRE**: `T1610` Deploy Container (실행 수단은 `T1078` Valid Accounts — 탈취한 admin-sa 토큰)

**우리 환경 구현**: ② 과권한 보강으로 ClusterRole `admin-tools` 에 추가 (`killchain/10-admin-overperm-rbac.yaml`):
- `pods` **[get, list, create]** ← ★ `create` 가 핵심 (파드 생성 가능)
- `pods/log` **[get]** — 띄운 파드의 **stdout(로그) 회수**용 유일한 비대화식 경로 (exec 은 SPDY 라 발판 `wget` 으로 못 씀)
- 재사용 가능한 `admin-sa-token` **classic(비만료) Secret** — 파드 자동마운트 bound 토큰은 못 꺼내므로, API 를 직접 칠 Bearer 토큰 확보용

**왜 위험 / 악용**: ②에서 `admin-dashboard` 의 confused-deputy(`/internal/secret/internal/admin-sa-token`)
로 admin-sa 토큰을 탈취 → 그 Bearer 토큰으로 `POST /api/v1/namespaces/default/pods` 에
**privileged·hostPath 파드**를 생성. 이게 다음 단계(T1611) 호스트 탈출의 **발판**. 즉 ②의 토큰
하나로 "아래로(③④ DB)"가 아니라 "밖으로(호스트)" 갈 수 있게 열어줌.

**방어 (정답)**: `restrict_rbac` — `admin-tools-binding` ClusterRoleBinding 삭제. 바인딩이 사라지면
그 토큰의 `pods create` 가 **403** → 파드 생성 자체가 막힘. (② Secret 조회·T1552.001 ConfigMap
경로도 같은 바인딩이라 **한 번에** 닫힘.) (`defense-reference/rbac-reduced.yaml`)

## T1611 · Escape to Host — 컨테이너 탈출 → 노드 장악

**정의**: 컨테이너(파드) 안에 갇혀야 할 코드가 **격리 경계를 뚫고 노드(호스트 머신)의 파일시스템·
자원에 접근**하는 것 = **컨테이너 탈출**. "파드를 장악해도 샌드박스 안에 갇힌다"는 쿠버네티스 보안
핵심 가정이 깨지는 **최악의 상승** — 노드를 먹으면 그 위 모든 파드·노드 자격증명까지 노출.

**MITRE**: `T1611` Escape to Host

**우리 환경 구현**: k3s 기본값은 **PodSecurity enforce 미강제** → `privileged: true` + `hostPath: /`
파드가 admission 을 **그대로 통과**. 공격자는 `attack-reference/escape-pod.yaml` 류를 배포(베이스라인
미적용 — 공격자가 런타임에 만드는 산출물):
- `privileged: true` ← 컨테이너 보안 제약 해제
- `hostPath: / → /host` ← ★ 노드 디스크 전체를 파드 안으로. `/host/etc/...` 읽으면 노드 진짜 파일

**왜 위험 / 악용**: T1610 으로 띄운 파드가 `/host/etc/shopflow/host.flag`·`/host/etc/shadow` 등
**노드 파일을 직접 read**. 컨테이너 경계가 사라진 상태. Falco 가 `Escape to host filesystem` 룰로
탐지(컨테이너에서 호스트 민감경로 read = 전형적 탈출 시그니처).

**방어 (정답)**: `restrict_pod_security` — 대상 네임스페이스에 PodSecurity `enforce=baseline` 라벨.
baseline 은 privileged/hostPath/host-네임스페이스를 **admission 에서 거부**하되 정상 ShopFlow 파드
(비-privileged·hostPath 없음)는 통과 → **가용성 유지하며 탈출 파드만 차단**. (`restricted` 를 넓게
걸면 정상 파드까지 깨지는 과잉차단 함정이라 baseline 이 기본값.) 보조로 `delete_pod`. (patcher
`render_op` 로 ns 라벨 머지-apply, 전용 defense-reference 파일 없음)

## T1005 · Data from Local System — 호스트 FLAG (크라운 주얼)

**정의**: 침해한 **로컬 시스템(여기선 노드 호스트)에서 목표 데이터를 수집**하는 것. 이 분기의
**최종 목표(크라운 주얼)** — 호스트를 실제 장악했는지를 '값'으로 증명하는 지점.

**MITRE**: `T1005` Data from Local System (④ DB 의 `T1213` 과 짝 — "③측면이동→④수집"처럼 "T1611탈출→T1005수집")

**우리 환경 구현**: 노드 로컬 파일 `/etc/shopflow/host.flag`(권한 600, root 전용)에 **랜덤 `FLAG{...}`**
를 심음. T1611 로 호스트에 닿아야만 읽힘. `k8s/flags/generate-flags.sh` 가 노드에 심고(sudo), 같은
값을 VM C 심판이 읽을 `flag-values.secret` 에도 기록(값 대조용).

**왜 위험 / 악용**: 탈출 파드 command 가 `/host/etc/shopflow/host.flag` 를 읽어 stdout 으로 흘림 →
공격자가 `pods/log` 로 회수 → 그 값을 보고. 실제 공격이면 여기서 노드 시크릿·kubelet 자격증명·
SSH 키를 털게 됨.

**채점**: **값 기반 objective** — 공격자 보고값을 심어둔 값과 대조(`match_value`)해 'host' 달성
판정. ④ DB FLAG 와 **별개 축**이고, 비-digit id 라 선형 깊이 ①~④ 를 바꾸지 않음.

**방어 (정답)**: T1005 자체엔 전용 차단이 없고, **상위 T1610/T1611 을 막으면 호스트 FLAG 도 못
읽음**(파드를 못 띄우거나 탈출이 admission 거부). → `restrict_rbac` + `restrict_pod_security`.

---

# 다경로 크레덴셜 (①단 보강)

## T1552.001 · Unsecured Credentials: Credentials In Files — 평문 ConfigMap

**정의**: 자격증명이 **안전한 저장소(Secret)가 아니라 평문 파일/설정에 노출**된 것. 여기선 DB
접속정보가 Secret 이 아닌 **평문 ConfigMap** 에 박혀 있음. ①단과 같은 T1552.001 이라 별도 flag
없이 **①을 보강**(과권한은 Secret 만의 문제가 아님을 가르침).

**MITRE**: `T1552.001` Unsecured Credentials: Credentials In Files

**우리 환경 구현**: 레거시 백엔드가 DB 접속정보를 ConfigMap `backend/legacy-db-config` 에 평문으로
둠 (`killchain/20-plaintext-configmap-creds.yaml`):
- `DB_PASSWORD: devpassword123` ← ★ Secret 의 진짜 비번과 동일 (base64 도 아닌 순수 평문)
- `NOTE: "TODO(legacy): move to Secret before prod — 아직 안 옮김"` (급하게 넣고 안 옮긴 전형적 실수로 위장)

**왜 위험 / 악용**: ①의 기존 경로(런북→admin 콘솔로 Secret 읽기)와 **독립된 둘째 열쇠**. 과권한
admin-sa(`configmaps get/list` 보유)로 `GET .../namespaces/backend/configmaps/legacy-db-config`
→ 같은 DB 비번 획득 → ④로 직행. 교훈: **과권한은 Secret 만의 문제가 아니다(ConfigMap 으로도 샌다)**.

**방어 (정답)**: `restrict_rbac` — admin-tools 바인딩 삭제/권한 축소로 `configmaps` 조회 권한도 함께
제거. Secret 만 잠가선 못 막고, **조회 권한 자체**를 줄여야 Secret·ConfigMap 두 경로가 함께 닫힘.
(`defense-reference/rbac-reduced.yaml`)

---

# Discovery 축 (탐지 전용)

**정의**: 공격자가 환경을 **정찰(열거)**하는 기법들. 정상 조회와 구분이 어렵고 **전용 차단 패치가
없음** → 방어자는 **탐지해서 보고만** 하는 게 정답(억지 차단은 가용성만 해침). "탐지 커버리지 ≠
차단 효과" 주제 + 방어자 과잉패치(오탐) 시험 장치.

| 기법 | 정의 | god-view 신호 |
|------|------|--------------|
| **T1046** Network Service Discovery | 발판에서 내부 서비스 포트 스캔(nc/nmap) | Falco `Port scan from foothold` |
| **T1613** Container and Resource Discovery | 탈취 토큰으로 네임스페이스/리소스 열거 | 감사 `admin-sa list namespaces` |
| **T1069** Permission Groups Discovery | `auth can-i`(self-subject review)로 자기 권한 열거 | 감사 `create selfsubject*reviews` |

**방어 (정답)**: **없음(보고만)**. 실질 위협 때문에 건 NetworkPolicy·RBAC 축소가 탐색도 부수적으로 줄일 뿐.

---

## 핵심 연결고리 (시너지)

- **토큰 하나 → 두 방향**: ②에서 confused-deputy 로 훔친 `admin-sa` 토큰이 "아래로(③④ DB)"와
  "밖으로(T1610→T1611→T1005 호스트)" 둘 다의 열쇠. 분기가 ②에 걸리는 이유.
- **방어 한 수 → 다중 봉쇄**: `restrict_rbac`(admin-tools-binding 삭제) 하나가 ②(secret) +
  T1610(pods create) + T1552.001(configmap) + T1613(열거)를 **동시에** 끊는다. 실험에서 관찰된
  공진화의 핵심(방어의 '한 수'가 공격면 여럿을 닫음).
- **방어 어휘(패치) 전체**: `add_networkpolicy`(③) · `restrict_rbac`(②·T1610·T1552.001·T1613) ·
  `restrict_pod_security`(T1611, Wave1 신규) · `delete_pod`(보조).
