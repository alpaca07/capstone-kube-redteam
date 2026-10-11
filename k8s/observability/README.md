# k8s/observability — 관측 (환경 구축 5단계, 관측 파트)

방어자(VM B 하네스)의 **"눈"**을 세팅한다. 관측은 세 소스로, 레벨이 다르다.

| 소스 | 레벨 | 보는 것 | 설치 |
|------|------|---------|------|
| **k3s 감사로그** | API 서버 | 누가 무슨 API를 호출했나 (secret 조회, exec, RBAC, 쓰기) | `enable-audit.sh` (k3s 재기동) |
| **Falco** | 런타임/syscall | 파드에서 셸·수상한 프로세스·파일/네트워크 | `install-falco.sh` (DaemonSet) |
| **상태 diff** | 클러스터 상태 | baseline 대비 바뀐 리소스 | 방어자 하네스 코드(에이전트 단계) |

**중요:** 탐지는 **불완전**하다(놓침 FN / 오탐 FP). 그게 설계 의도 — 방어자가 부분적·노이즈 낀
관측에서 공격을 추론해야 공수 공진화가 의미 있다. 아래 매핑에서 블라인드 스팟을 명시한다.

## 킬체인 탐지 매핑

| 단계 | 감사로그 | Falco | 블라인드 스팟(FN) |
|------|----------|-------|-------------------|
| **①** 크레덴셜 | secret 조회 경로는 보임 / **wiki 유출은 안 보임**(HTTP) | 파드 내 curl·셸 | wiki 열람 자체 → 거의 안 잡힘 |
| **②** 과권한 SA | ★ `admin-sa`의 secret get/list가 **명확히** 찍힘 | SA 토큰 파일 접근 | 거의 없음(제일 잘 잡히는 단계) |
| **③** 측면이동 | pod-to-pod 네트워크 **안 보임** | 수상한 아웃바운드 연결(커스텀 룰 시) | 정상처럼 보이는 TCP는 놓칠 수 있음 |
| **④** 데이터탈취 | DB 쿼리 **안 보임**(K8s API 아님) | DB 접속 프로세스 기동 | SELECT 자체는 안 보임 → 심판 god-view로만 확정 |

→ 방어자 입장에서 **②가 가장 선명**하고, ①·③·④엔 사각이 있다. 공격자가 어떤 경로를 타느냐에
따라 방어자가 보는 그림이 달라지는 게 핵심.

## 활성화 (VM B)

```bash
# 1) 감사로그 (sudo, k3s API 재기동 ~15초)
bash k8s/observability/enable-audit.sh
# 2) Falco (DaemonSet, 인터넷 필요)
bash k8s/observability/install-falco.sh
```

## 검증

```bash
# 감사로그: ② 탐지 — admin-sa가 DB secret 조회 → 로그에 기록
kubectl -n internal exec deploy/admin-dashboard -- sh -c \
  'curl -sk -H "Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" \
   https://kubernetes.default.svc/api/v1/namespaces/database/secrets/postgres-credentials' >/dev/null
sudo grep 'admin-sa' /var/lib/rancher/k3s/server/logs/audit.log | tail -1

# Falco: 파드에 셸 뜨면 경고
kubectl -n frontend run t --rm -it --image=busybox --restart=Never -- sh   # exit로 나오기
kubectl -n falco logs -l app.kubernetes.io/name=falco -c falco --tail=20 | grep -i shell
```

## 다음 (방어자 하네스 코드 — 에이전트 단계)
이 소스들을 수집 → **1차 필터**(baseline diff + 룰로 노이즈 축소) → **LLM 트리아지**(일반 모델이
"공격인가? 어떤 기법인가?" 추론) → 패치. 수집·필터·트리아지는 defender 하네스 코드에서 구현.
