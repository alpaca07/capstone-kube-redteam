# k8s/services — 자체 서비스 스택 (환경 구축 2단계)

Goat(1단계) 위에, 킬체인이 관통할 **진짜 3-tier 서비스**를 세운다. 가짜 사내
"고객관리 포털"이며, 이 단계에선 **취약점 없이 정상 동작**하는 깨끗한 스택까지만 만든다.
실제 취약점(①②③)은 3단계에서 이식한다.

## 구조

| 계층 | 네임스페이스 | 파드 | 이미지 | 역할 |
|------|-------------|------|--------|------|
| 프론트 | `frontend` | `frontend-web` (nginx) | nginx:1.27-alpine | 포털 UI + `/api` 리버스 프록시, NodePort **30080** |
| 백엔드 | `frontend` | `backend` (Flask) | python:3.12-slim | 고객 조회 API, DB 연결 |
| DB | `database` | `postgres` | postgres:16-alpine | 가짜 고객 PII + **FLAG** (킬체인 ④ 목표) |
| 측정 | `frontend` | `traffic-generator` | curlimages/curl | 주기 호출 → 가용성 baseline + 배경 노이즈 |

**네임스페이스를 둘로 나눈 이유**: `frontend`(웹앱)와 `database`(DB)의 경계가
킬체인 ③(측면이동)이 넘어야 할 선이다.

## 킬체인 자리 (지금은 전부 '깨끗', 3단계에서 심음)

| 단계 | 지금 (2단계, 정상) | 3단계에서 심을 취약점 |
|------|-------------------|----------------------|
| ① 초기침투 | DB 자격증명을 Secret(env)으로 정상 주입 | 같은 값을 웹앱 소스/디버그 페이지에 **평문 노출** (T1552) |
| ② 권한상승 | 웹앱 파드에 기본 SA(권한 거의 없음) | 웹앱 SA에 **과다 RBAC** 부여 (T1078) |
| ③ 측면이동 | frontend↔database 네트워크 자유롭게 열림 | NetworkPolicy 부재를 그대로 둬 **경계 통과** 허용 (T1210) |
| ④ 목표탈취 | `internal_secrets`에 placeholder FLAG | 4단계에서 **실제 랜덤 FLAG**로 교체(gitignore secret) |

## 이미지 전략

개발 단계는 **공식 이미지 + ConfigMap 코드 주입** (커스텀 빌드/레지스트리 없이 git YAML만으로 배포).
backend는 기동 시 `pip install` 하므로 인터넷이 필요하다. **실험 직전엔**(5단계) 코드를 박은
진짜 이미지로 구워서 VM 스냅샷에 담는다(인터넷 OFF 대비).

## 배포 / 검증 / 정리

```bash
# VM B, 레포 루트에서
git pull
bash k8s/services/setup-services.sh

# 파드 확인 (backend는 pip 설치로 ~30초+ 걸림)
kubectl get pods -n database
kubectl get pods -n frontend

# 브라우저:  http://<VM B IP>:30080   → 고객 포털 (목록 클릭하면 상세+주민번호)
# 가용성 로그:
kubectl -n frontend logs deploy/traffic-generator --tail=5   # list=200 detail/..=200

# DB에서 FLAG 자리 직접 확인(심판 관점):
kubectl -n database exec deploy/postgres -- \
  psql -U appuser -d customerdb -c "SELECT key,value FROM internal_secrets;"

# 정리
bash k8s/services/teardown-services.sh
```
