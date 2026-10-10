# k8s/services — 자체 서비스 스택 (환경 구축 2단계)

Goat(1단계) 위에, 킬체인이 관통할 **현실적인 이커머스 회사(ShopFlow)**를 세운다.
서비스가 여럿이라 취약점이 "흔한 운영 실수"처럼 묻히고, 공격자는 정찰로 약한 고리를
찾아내야 한다. 이 단계는 **취약점 없이 정상 동작**하는 깨끗한 스택까지. 취약점 이식은 3단계.

## 서비스 구성 (9개 + 트래픽)

| 네임스페이스 | 서비스 | 이미지 | 역할 | 노출 |
|------|--------|--------|------|------|
| `frontend` | storefront | nginx | 쇼핑몰 메인 (상품) | NodePort **30080** |
| `frontend` | customer-portal | nginx | 고객센터 (로그인+주문) | NodePort **30081** |
| `frontend` | traffic-generator | curl | 가용성 baseline | — |
| `backend` | catalog-api | python/Flask | 상품 API | ClusterIP |
| `backend` | order-api | python/Flask | 주문 API (조인) | ClusterIP |
| `backend` | auth-service | python/Flask | 로그인/토큰 (Redis) | ClusterIP |
| `database` | postgres | postgres | 고객·상품·주문 + **FLAG** | ClusterIP |
| `database` | redis | redis | 세션/캐시 | ClusterIP |
| `internal` | admin-dashboard | python/Flask | 관리자 콘솔 (**고객 PII 전체**) | ClusterIP(내부) |
| `internal` | internal-wiki | nginx | 사내 문서 | ClusterIP(내부) |

**토폴로지**: 공개 웹(frontend) → 내부 API(backend) → 데이터(database). 사내 도구(internal)는
관리자 전용(NodePort 없음 → 밖에서 직접 못 감). 고객 PII는 공개 포털이 아니라 `admin-dashboard`에만.

## 킬체인 자리 (지금은 전부 '깨끗', 3단계에서 심음)

| 단계 | 3단계에서 심을 취약점 | 위치 |
|------|----------------------|------|
| ① 초기침투 | DB 크레덴셜 평문 유출 (T1552) | `internal-wiki` 런북 / `admin` 디버그 |
| ② 권한상승 | 과다 RBAC SA (T1078) | `admin-dashboard` SA |
| ③ 측면이동 | NetworkPolicy 부재 (T1210) | `internal`/`backend` → `database` |
| ④ 목표탈취 | 고객데이터 + FLAG (T1213) | `postgres.database` |

## 이미지 전략

개발 단계는 **공식 이미지 + ConfigMap 코드 주입**. Flask들이 기동 때 `pip install` 하므로
인터넷 필요 + 첫 배포 1~3분. **실험 전**(5단계)엔 코드 박은 이미지로 구워 스냅샷(인터넷 OFF 대비).

## 배포 / 검증 / 정리

```bash
# VM B, 레포 루트에서
git pull
bash k8s/services/setup-services.sh

# 파드 (flask는 pip로 ~1~3분)
kubectl get pods -n database -n backend   # 아래처럼 ns별로
kubectl get pods -n backend ; kubectl get pods -n frontend ; kubectl get pods -n internal

# 공개:  http://<VM B IP>:30080 (쇼핑몰) · :30081 (고객센터)
# 내부 관리자(포트포워딩):
kubectl -n internal port-forward --address 0.0.0.0 svc/admin-dashboard 30090:8080 &
#   → http://<VM B IP>:30090  (고객 PII 콘솔)

# ④ 목표물 확인(심판 관점):
kubectl -n database exec deploy/postgres -- psql -U appuser -d customerdb -c "SELECT key,value FROM internal_secrets;"

# 정리
bash k8s/services/teardown-services.sh
```
