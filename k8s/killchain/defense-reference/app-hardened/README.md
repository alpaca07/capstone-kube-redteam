# defense-reference/app-hardened — 앱 레벨 패치 (`patch_app` 프리미티브)

Phase A 웹 취약점(SQLi·SSRF·cmd injection·debug cred-leak)은 **클러스터 구성이 아니라 앱 코드 결함**이라,
방어자는 "고친 ConfigMap 재배포"로 막는다. 각 파일은 **동일 ConfigMap 이름의 하드닝 변종**이라
`kubectl apply` + `rollout restart` 로 코드가 교체된다. (기존 `defense-reference/` 패턴과 동일 — 베이스라인 미적용)

## 적용 (`patch_app <service>`)

```bash
# catalog-api: A1 SQLi + A2 SSRF + B0 cred-leak
kubectl apply -f catalog-api-code.yaml      && kubectl -n backend  rollout restart deploy/catalog-api
# order-api: B0 cred-leak
kubectl apply -f order-api-code.yaml        && kubectl -n backend  rollout restart deploy/order-api
# admin-dashboard: A3 cmd injection
kubectl apply -f admin-dashboard-code.yaml  && kubectl -n internal rollout restart deploy/admin-dashboard
```

## 하드닝 내용

| 서비스 | 차단 | 방법 |
|--------|------|------|
| catalog-api | A1 SQLi | 검색 쿼리 파라미터 바인딩(`%s`) |
| catalog-api | A2 SSRF | `preview` URL allowlist — http/https 공인 호스트만, 사설·루프백·링크로컬·`.svc`/`.cluster.local`/`.internal`·`file://` 거부 |
| catalog-api | B0 | `/debug/config` 제거 |
| order-api | B0 | `/debug/config` 제거 |
| admin-dashboard | A3 cmd injection | `/admin/diag` → `shell=False` + arg 배열 + host 정규식 검증 |

## 보상통제 (앱 패치 대신/병행 가능, 클러스터 레벨)

웹 취약점이지만 클러스터 레벨로도 2차 피해를 억제할 수 있어 "독립적 두 방어"가 성립한다.

- **A2 SSRF** → `catalog-api` egress NetworkPolicy(`internal` ns·`kube-apiserver` 차단). 앱 allowlist 없이도 내부 피벗을 끊음.
- **A3 cmd injection RCE** → Falco 탐지 + `restrict_pod_security`/`delete_pod` 로 탈출(T1610/T1611) 2차 피해 억제.
- (주의) SQLi·cred-leak 은 앱 패치가 사실상 유일 방어. egress NP 는 SQLi 자체는 못 막음(이미 DB 접근은 정상 경로).
