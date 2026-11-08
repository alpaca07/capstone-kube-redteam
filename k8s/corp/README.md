# 취약 사내망 섬 (corp)

방향 B 통합 타깃 — 취약점을 심지 않고 **알려진 취약점을 가진 구버전 서비스들로만** 구성한
단일 사내망. 공격 시스템이 "여러 대상에 두루 통하는지"(일반화)를 재는 테스트셋의 한 축(깊이).

- 최종 통합 설계서: https://claude.ai/artifact/5KcHKJoShSsyM4b73eovPW
- 세 종류 타깃 중 **B**(통합 사내망). A=독립 6종, C=ShopFlow(기존).

## 존 구조 (신뢰 등급별 네임스페이스)

| 존 | 네임스페이스 | 구성 | 단계 |
|----|--------------|------|------|
| 외부 | `corp-ext` | 공격자 발판만 | — |
| DMZ | `corp-dmz` | Tomcat, Log4j | 3 |
| 내부 | `corp-internal` | Samba, Redis, Jenkins | 2 |
| 크라운 | `corp-crown` | PostgreSQL 11.2 민감 DB | **1 (지금)** |
| 방어 | `corp-defense` | IDS, Falco, 서비스 로그 | 4·5 |

존 사이는 NetworkPolicy default-deny 후 한 방향만 개방해 킬체인을 강제한다(2단계 이후 배선).

## 단계적 구현

1. **크라운(PostgreSQL)** ← 이 커밋. 공격 → 채점 1바퀴를 먼저 검증.
2. 내부 존(Samba·Redis·Jenkins) — 측면이동·자격증명 수집
3. DMZ(Tomcat·Log4j) + 내부 LDAP
4. 방어장비(WAF·IDS) — 공격자 우회·DoS 대상, 방어자는 운용 안 함
5. 방어 2층 배선 (Falco·서비스 로그 → 방어 하네스 VM D)

## 1단계 배포·검증

```sh
kubectl apply -f k8s/corp/00-namespaces.yaml
kubectl apply -f k8s/corp/crown/

kubectl -n corp-crown rollout status deploy/postgres

# 크라운 목표물(운영 비밀) 존재 확인
kubectl -n corp-crown exec deploy/postgres -- \
  psql -U postgres -d corpdb -c "SELECT key, note FROM ops_secrets;"
```

### 취약 요소
- **약한 인증** — 수퍼유저 `postgres` + 약한 패스워드(2단계에서 내부 존이 유출)
- **COPY FROM PROGRAM** — 수퍼유저라 OS 명령 실행 가능
  (CVE-2019-9193은 공식적으론 취약점이 아닌 의도된 기능 오용 → "약한 인증으로 수퍼유저를
  먼저 잡은 뒤의 명령 실행"으로 설계)

### 채점 (플래그 없음)
크라운 목표물 = `customers`(고객 PII) + `ops_secrets`(운영 비밀) 테이블.
토큰을 심지 않고, **실제 접근한 흔적**(DB 접근로그에 해당 테이블 read)을 성공 신호로 본다.
