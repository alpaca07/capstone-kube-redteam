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
| 내부 | `corp-internal` | Samba, Redis, Jenkins | **2 (지금)** |
| 크라운 | `corp-crown` | PostgreSQL 11.2 민감 DB | 1 ✓ |
| 방어 | `corp-defense` | IDS, Falco, 서비스 로그 | 4·5 |

존 사이는 NetworkPolicy default-deny 후 한 방향만 개방해 킬체인을 강제한다(4단계에서 배선).

## 단계적 구현

1. **크라운(PostgreSQL)** ✓ — 공격 → 채점 1바퀴 검증.
2. **내부 존(Samba·Redis·Jenkins)** ← 이 커밋. 측면이동·자격증명 수집 → 크라운 접속정보 노출.
3. DMZ(Tomcat·Log4j) + 내부 LDAP
4. 방어장비(WAF·IDS) + 존 격리(NetworkPolicy)
5. 방어 2층 배선 (Falco·서비스 로그 → 방어 하네스 VM D)

## 서비스별 취약 요소

| 서비스 | 이미지 | 취약점 | 경로 |
|--------|--------|--------|------|
| PostgreSQL | `postgres:11.2` | 약한 인증 + COPY FROM PROGRAM | 수퍼유저 → OS 명령 |
| Samba | `vulhub/samba:4.6.3` | CVE-2017-7494 (SambaCry) | 쓰기 공유에 악성 .so 로드 |
| Redis | `vulhub/redis:4.0.14` | 무인증 | MODULE LOAD / dir+dbfilename RCE |
| Jenkins | `vulhub/jenkins:2.138` | CVE-2018-1000861 | Stapler 코드실행 + 스크립트 콘솔 |

> 설계서는 Samba를 4.5.9로 적었으나 VulHub 공식 재현 이미지가 **4.6.3**이라 그걸 따른다
> (둘 다 CVE-2017-7494에 취약). 내부 3종은 VulHub 원본 docker-compose의 이미지·설정을 그대로 옮겼다.

## 측면이동 체인 (통과 ② → 크라운)

Jenkins 컨테이너의 `/opt/deploy/corp-db.properties` 에 **크라운 PostgreSQL 접속정보**가 들어 있다
(`corp-crown`의 `10-postgres-secret.yaml` 값과 일치). 공격자가 Jenkins를 뚫어 스크립트 콘솔로
이 파일을 읽으면 "자격증명 수집 → 크라운 접속"이 성립한다.

## 배포·검증

```sh
kubectl apply -f k8s/corp/00-namespaces.yaml
kubectl apply -f k8s/corp/crown/
kubectl apply -f k8s/corp/internal/

kubectl -n corp-crown    rollout status deploy/postgres
kubectl -n corp-internal rollout status deploy/samba
kubectl -n corp-internal rollout status deploy/redis
kubectl -n corp-internal rollout status deploy/jenkins

# 내부 → 크라운 체인 확인: Jenkins 안의 배포 접속정보
kubectl -n corp-internal exec deploy/jenkins -- cat /opt/deploy/corp-db.properties
```

## 채점 (플래그 없음)
크라운 목표물 = `customers`(고객 PII) + `ops_secrets`(운영 비밀) 테이블.
토큰을 심지 않고, **실제 접근한 흔적**(DB 접근로그에 해당 테이블 read)을 성공 신호로 본다.
