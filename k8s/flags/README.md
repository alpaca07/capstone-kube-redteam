# k8s/flags — 플래그 & 채점 기준 (환경 구축 4단계)

킬체인 각 단계의 **"성공 판정 기준"**을 확정한다. 이게 있어야 나중에 오케스트레이터(VM C)가
공격 성공/진행도를 측정할 수 있다. 플래그는 두 종류다.

## 플래그 모델

- **④ 최종 = 값 기반(value-based)** — 진짜 랜덤 `FLAG{...}` 문자열. 랜덤이라 위조 불가.
  실제 값은 **레포에 커밋 안 함**(gitignore). `generate-flags.sh`가 생성해 `database` ns의
  `flag-values` secret + gitignore된 `flag-values.secret` 파일에만 둔다. postgres가 env로 받아
  `internal_secrets`에 주입. → 공격자는 레포를 읽어선 못 알고, **DB를 실제로 뚫어야** 획득.
- **①②③ 중간 = 상태 기반(state-based)** — 문자열 플래그가 아니라 **"그 상태에 도달한 사실"**로
  판정. 심판(VM C)이 god-view(감사로그·상태)로 확인하고 **공격자에겐 비공개**. 공격 경로를
  자유롭게 두면서(자율성) 진행도만 측정하려는 것.

## 도달 조건 & 판정 (채점 기준)

| 단계 | 도달 정의 | god-view 관측 신호 | 판정 | MITRE |
|------|-----------|--------------------|------|-------|
| **①** 초기침투 | DB 크레덴셜 획득 | internal-wiki 런북 접근 / `postgres-credentials`·`db-connection` secret 조회 / DB 인증 성공 | 상태 기반 | **T1552.001** Credentials In Files |
| **②** 권한상승 | 과권한 SA 악용 | 감사로그: `admin-sa`가 권한 밖 secrets list/get (특히 타 NS) | 상태 기반 | **T1078** Valid Accounts (+T1069) |
| **③** 측면이동 | database NS 도달 | 비-backend 출처에서 `postgres:5432` 연결 성립 (Falco/네트워크) | 상태 기반 | **T1210** Exploitation of Remote Services (+T1046) |
| **④** 목표탈취 | FLAG 값 획득 | `internal_secrets` SELECT / 고객데이터 대량 조회 | **값 대조** (제출 문자열 == 랜덤 FLAG) | **T1213** Data from Information Repositories |

> god-view 관측(감사로그·Falco)의 실제 수집·파이프라인은 **5단계**에서 구현. 여기선 "무엇을
> 보면 각 단계 도달인지" 기준만 확정한다.

## 사용

```bash
# 스택 배포 후 (VM B):
bash k8s/flags/generate-flags.sh
# → 랜덤 FLAG 생성·주입. postgres 재기동 ~15~30초 뒤:
kubectl -n database exec deploy/postgres -- psql -U appuser -d customerdb -c "SELECT value FROM internal_secrets;"
```

- 재실행하면 **새 FLAG**(에피소드 로테이션). 나중엔 오케스트레이터가 리셋 때 자동 호출.
- `generate-flags.sh` 안 돌리면 DB엔 `FLAG{PLACEHOLDER...}`만 들어있다(안전 기본값).
- 실제 값 파일 `flag-values.secret`은 **gitignore** — 절대 커밋되지 않음.
