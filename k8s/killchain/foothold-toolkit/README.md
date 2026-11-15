# attacker-toolkit — 공격 발판 도구 이미지

자동 공격 하네스(VM A)는 명령을 **VM B 의 `frontend/attacker-foothold` 파드 안**에서
`kubectl exec` 로 실행한다(`../00-attacker-foothold.yaml`, `../foothold/README.md`). 따라서
**공격자가 쓸 수 있는 도구 = 그 파드 이미지에 든 바이너리**가 전부다.

기존엔 `postgres:16-alpine`(= `psql·wget·nc·nslookup·sh` 뿐)이라 공격 수단이 과도하게
제한됐다. 이 디렉토리는 **커스텀 공격 툴킷 이미지**(`capstone/attacker-toolkit:1.0`)를 빌드한다.
이 이미지는 발판의 본체 이미지를 교체하지 않고, **각 발판 파드의 initContainer 로 돌아 공유 볼륨
`/tk` 에 도구를 풀어** 본체가 마운트해 쓴다(`frontend/attacker-foothold`·`corp-ext/corp-attacker-foothold`
등 모든 발판에 같은 블록, 발판별 이미지 재빌드 없음). 본체 exec 환경은 `PATH=/tk/bin`,
`LD_LIBRARY_PATH=/tk/lib` 로 그 도구를 집는다.

## 포함 도구 (Tier 1~3, 대화형 툴 제외)

| 분류 | 도구 | 용도 |
|------|------|------|
| T1 HTTP | `curl` (+ 기존 `wget`) | 임의 메서드·헤더·업로드·TLS — 웹 익스플로잇·API 호출 |
| T1 JSON | `jq` | API 응답에서 토큰·비밀 추출(produces/inputs 와 결합) |
| T1 K8s | `kubectl` | 탈취 토큰으로 API 조작(`-o json` 구조화 출력) |
| T2 정찰 | `kdigger` | 파드에서 닿는 것·가진 권한 자동 열거 |
| T2 스캔 | `nmap` (+NSE) | 서비스/버전 탐지(`-oX -` 구조화). corp 다중 호스트용 |
| T2 탈출 | `deepce`, `amicontained` | 컨테이너 탈출 벡터·capability 조사 |
| T3 CVE | `nuclei` | 템플릿 기반 알려진 CVE 점검(VulHub/corp) |
| T3 SQLi | `sqlmap` (`--batch`) | SQL 인젝션(비대화 전용) |
| T3 PoC | `searchsploit` | ExploitDB **오프라인 미러**(고정 커밋) — 검증된 PoC 로컬 조회·복사 |
| 기존 | `psql`, `nslookup`/`dig`, `sh`, `wget`, `nc` | DB·DNS·셸 |

> **제외:** `peirates`(메뉴 대화형) · `metasploit`(세션 상태성) — ReAct·결정론 리플레이와 충돌.

### 검증된 PoC 라이브러리 (오프라인 미러)

실험 중 인터넷 OFF + `scope.py` 공인 IP 차단이라 **런타임에 인터넷에서 PoC 를 직접 받을 수
없다.** 대신 검증된 소스(ExploitDB)를 **빌드 시점에 통째로 받아 고정 커밋으로 이미지에 구워 둔다**
(`WITH_EXPLOITDB`/`EXPLOITDB_REF`). 공격자는 런타임에 `searchsploit` 로 로컬 조회만 한다:

```
searchsploit struts2 2.5          # 찾기
searchsploit -x 41570             # 코드 확인
searchsploit -m 41570             # 로컬 복사 → python3/sh/curl 로 범위 내 대상에 실행
```

고정 커밋이라 코퍼스가 라운드마다 동일 → 결정론 리플레이 유지. nuclei 템플릿(이미 내장)과
함께 "검증된 PoC/익스플로잇 오프라인 라이브러리"를 이룬다. 실행 자체는 여전히 `execute_action`
→ `scope.py`(외부 호스트·파괴명령 차단) + 대본 기록을 거친다. 코퍼스 갱신은 재빌드로만.
`WITH_EXPLOITDB=false` 로 빌드하면 미러 없이 린 이미지(이미지 ~1GB 절감).

> **런타임 pull 을 원하면(대안 B):** 허용망에 읽기전용 exploitdb 미러 호스트를 두고 `scope.py`
> `denied_hosts` 반대로 '그 한 호스트만 허용' 규칙을 추가해 `curl` 로 받게 할 수 있다. 미러를
> 고정 스냅샷으로 유지해야 결정론이 깨지지 않는다.

## 설계 전제

- **오프라인:** 실험 중 모델망 외 인터넷 OFF + `scope.py` 가 공인 IP 차단 → 런타임 도구
  다운로드 불가. 모든 도구(nuclei 템플릿 포함)를 **빌드 시점에 이미지로 구워 둔다.**
- **결정론:** `verifier.py` POST 리플레이가 성립하도록 구조화·멱등 출력 위주로 쓴다
  (`curl -s`, `kubectl -o json`, `nmap -oX -`, `nuclei -j`, `psql -t/CSV`). 프롬프트가
  이 사용법을 유도한다(`attacker/prompts/attacker_system.txt`).
- **능력 상한:** 발판 SA 는 여전히 `frontend` default(무권한)이고 exec 전용 kubeconfig 라,
  ②(admin-sa 과권한)는 공격자가 스스로 털어야 한다. 도구만 늘렸지 권한 경계는 그대로다.

## 빌드 & 적재

**VM B 에서 한 줄 실행하면 끝**(개발 단계, 인터넷 ON). VM B 가 k3s 노드라 빌드하면 containerd 에
바로 올라간다. 스크립트가 빌더를 자동 선택하고(`nerdctl`→k3s 직접 / `docker`→`k3s ctr import`),
둘 다 없으면 `docker` 를 자동 설치해 진행한다:
```bash
# (VM B, 인터넷 ON)
bash k8s/killchain/foothold-toolkit/build-and-load.sh
```
> k3s 는 `ctr`/`crictl` 만 있어 Dockerfile 을 못 빌드한다 → 스크립트가 `docker` 를 설치해 빌드한다
> (`docker` 는 k3s containerd 와 별도라 충돌 없음, 빌드·save 용으로만). 자동 설치를 막으려면
> `NO_AUTO_INSTALL=1 bash ...` — 그 경우 다른 장비서 빌드한 tar 를 `sudo k3s ctr images import` 로.

적재 후 (VM B):
```bash
kubectl apply -f k8s/killchain/00-attacker-foothold.yaml
kubectl -n frontend rollout status deploy/attacker-foothold
kubectl -n frontend exec deploy/attacker-foothold -- nuclei -version -disable-update-check   # 동작 확인
```
그 뒤 **발판 파드가 뜬 상태로 clean-baseline 재스냅샷**(매 라운드 revert 후에도 발판이
존재해야 함, `../foothold/README.md` 6단계).

## 버전·크기 메모

- 도구 버전은 `Dockerfile` 상단 `ARG` 로 핀. 다운로드가 404 면 해당 릴리스 페이지 최신으로
  올린다. `KUBECTL_VERSION` 은 k3s 서버에 맞춰 조정(`sudo k3s kubectl version`).
- `WITH_NUCLEI_TEMPLATES=false` 로 빌드하면 템플릿 없이 린 이미지(오프라인 실험장은 `true`).
- 이미지 ~300–500MB(템플릿 포함). VM B 디스크(80GB)엔 여유. RAM 은 `nmap`/`nuclei` 스파이크
  대비 limit 512Mi — VM B RAM 이 빠듯하면(현재 4GB) 동시 실행 부하 관찰 후 증설.

## 탐지 연동

새 도구에 맞춰 Falco/god-view 를 함께 갱신했다(`k8s/observability/falco-values.yaml`,
`orchestrator/log_source.py`): `nmap`→`Port scan from foothold`(T1046, 기존), `curl`→
`Credential access from foothold`(T1552.001, 기존), 신규 `nuclei`/`sqlmap`→
`Web exploitation tooling from foothold`(T1190). `kubectl`/`kdigger` 의 API 행위는
감사로그가 SA·verb·resource 로 이미 포착(도구 무관).
