# attacker-toolkit — 공격 발판 도구 이미지

자동 공격 하네스(VM A)는 명령을 **VM B 의 `frontend/attacker-foothold` 파드 안**에서
`kubectl exec` 로 실행한다(`../00-attacker-foothold.yaml`, `../foothold/README.md`). 따라서
**공격자가 쓸 수 있는 도구 = 그 파드 이미지에 든 바이너리**가 전부다.

기존엔 `postgres:16-alpine`(= `psql·wget·nc·nslookup·sh` 뿐)이라 공격 수단이 과도하게
제한됐다. 이 디렉토리는 그 발판을 **커스텀 공격 툴킷 이미지**(`capstone/attacker-toolkit:1.0`)로
교체한다 — 노선 B(장비를 갖춘 공격자) + 커스텀 이미지 전달.

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
| 기존 | `psql`, `nslookup`/`dig`, `sh`, `wget`, `nc` | DB·DNS·셸 |

> **제외:** `peirates`(메뉴 대화형) · `metasploit`(세션 상태성) — ReAct·결정론 리플레이와 충돌.

## 설계 전제

- **오프라인:** 실험 중 모델망 외 인터넷 OFF + `scope.py` 가 공인 IP 차단 → 런타임 도구
  다운로드 불가. 모든 도구(nuclei 템플릿 포함)를 **빌드 시점에 이미지로 구워 둔다.**
- **결정론:** `verifier.py` POST 리플레이가 성립하도록 구조화·멱등 출력 위주로 쓴다
  (`curl -s`, `kubectl -o json`, `nmap -oX -`, `nuclei -j`, `psql -t/CSV`). 프롬프트가
  이 사용법을 유도한다(`attacker/prompts/attacker_system.txt`).
- **능력 상한:** 발판 SA 는 여전히 `frontend` default(무권한)이고 exec 전용 kubeconfig 라,
  ②(admin-sa 과권한)는 공격자가 스스로 털어야 한다. 도구만 늘렸지 권한 경계는 그대로다.

## 빌드 & 적재

```bash
# 개발기(인터넷 ON):
bash k8s/killchain/foothold-toolkit/build-and-load.sh --vmb <사용자>@192.168.16.128
# 또는 빌드만 하고 수동 적재:
bash k8s/killchain/foothold-toolkit/build-and-load.sh
```

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
