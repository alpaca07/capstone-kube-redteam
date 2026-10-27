# capstone-kube-redteam

**LLM 기반 쿠버네티스 자동 공격-방어 공진화 시스템** (캡스톤)

같은 LLM을 공격·방어 양쪽 하네스에 붙여, K8s 환경에서 자동 공격-방어 루프를 돌리고
공수 공진화(co-evolution)를 측정한다. 공격자는 탈옥(uncensored) 모델, 방어자는
일반(aligned) 모델을 쓰며, 둘 다 DGX Spark의 Ollama에서 서빙된다.

> ⚠️ 의도적으로 취약한 실습 환경을 다룬다. 격리된 랩(VMware, 인터넷 차단)에서만 사용.

---

## 시스템 구조도

색상 코드 — 🟥 공격 / 🟦 대상·방어 / ⬜ 시스템 / 🟥⃝ 취약점. 망: 공격망(VM A↔B) · 관리망(VM C↔A/B) · 모델망(DGX).

### 전체 구조
<img src="docs/diagrams/overview.svg" alt="전체 시스템 구조 — VM A(공격)·VM B(대상+방어)·VM C(심판)·DGX" width="900">

### VM A — 공격 하네스
탈옥 LLM을 ReAct 루프로 돌려 발판 셸에서 자율 침투. `execute_action` 단일 통로가 모든 명령을 실행하며 리플레이 대본을 남긴다.

<img src="docs/diagrams/vm-a.svg" alt="VM A 공격 하네스 내부 구조" width="900">

### VM B — 대상 클러스터 + 방어 하네스
k3s 취약 클러스터(ShopFlow)에 킬체인 ①~④와 Wave 1 분기(탈출·다경로·정찰)를 이식. 옆에 방어 하네스(관측→트리아지→패치)와 Falco가 붙는다.

<img src="docs/diagrams/vm-b.svg" alt="VM B 대상 클러스터 및 방어 하네스 내부 구조" width="920">

### VM C — 오케스트레이터 / 심판
LLM이 아닌 결정론 심판. 턴 시퀀서로 루프를 제어하고, god-view 정답지로 공격·탐지를 검증·채점하며, 대시보드로 실시간 관제한다.

<img src="docs/diagrams/vm-c.svg" alt="VM C 오케스트레이터/심판 내부 구조" width="900">

---

## 구성 (3 VM + DGX)

| VM | 역할 | 디렉토리 | 모델 |
|----|------|---------|------|
| **VM A** | 공격 하네스 (자율 침투) | `attacker/` | 탈옥(uncensored) |
| **VM B** | 대상 K8s + 방어 하네스 | `defender/`, `k8s/` | 일반(aligned) |
| **VM C** | 오케스트레이터 (심판, LLM 아님) | `orchestrator/` | — |
| DGX Spark | 두 모델 서빙 (별도 머신) | — | Ollama |

- **간접 상호작용**: 공격자·방어자는 직접 대화 없이 클러스터를 매개로만 반응.
- **정보 비대칭**: VM C만 god-view(정답). 두 에이전트는 부분 관측.
- **통신**: HTTP(FastAPI) 메시지 10종. VM C가 주도, A·B는 서버.
- **검증 2중화**: 리플레이(공격 재현) + 상태 검증.
- **계층**: 교전 1회 = 라운드, 종료조건까지 = 에피소드, 여러 에피소드 = 통계.

---

## 디렉토리 구조

```
capstone-kube-redteam/
├─ common/              # 세 VM 공통 (메시지·replay 스키마·설정 템플릿)
│   ├─ messages.py          # 메시지 10종 스키마
│   ├─ replay_schema.py     # replay_script 스키마 (검증 핵심)
│   └─ config.example.yaml  # 설정 템플릿 (실제값은 config.yaml, gitignore)
├─ orchestrator/        # VM C — 심판 (순수 코드, 판단 없음)
│   ├─ main.py              # 진입점 (실험 시작)
│   ├─ sequencer.py         # ① 턴 시퀀서 (0~8 루프)
│   ├─ snapshot.py          # ② 스냅샷 매니저 (VMware API)
│   ├─ verifier.py          # ③ 검증 엔진 (pre/post·상태·판정)
│   ├─ scorer.py            # ④ 채점·로깅
│   ├─ truth_log.py         # 정답 타임라인 (god-view)
│   ├─ api.py               # FastAPI (대시보드 조회 API)
│   └─ static/              # 대시보드 (HTML+Chart.js, 나중)
├─ attacker/            # VM A — 공격 하네스
│   ├─ server.py            # HTTP 서버
│   ├─ react_loop.py        # ReAct 루프
│   ├─ execute_action.py    # ★ 단일 통로 (실행+대본기록)
│   ├─ llm_client.py        # 탈옥 모델 호출
│   ├─ history.py           # 공격 히스토리
│   ├─ replay_engine.py     # 리플레이 재생 (LLM 없음)
│   └─ prompts/             # 공격자 시스템 프롬프트
├─ defender/            # VM B — 방어 하네스
│   ├─ server.py            # HTTP 서버
│   ├─ observer.py          # 관측 레이어 (감사로그·Falco·상태)
│   ├─ filter.py            # 필터 (baseline diff·룰)
│   ├─ triage.py            # LLM 트리아지 (일반 모델)
│   ├─ patcher.py           # 패치 세트 적용 (atomic·헬스체크)
│   ├─ state_query.py       # 상태조회 핸들러
│   └─ prompts/             # 방어자 시스템 프롬프트
├─ k8s/                 # VM B — 쿠버네티스 환경
│   ├─ goat/                # Kubernetes Goat 개조분
│   ├─ services/            # 자체 서비스 (nginx·flask·postgres)
│   ├─ killchain/           # 취약점 심기 (RBAC·NetworkPolicy·Secret)
│   ├─ flags/               # 플래그 정의·심기
│   └─ observability/       # Falco·감사정책 설정
├─ scripts/             # 운영 스크립트 (환경 준비·스냅샷 등)
└─ docs/                # 설계 문서
```

---

## 킬체인 (메인 4단계, 각 단계 플래그)

```
① 초기침투  웹앱 하드코딩 DB 자격증명        (T1552)  [상태 기반 플래그]
② 권한상승  웹앱 파드 과다 RBAC             (T1078)  [상태 기반 플래그]
③ 측면이동  느슨한 네임스페이스/네트워크 격리  (T1210)  [상태 기반 플래그]
④ 목표탈취  DB 고객데이터 + FLAG{}          (T1213)  [값 기반 플래그]
```
사슬 구조: ①(자격증명)+③(네트워크)이 ④에서 합쳐지고, ②가 ③을 엶 → 순서대로 밟아야 뚫림.

---

## VM별 배포 (sparse checkout)

각 VM은 자기 코드만 받는다 (모노레포 + sparse checkout):

```bash
# VM A (공격)
git clone --no-checkout <repo> capstone && cd capstone
git sparse-checkout init --cone
git sparse-checkout set attacker common
git checkout

# VM B (대상+방어)
git sparse-checkout set defender k8s common

# VM C (심판)
git sparse-checkout set orchestrator common
```

VM 간 통신은 폴더 공유가 아니라 **HTTP 메시지**로만 한다.

---

## 개발 / 실험 모드

| | 인터넷·GitHub | Tailscale | 비고 |
|--|--------------|-----------|------|
| **개발 중** | ON | ON | 코드 push/pull, 어디서든 SSH |
| **실험 중** | OFF | OFF (최소 VM A) | DGX만 유지, 코드는 미리 pull 완비 |

실험 전에 최신 코드를 다 pull → 인터넷 차단 → 받아둔 코드로 실행.

---

## 상태

- ✅ 전체 설계 완료 (아키텍처·환경 구축·에이전트 구현)
- ✅ 0단계 인프라: VM A·B·C 설치 + Tailscale + SSH + sparse-checkout, VM B에 k3s(노드 Ready, 부팅 자동시작)
- 🔨 1단계 Goat 배포: 배포 자산(`k8s/goat/`) 준비 완료 → VM B에서 실행·검증 대기
- ⬜ 2~5단계(자체 서비스·킬체인·플래그·관측) 및 에이전트 코드 구현 예정

## 실행 (구현 후)

```bash
python orchestrator/main.py --episodes 50 --max-rounds 20 --time-limit 300
```
