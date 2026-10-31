# 변경 이력 — K8s LLM 자동 공수 공진화 시스템

> 발표·회고용 일자별 변천사. '현재 상태/실행법'은 [HANDOVER.md](HANDOVER.md) 참고.
> 각 날짜 = 그날의 테마 + 핵심 변경(커밋) + **그날 끝 상태**. 커밋 해시는 추적용.

---

## 2026-10-10 — 환경 구축 (타깃 클러스터)

쿠버네티스 위에 '현실적인 이커머스 회사'를 세우고 거기에 취약점을 이식.

- `658aa6d` 3-VM 공수 공진화 뼈대(초기 scaffold)
- `312164c` Kubernetes Goat 배포 자산(1단계) — 레퍼런스 취약 환경
- `073183b`·`d602288`·`44e98f7`·`d34f356` **자체 서비스 스택(ShopFlow)** — 깨끗한 3-tier →
  이커머스 멀티서비스(frontend/backend/database/internal)로 확장 + UI
- `a9ebf96` **킬체인 ①②③ 이식** — ①크레덴셜 평문노출 ②과권한 SA ③NetworkPolicy 부재

**그날 끝:** 공격 대상(취약한 ShopFlow 클러스터)과 메인 킬체인이 선다.

---

## 2026-10-11 — 에이전트·오케스트레이터 구현 (공수 루프의 뼈대)

공격/방어 LLM 하네스와 심판(VM C)을 전부 코드로. 테스트 우선.

- `94bdce7` **공통 인터페이스** — 메시지 10종 + 리플레이 스키마 + 설정 로더(두 하네스의 계약)
- `f870c30` DGX Ollama LLM 클라이언트(하네스 공유 연결 수단)
- 공격 하네스: `555435b` 액션 파서·스코프 → `04944f1` execute_action(심장) → `a5bb097` ReAct
  루프·히스토리 → `13104e4` **리플레이 엔진**(LLM off 결정론 재생) → `bf2acbd` 서버 완성
- 방어 하네스: `f48d31e` 관측·필터 → `6e645ac` triage 파서 → `c9c36cf` triage·patcher →
  `29058b6` state_query·DefenseHarness → `951473b` 실 kubectl 어댑터·서버 완성
- 오케스트레이터(VM C): `1f0e063` **검증 엔진(pre/post 재생+판정)** → `2a25403` 채점·로깅
  (TP/FP/FN·MTTD) → `10b857c` 턴 시퀀서(0~8 루프·종료조건·복구) → `4b9799a` 실 어댑터·CLI
- `5b70425` 플래그·채점기준(랜덤 FLAG+MITRE) / `e97d17b` 관측(k3s 감사로그+Falco)

**그날 끝:** 공격·방어·심판 3축이 전부 구현돼 루프가 '조립'은 됨(실연결·튜닝은 이후).

---

## 2026-10-14 — 스냅샷 인프라 (상태 리셋 수단)

에피소드마다 클러스터를 되돌릴 방법 찾기. 이게 나중에 최대 골칫거리가 됨(→10-16 A2에서 교체).

- `ffedbd8`·`12110fd` config: LLM 서빙 host를 공격/방어 역할별 분리 + `/v1` 경로
- `c610262` **vmrun(Workstation) SnapshotManager** — VM 레벨 스냅샷/revert
- `9257941`·`1236074`·`8e9fed2`·`3f14fb2` vmrun revert 후 재개 문제(FastAPI 422, 이중
  인스턴스, 락 재시도, paused 커버) 연속 수정
- `c65241d` revert 후 VM B ready 대기 게이트
- `40fb0b2`→`d1b4f7e` kubectl 리셋 스크립트 시도했다가 **되돌림**(당시엔 VM 스냅샷 설계 유지)
- `7af3735` **호스트 스냅샷 에이전트** — SSH가 못 하던 'revert 후 VM 재개'를 호스트 세션에서 해결

**그날 끝:** VM 스냅샷으로 상태 리셋이 되긴 함(단, revert가 VM 을 stun 시키는 불씨가 잠복).

---

## 2026-10-15 — 공격자 튜닝·견고성 + 방어 패치 수정

루프를 '실제로' 돌리니 공격 턴이 느리고·죽고·치팅. 하나씩 잡음.

- 타임아웃·예산: `3a3ddeb` LLM 타임아웃을 턴 예산에 맞춤 + 토큰 노브 / `35b0685` ReAct 를
  '남은 예산'으로 묶음 / `6346951` verify state_query·health 30→120초
- 생성 병목: `bc2ff1a` max_tokens 를 실험 파라미터로 + thought 넛지 / `e4fe161` thought 축약
- 견고성: `f5a0264` 파싱 실패 비치명화(1스텝 실패가 턴을 안 죽이게) / `ca81e6a` 라운드 간 지식
  이월(발판 매 라운드+요약 누적) / `480b6b0` **가짜 플래그 reward-hacking 차단**(cwd 격리·스코프)
- 방어: `2824a33` 패치 시도 결과 가시화(noop 원인) / `22c8668` 자연어 NS 타깃이 패치 세트를
  통째 롤백시키던 문제 수정(②③ 적용 가능)
- 운영: `ef2355d`·`e35e3f3`·`12f6735`·`47d3611`·`14f7902` 진단/타이밍/ABORT 사유 로그 +
  `811ee85` 자동기동 systemd 템플릿 + `4066dae` 재베이스라인 헬퍼(baseline.py)

**그날 끝:** 공격 턴이 '덜 죽고 덜 느려짐', 방어가 ②③ 패치는 냄. 근데 여전히 생성 병목·간헐
실패가 남음(→ 원인은 다음 날 밝혀짐).

---

## 2026-10-16 — 돌파의 날: FLAG 자동 포획 → 방어 patched → 공진화 루프 완주

밤샘 디버깅으로 근본 원인들을 연쇄 해결. 하루에 공수 루프가 처음으로 자동으로 닫힘.

**(1) 공격이 안 되던 진짜 원인 — Qwen3 사고 모드**
- `f19991d`→`078c9b1` **`reasoning_effort="none"` 하드 스위치** — 모델이 `<think>`로 토큰
  상한을 다 써 본문을 빈 채 잘리던(`finish=length,len=0`) 파싱 전멸의 정체. Ollama `/v1`은
  `/no_think` 를 무시 → reasoning_effort 로만 꺼짐. llm 호출 261초→8~15초. **전체를 되살린 결정타.**
- `39d0e07` 방어자도 동일 적용 / `7e5e850` scope 오탐·truncation bump 제거

**(2) 자율 발견 설계 — discoverability**
- `c55532d` **in-cluster 발판**(frontend 파드 kubectl exec) / `4044389` 발판=공식 postgres 이미지
- `16a7483` **웹앱에 internal-wiki 단서 심기** — 프롬프트 유출 0 으로 공격자가 ①에 자율 도달
- `3b984cc` **관측 절단 완화** — 크레덴셜이 페이지 하단(603자째)이라 잘리던 문제, 최근 관측
  넉넉히+크레덴셜 상단 고정
- `6080f5e` **carry-forward 리셋을 R1에도** — 상주 하네스가 '이미 땄다'를 기억해 즉시 give_up 하던 누수 차단

**(3) 게이팅·단발 포획**
- `810151c` 플래그 획득 라운드만 방어+검증(미획득은 생략·이월) / `4681b49` `--no-revert`
  (vmrun stun 임시 우회)
- → **FLAG 자동 포획 성공**(7스텝, 획득값==DB 실제값 수동 확인, `f43ddf9`·`78f2347`)

**(4) 방어자 noop 해결**
- `7583260` 방어 프롬프트를 patcher 렌더 가능한 어휘로 / `20ca61c` **방어자 단독 probe**
- → 근본원인 4개(프롬프트·carry-forward·관측절단·**kubeconfig 권한**) 규명. kubeconfig 600→644
  후 **방어자가 `add_networkpolicy database` 실제 적용**(`3d0ba7e`)

**(5) §8 #1 근절 — A2: VM 스냅샷 → k8s 네이티브 리셋**
- `667493c` **BaselineManager**(kubectl 리셋+클린 지문) + verify 재작성 + 시퀀서 배선
- `68f6fb3` **verify POST-only** — 리셋 제거로 방어가 라운드 간 누적(공진화 올바름)
- → vmrun 스냅샷이 VM 을 stun(freeze)시켜 k3s·SSH 를 끊던 문제를 설계에서 제거.
- `5c3a767` §11.5 확장 가이드(새 취약점 추가 시 점검 4개 층)

**그날 끝(검증됨):** 자동 공진화 1라운드 **94초** 완주 — `공격=flag(69s) → 방어=patched(19s)
→ 판정=blocked(5s)`, 베이스라인 리셋 2초, VM 안 끊김. 직전 VM 스냅샷 방식(스냅샷 337초+verify
1364초+VM 재부팅) 대비 ~20배 단축 + 크래시 제거. **공격→방어→차단이 심판 자동 측정으로 닫힌 첫 기록.**

---

## 2026-10-17 — VM 3망 분리 + ② 활성화 + 측정 배관(#4·#6)

단일 평면에서 평면 분리로 '공격자↔심판 격리'를 아키텍처화하고, 죽어 있던 ②를 필수 경로로 살림.

**(1) VM 간 3망 분리 (공격자 ↔ 심판 격리)**
- **관리망**(기존 192.168.16.0/24): 심판 VM C ↔ 하네스·k3s admin API·리셋·god-view.
- **공격망**(신규 LAN 세그먼트 10.10.10.0/24, 호스트 미참여): VM A↔VM B `6443` 발판 exec 전용.
  발판 kubeconfig server 를 10.10.10.20:6443 로 이전(`insecure-skip-tls` 라 k3s 재시작 불필요).
- **서비스망**: k3s 오버레이(10.42/10.43)+NetworkPolicy 유지(VMnet 아님).
- **파드 egress 봉쇄**(노드 iptables, `capstone-netrules.service` 로 영속): 발판 파드(10.42/16) →
  관리망(VM C·호스트)·DGX 차단, in-cluster API(②)·내부통신은 보존(호스트/포트 지정, 통짜 DROP 금지).
- **검증됨**: tcpdump — 공격망엔 10.10.10.10↔.20:6443 만, 관리망엔 VM C↔.128:6443 만(상호 부재).
  파드→관리망 5초 먹통 / 내부 0초. 루프 97초 정상(flag→patched→blocked) — 격리가 로직 안 깨뜨림.

**(2) ② 과권한 SA 활성화 (죽은 취약점 → 필수 관문)**
- 그동안 ①위키가 DB 비번을 평문으로도 흘려 공격자가 ②를 건너뛰고 ①→④ 지름길만 탐.
- `42-internal-wiki.yaml`: 런북 평문 비번 제거 → "admin 콘솔 운영 엔드포인트로 조회" 안내로 교체.
- `41-admin-dashboard.yaml`: `/internal/secret/<ns>/<name>` 추가 — 마운트된 과권한 admin-sa 토큰으로
  k8s Secret 조회(confused deputy). 자동 공격자는 admin 파드에 exec 못 하니 HTTP 로 닿게 한 것.
- 효과: 경로가 `①단서→②SA로 Secret→③NP갭→④FLAG` 로 바뀌어 **②가 비번 획득 필수 관문**이 됨.
  방어자는 `restrict_rbac`(바인딩 삭제→403) 또는 `add_networkpolicy` 어느 쪽도 독립 차단 가능.
  방어자·공격자 **코드 변경 0**(둘 다 이미 지원). 감사정책이 secret-get 을 남겨 ② 탐지도 가능.
- **검증됨(2026-10-17)**: 공격자가 자율로 `①위키→②admin-dashboard /internal/secret→base64 -d→
  ③④psql` 를 밟아 11스텝 108초 FLAG 포획(전엔 wiki→psql 직행 7스텝). 루프 정상 종료
  (flag→patched 탐지2개→blocked). restrict_rbac 단독 차단도 검증됨(바인딩 삭제→엔드포인트 403).

**(3) 측정 배관 #4·#6 (숫자 정상화)**
- #4 ④ 값 채점: VM C 가 클러스터 secret(`database/flag-values`)에서 ④ 값을 읽어 `--flag-file` 채움
  → value_match → **플래그깊이 0→4**.
- #6 god-view 감사로그: `k8s/observability/audit-tail.yaml`(hostPath tail DaemonSet) +
  `scripts/vmc-sync-audit.sh` 로 VM C 가 admin kubeconfig 만으로 수집(SSH 불필요),
  config `observability.audit_log_path` 를 로컬 수집본으로 → truth 에 T1078(②) 유입.
- **검증됨**: 탐지 `0/3/0 → 1/1/1`, **MTTD=0**(② 같은 라운드 탐지), 깊이 4. TP=T1078(②),
  FN=T1213(④ 미탐), FP=①③(HTTP·pod-to-pod 감사 사각 — Falco 네트워크 룰이 다음 선행조건).

**(4) 견고성 — exec 타임아웃 120s→15s**
- 다중 에피소드에서 방어로 DB가 차단된 재시도 라운드의 `nc -zv postgres 5432` 가 커넥트 대기로
  매달려 kubectl exec 가 120s 까지 걸림 → 턴이 오케스트레이터 read timeout(예산+30)을 넘겨 E2·E3 ABORT.
- `create_harness` step_to 를 `min(time_limit,120)`→`min(time_limit,15)` (러너 기본도 15s). 정상 명령은
  <1s 라 무해, 차단 명령은 15s 에 실패→perseveration 가드가 예산 안에서 발동. 턴 최악 ~195s < 210s.

**(5) VM C 대시보드 + 실험 관제판** (`orchestrator/api.py`·`static/dashboard.html`)
- FastAPI 가 rounds/episodes.jsonl 을 서빙 + 대시보드에서 ▶시작/■중지 + 2.5s 폴링 라이브(진행로그·
  green 펄스·차트 자동갱신). 차트(ui-ux-pro-max): 공진화=스트리밍 area, precision/recall=추세 area.
  인라인 SVG(CDN 0, 폐쇄망 OK). 관리망 전용(god-view).

**(6) 대시보드 리디자인 — 킬체인 상태판 + 교전 패널** (`static/dashboard.html`·`scorer.py`)
- 식상한 슬레이트-글래스+그린·'짜치는' 터미널 로그 폐기 → **공격빨강↔방어파랑** 정체성으로
  재설계(Space Grotesk+IBM Plex+JetBrains Mono, ui-ux-pro-max). **킬체인 상태판**(①②③④를
  공격도달=빨강/방어차단=파랑/미도달=회색 실시간 색칠) + **교전 패널**(공격↔판정↔방어 versus,
  로그 대체) + 교전 스트림(색코드 pill) 신설.
- 정확도: `RoundRecord.stages_reached`(라운드별 god-view 도달, 체인필) 추가 → 킬체인이 추정이
  아닌 실데이터로 칠해짐(①③ 감사 사각은 선형 체인 보강). 패치 단계는 보고기법→단계 유도.
  테스트 scorer 11/11·sequencer 11/11 통과.

**그날 끝(검증됨):** 위 전부를 깐 위에서 **다중 에피소드 공진화 3×3 완주 — ABORT 0, rc=0.**
지난번 `nc 5432` 매달림이 죽이던 E2·E3 중단 재발 없음(15s 캡 효과). 대시보드 실시간 관제로 전
과정 관측 — 에피소드마다 `R1 flag(깊이4)→patched→blocked, R2·R3 공격실패(timeout/deadend)→
inconclusive`, **방어 실패 라운드 0**. 집계: 평균깊이 4/4, 정밀도·재현율 50%/50%(탐지 1/1/1,
FP·FN=①③ 감사 사각), MTTD 0R, 가용성 100%, blocked 3/9. 타임라인=에피소드 리셋에 의한
**톱니×3**(독립 재시행 — 누적 군비경쟁은 `skip_revert` 로 전환 가능, 서사 결정 대기).

---

## 2026-10-24 — Wave 1 취약점 확장 (MITRE 공격면 확대)

중간발표 이후. 메인 킬체인 ①~④에 **②에서 갈라지는 두 분기 + 다경로 크레덴셜**을 이식해 공격면을
넓히고, '차단 가능' vs '탐지만 가능(Discovery)' 위협을 구분. 설계·결정 전문: [wave1-design.md](wave1-design.md).

**WHAT / WHY (무엇을·왜)**
- **T1610 Deploy Container + T1611 Escape to Host (체인)** — `admin-tools` 과권한에 `pods:create`
  와 `admin-sa` classic 토큰 Secret 추가. *왜*: 공격자가 탈취 토큰으로 privileged/hostPath 파드를
  배포→노드 탈출하는 현실적 경로. 기존 `restrict_rbac`(바인딩 삭제)가 ②+T1610 을 한 번에 막는 시너지.
- **T1552.001 (평문 ConfigMap, 다경로 크레덴셜)** — `backend/legacy-db-config` 에 DB 비번 평문.
  *왜*: 과권한이 Secret 만의 문제가 아님(ConfigMap 도 샌다)을 보여 `restrict_rbac` 의 가치를 키움.
- **Discovery 채점 편입 (T1046/T1613/T1069, detect-only)** — Falco 포트스캔 룰 + 감사(네임스페이스
  열거·auth can-i) 매핑. *왜*: 전용 차단 패치가 없는 '탐지 전용' 범주로 방어자의 **과잉 패치
  억제(정밀도)**를 시험 → 탐지≠차단 주제 강화.
- **새 방어 어휘 `restrict_pod_security`** — ns 에 PodSecurity `enforce=baseline`(privileged/
  hostPath admission 거부). *왜*: T1611 예방. baseline 은 정상 파드를 안 깨 가용성 유지(restricted
  는 과잉차단 함정).
- **A2 리셋 보강** — 공격자 생성 파드(default 전삭제 + `created-by=attacker`) + PodSecurity 라벨
  역산. *왜*: 공격자가 이제 상태를 바꾸므로(T1610) 에피소드 독립성 유지.

**구현/채점 배선**: 신규 기법은 `orchestrator/log_source.py` 매핑만으로 `sequencer._build_truth`
가 truth 에 자동 편입(탐지 TP/FP/FN). 확장 기법은 비-digit flag_id 라 선형 깊이(①~④) 불변.
방어자 관측(observer/filter)은 제네릭이라 무수정으로 신규 신호 포착.

**테스트**: 신규 8케이스 추가(audit/falco 매핑·render_op pod_security·baseline PSA 역산) →
`tests/run_all.py` **210 passed, 0 failed**. 매니페스트 YAML·Falco 룰 파싱 검증.

**스테이징(Wave 1b)**: T1110 Brute Force(약한 DB 크레덴셜)는 **postgres auth 로그**라는 새 관측
소스가 필요(k8s 레이어에선 T1210 과 구분 불가) → VM B 배포 단계가 늘어 별도 증분으로 분리.

**그날 끝:** 공격면이 ①~④ + 탈출 체인(T1610→T1611) + 다경로 크레덴셜 + Discovery 3종으로 확대.
코드·테스트 완료, VM B/C 재적용·하네스 재시작으로 반영 대기(배포 메모: wave1-design §6).

---

## 2026-10-24 (저녁) — Wave1 라이브 검증 + 호스트 objective + 오탐 수정

**라이브 검증(VM B 실클러스터)**: 탈출 체인을 kubectl 로 직접 확인 — T1610 파드 생성(admin-sa
과권한) ✓, T1611 노드 `/etc/shadow` 실제 read ✓, Falco `Escape to host filesystem` 발동 ✓,
`restrict_pod_security=baseline` 재생성 admission 거부 ✓, `restrict_rbac` 삭제 후 admin-sa
create 불가(impersonation can-i=no) ✓, 리셋 복구 ✓. **환경·탐지·차단·복구 4박자 전부 작동.**
(주의: `kubectl --token` 은 k3s 기본 kubeconfig 의 클라 인증서가 우선돼 무시됨 → 실 공격자는
raw Bearer 라 admin-sa 로 인증. impersonation `--as` 로 RBAC 경로 검증.)

**통합 테스트**: `tests/test_wave1_integration.py` — 실 log_source·sequencer·scorer 를 가짜
클라이언트로 엮어 배선 증명(기법 8종 추출 / truth 편입·TP·FP·FN / Discovery TP). 215 passed.

**WHAT/WHY (저녁 변경)**:
- **호스트 장악 objective(크라운 주얼 축)** — 자율 공격자는 "DB FLAG" 목표만으론 탈출할 이유가
  없다(실런에서 순수 ①②③④). → 노드 파일 `/etc/shopflow/host.flag` 에 FLAG 를 심고 공격 목표에
  "노드 호스트 FLAG 도 획득" 추가. `FlagSpec(flag_id="host", VALUE, T1005)`, 비-digit 라 선형
  깊이 불변. *일반화*: 하네스가 flag_id 를 "4"로 하드코딩하므로 god-view 가 **값으로 objective
  식별**(`match_value`) → Wave2/3 objective 는 VALUE flag 만 더하면 자동 집계(재배선 불필요).
  (`flags.py`·`sequencer._build_truth`·`main.py`·`generate-flags.sh`·`escape-pod.yaml`)
- **방어 오탐 억제** — 새 기법을 프롬프트에 넣으니 방어가 신호 없이 T1611·T1046 과보고(정밀도↓).
  `defender_system.txt` 에 '근거 기반 탐지'(관측 보고서에 신호 있을 때만 보고) 규칙 추가. 전체
  매핑표는 안 박음(기법 분류 변동성은 연구 관찰 대상이라 보존).
- **인프라**: 방어 DGX(.110) 다운 → `config.yaml` `dgx.defender_host` .110→.111(동일 모델
  qwen3.8:27b). Wave1 코드 무관한 순수 장비 이슈였음.

**그날 끝(저녁):** 탈출 체인이 실클러스터에서 검증됐고, 호스트 objective 로 '탈출할 이유'를 부여.
다음: 노드 FLAG 설치(generate-flags.sh) + 자율 런으로 공격자가 실제 탈출·획득하는지 관측.

**21:30 자율 런 결과 + 탈출 경로 breadcrumb**: 호스트 objective 를 켜고 1 에피소드(턴예산 300/3R).
- **인센티브는 행동을 바꿨다** — 공격자가 ①②③④만 하던 걸 넘어, turn 5 에서 `/proc/net/arp`·
  route·노드 IP(10.42.0.1) probing·포트스캔(`nc -zv`, → T1046/disc-net 득점)·`env|grep NODE|HOST`
  로 **호스트 경로를 스스로 탐색**. 목표 한 줄 추가가 탐색 방향을 바꿈.
- **그러나 탈출 체인은 unaided 로 발견 못 함** — admin-sa 토큰을 대시보드로 훔쳐 wget 으로 파드를
  POST 하는 벡터에 도달 못 하고(자기 발판 토큰만 읽어봄), 네트워크/포트로만 접근 시도. 호스트 FLAG
  미획득(flags_reached=1,2,3,4,disc-net). 방어는 정상(마지막 R 에서 NetworkPolicy 로 DB 경로 차단
  → 공격 DEADEND).
- **대응**: DB 경로가 되는 건 internal-wiki 런북이 'admin 콘솔 secret 엔드포인트' breadcrumb 를
  깔아줘서다. 탈출 경로엔 그게 없었다 → `42-internal-wiki.yaml` runbook 에 **"노드 유지보수 런북"**
  추가(admin-sa-token 엔드포인트 + Bearer 로 pods API 에 hostPath 파드 배포 + /etc/shopflow 경로
  힌트). DB 단서와 같은 수위 — 길만 열어주고 실행은 공격자 몫.
- *발견(발표 포인트)*: LLM 공격자는 인센티브만으론 탐색 방향은 바뀌나, obscure 다단계 벡터는
  breadcrumb 없이 못 뚫는다.

**21:50 breadcrumb 재조정 (salience + executability)**: 부스러기 배포 후 재런했으나 공격자가
runbook 의 노드 섹션을 **읽고도 무시**(admin-sa-token 조회·pods API 시도 '0건', grep 확인) —
DB 얻고 더 어려운 호스트 목표를 안 쫓거나 DB 막히면 DB만 붙잡음(pivot 실패). = capability 아닌
**salience 문제**. 두 레버 상향:
- 목표 2단계·명시화(sequencer goal): "DB 얻은 뒤 멈추지 말고 노드로 상승, 런북 '노드 유지보수'
  절차를 따르라".
- 런북에 **실행 가능 레시피**(토큰 조회→`--post-data` 한 줄 JSON 으로 privileged/hostPath 파드
  배포→`/pods/.../log` 회수). busybox wget HTTPS 로 되게 heredoc·리다이렉트 없이 구성.
- *긍정 지표*: 이 재런에서 **정밀도 100%**(오탐 억제 먹힘) · 재현율 60% · 방어 1/3 차단.
- 다음 확인: 발판 busybox wget 이 HTTPS POST 가능한지(안 되면 foothold 에 curl/kubectl 필요).

---

## 2026-10-25 — Wave1 end-to-end 완주 + 대시보드 '노드·호스트 탈출 축'

탈출 레시피까지 깔았는데도 자율 공격자가 안 뚫던 **근본 원인**을 잡고, 공진화 루프에서 호스트
장악이 실제로 발생하는 걸 확인 → 대시보드에 그 축을 시각화.

**근본 원인(탈출 미발동) 2건**:
- `1050047` **공격자가 첫 FLAG 에서 멈췄다** — `react_loop.py` 가 `obs.flag_found` 에 `break`.
  DB FLAG(④) 를 얻는 순간 루프 종료 → 예산이 남아도 호스트 축을 쫓을 기회가 없었다. 목표·레시피·
  HTTPS 가 다 맞아도 이 한 줄 때문에 탈출이 구조적으로 불가능. → 멀티-objective 로 전환(같은 값
  FLAG 는 재기록 안 함, 종료는 timeout/max_steps/give_up/perseveration 이 담당).
- `1e04128` **pods/log 403** — 탈출 파드는 띄워도 `admin-tools` 에 `pods/log get` 이 없어 결과
  (호스트 파일 stdout)를 회수 못 함. exec 는 SPDY 라 wget 불가 → 로그가 유일한 비대화식 회수 경로.
  권한 추가(방어 `restrict_rbac` 가 바인딩째 제거하므로 과권한 봉쇄는 그대로 유효).

**최종 자율 런(완주)**: 1 에피소드에서 공격자가 **두 FLAG 모두 자력 획득** — DB `FLAG{shopflow_…}`(④)
에 더해, admin-sa 토큰 탈취→`--post-data` 로 privileged/hostPath 파드 배포(T1610)→노드 FS 접근
(T1611, Falco "Escape to host filesystem" 점화)→`/etc/shopflow/host.flag` 회수(T1005). 심판은
값 매칭(`match_value`)으로 `host` objective 크레딧. **공진화도 관측**: 다음 라운드에서 방어의
`restrict_rbac` 가 confused-deputy 를 끊어 공격자를 403 으로 잠금(탈출 축 자가 봉쇄).

**대시보드 '노드·호스트 탈출 축' 패널 추가**(`orchestrator/static/dashboard.html`):
- **WHY**: 호스트 장악은 선형 DB 킬체인(①②③④)이 아니라 ②에서 분기하는 **별도 axis**(option A).
  기존 ①→④ 보드에 끼워 넣으면 '깊이'가 왜곡되므로 전용 보드로 분리 — 확장 구조(Wave2/3 축 추가)와도 일치.
- **WHAT**: ② 과권한 SA 분기 → `T1610 컨테이너 배포`→`T1611 호스트 탈출`→`T1005 노드 FLAG(크라운
  주얼 ♚)` 3단계 미니 체인. `flags_reached_cum` 의 비-숫자 마커(`esc-deploy`/`esc-host`/`host`)로
  진행도를, 방어 보고 `T1610`/`T1611` 로 차단을 읽음. 우상단 **'호스트 장악' 배지**(미도달→탈출
  진행→탈출 차단→호스트 장악✓) + KPI 타일 `호스트 장악 N/ep`. 색·컴포넌트는 기존 다크 디자인
  그대로(공격 빨강 `--atk`/방어 파랑 `--def`).
- **검증**: headless(playwright)로 pwned/blocked/none 3상태 렌더·JS 에러 0건 확인 후 반영.

**그날 끝:** 공격자가 **인센티브+레시피 하에서 호스트까지 자율 완주**하고, 방어가 그 축을 되받아치는
공진화가 성립. 대시보드가 DB 축과 탈출 축을 분리해 보여줌. 다음: 정보량 ablation(레시피→힌트→목표만)
으로 '최소 유도' 임계 탐색.

---

## 2026-10-31 — 방어 하네스 분리(VM D) 설계·런북

VM B 한 대에 **대상 클러스터 + 방어 하네스**가 공존하던 걸, 방어 하네스를 **VM D 로 분리**하는
설계·문서화 단계(코드 변경 없음 — 배포·네트워크·kubeconfig·로그 파이프라인 작업).

- `ddc2ff1` **4-VM 토폴로지 + 마이그레이션 가이드** — `docs/diagrams/topology-4vm.svg`(VM D '신규'
  배지, D↔B 관리망 신규 링크), `docs/migration-vm-d-defender.md`(이점·끊어지는 결합 3가지
  (원격 kubectl·로그 pull·DGX)·Phase 체크리스트·config 변경표·롤백).
- **VM D 셋업 런북** `docs/setup-vm-d.md` — VMware 생성→OS→Tailscale→네트워크→kubeconfig→코드→
  로그 sync→config→스모크→systemd→VM C 전환→VM B 정리→e2e 까지 실전 순서.
- **네트워크 단일 NIC 로 정정** — 최초 런북은 관리망(Host-only)+모델망(NAT) 2-NIC 를 가정했으나,
  이 랩은 `192.168.16.0/24`(VMnet8 NAT) **한 망**이 VM↔VM + DGX egress 를 모두 처리함을 실측 확인
  (2-NIC 로 붙였더니 두 인터페이스가 같은 서브넷 → 라우팅 split → `No route to host`). §0·§1·§3 을
  단일 NIC(static `.131`, gw `.2`)로 수정.
- **방어 DGX IP 확정** — 방어 모델 서빙을 `211.170.162.110`(HANDOVER DGX #2)으로 통일. 이전 세션에서
  `.110` 다운으로 `.111` 로 임시 이전했던 것을 되돌림 → VM D 문서·구조도(topology/overview/vm-b)의
  `.111` 을 전부 `.110` 으로 정정(과거 worklog/CHANGELOG 의 당시 기록은 보존).
- **VM B 방어 로직 제거 지침** — 분리의 보안 이점(T1611 탈출 노드에서 방어자+admin 격리)은 VM B 의
  `defense-harness`·`capstone-falco-tail` 를 내려야 완성. 단 리포의 `defender/` 코드는 VM D 가 쓰므로
  삭제하지 않음(런북 §12).
- **sparse-checkout 보정** — VM D 실기동 중 `probe_defender` 가 `ModuleNotFoundError: orchestrator` 로
  죽어, VM D 세트에 `orchestrator/` 추가(`scripts/probe_defender.py` 가 `orchestrator.http_clients` 를
  import — VM D 는 실행 안 하고 코드만 필요). HANDOVER §10·런북 §6·migration 반영.

**실기동·검증(14:00~14:55)**: VM D 를 런북대로 끝까지 올림 — 네트워크(단일 NIC, ens34 NAT)→kubeconfig
(§7 원격 조회·임퍼소네이션 OK)→코드(sparse 에 `orchestrator` 추가)→로그 sync(audit 2956줄; Falco 는
`/etc/shadow` 트리거로 T1552.001 탐지되며 파이프 입증)→config(DGX `.110` 미가동이라 현재 서빙 중인
`.111` 로 기동)→스모크(관측→LLM 43s→패치 라이브 적용)→systemd 3종 상주화→**§12 컷오버**(VM C
`defender_url`→`.131`, VM B `defense-harness`·`capstone-falco-tail` 내림·defender sparse 제거)→
**§13 e2e 1라운드 green**(revert 2s · 공격 deadend · 방어 patched 탐지4 health=True 43s · 검증 blocked).

**그날 끝:** 방어 하네스가 **VM D 로 완전 분리·검증**됨 — 공격자의 호스트 탈출(T1611) 노드에서 방어자와
그 admin kubeconfig 가 격리돼 '독립 관측자' 전제가 성립. DGX 방어는 `.110` 복구 시 `config.yaml`
`defender_host` 한 줄 교체(현재 `.111`). 다음: 정보량 ablation(레시피→힌트→목표만).

---

## 남은 숙제 (루프가 아니라 '숫자'·확장)

- **[다음주] 정보량 ablation 실험**: 공격자에게 주는 유도를 2채널로 단계 축소해 '최소 유도' 임계를
  찾는다. 채널 ① = sequencer goal 주입(현재: 명시 2-FLAG·pivot 지시·메커니즘 한 줄 요약), 채널 ② =
  internal-wiki 런북 breadcrumb(현재: 실행 가능 레시피 전체). 레벨 L0(현재=양 채널 full) → L1(레시피
  →메커니즘 설명만) → L2(위치·존재 힌트만) → L3(목표만, 단서 제거). 각 레벨 N 에피소드씩 돌려 호스트
  완주율·도달 깊이·방어 반응 측정. 현 베이스라인은 양 채널 다 L0. 2채널×4레벨 표 설계는 다음 세션에서.
- **①③ 관측(Falco)**: 현재 FP·FN 이 ①③(HTTP 단서·pod-to-pod)에서 발생 — 감사로그 사각.
  Falco 네트워크 룰이 정밀도·재현율 50%→상향의 선행조건(HANDOVER §11.5).
- **공진화 모드 선택**: 지금은 에피소드마다 리셋(독립 재시행=견고성 곡선). `skip_revert` 로 패치
  누적(군비경쟁=flag 깊이 하강 곡선) 전환 가능 — 서사 결정 후 배선.
- **자동 기동(systemd) 완료 (2026-10-17)**: 대시보드·Falco/감사 동기(VM C)·Falco tail(VM B)을
  `docs/deploy/capstone-*.service` 로 영속화 → 재부팅 시 자동 기동·크래시 자동 복구(수동 nohup 제거).
- **[Wave1b] T1110 Brute Force**: 약한 DB 크레덴셜 무차별 대입. postgres auth 로그(새 관측 소스)
  필요 — `log_connections` 활성화 + tail 유닛 + `log_source` 3번째 reader. 설계는 wave1-design §5.
- **[Wave1 배포]**: 코드·테스트는 끝. VM B `kubectl apply -f k8s/killchain/` + Falco values 재적용,
  VM B/C 하네스 재시작으로 반영(배포 메모: wave1-design §6). `admin-sa-token` Secret 생성 확인.
- **Wave 2/3 (후보)**: 공급망(악성 이미지/initContainer), 지속성(CronJob 백도어), 토큰 탈취 확대 등.
