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

## 남은 숙제 (루프가 아니라 '숫자'·확장)

- **①③ 관측(Falco)**: 현재 FP·FN 이 ①③(HTTP 단서·pod-to-pod)에서 발생 — 감사로그 사각.
  Falco 네트워크 룰이 정밀도·재현율 50%→상향의 선행조건(HANDOVER §11.5).
- **공진화 모드 선택**: 지금은 에피소드마다 리셋(독립 재시행=견고성 곡선). `skip_revert` 로 패치
  누적(군비경쟁=flag 깊이 하강 곡선) 전환 가능 — 서사 결정 후 배선.
- 감사 동기화(`scripts/vmc-sync-audit.sh`) systemd 영속화 / 대시보드 추가 다듬기.
