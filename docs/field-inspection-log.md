# HELIX 실서버 점검 로그

> 실서버에서 **명령으로 직접 확인된 사실**만 날짜별로 기록한다. 설계·결정·추천은 범위 밖.
> 자격증명·토큰 실제 값은 기재하지 않는다(로컬 전용). **최신 날짜가 위**, 새 점검은 새 `## YYYY-MM-DD` 섹션으로 추가.

---

## 2026-11-24

점검 대상: VM A(공격)·VM B(대상)·VM C(오케스트레이터)·Neo4j. (KST)

### 요약

| 영역 | 핵심 확인 | 상태 |
|---|---|---|
| 공격자 메모리 리셋(2.7) | VM C config의 `attacker_ssh` 주석 처리 → 현재 비활성 | 꺼짐 |
| 하네스 재시작 전경로 | 유닛명·NOPASSWD·키 SSH·requiretty 모두 충족 | 가능 |
| 공격자 그래프 백엔드 | `graph_backend: neo4j` (VM A) | 확인 |
| Neo4j 에디션 | community → 복수 named database 불가 | 제약 |
| KG 학습지식 | coevolution 출처 0 · 전부 THEORETICAL(3121) | 깨끗 |
| VM B 자원 | 6 cores · 여유 RAM 5.4Gi · 디스크 32G free | 여유 |
| corp 배포 | 네임스페이스 5개 14일 존재, **파드 0**(워크로드 내려감) | 부분 |
| Docker / k3d (VM B) | Docker 데몬 불가 · k3d 없음 | (나) 전제 미충족 |

### 1. VM C (오케스트레이터) — `~/capstone/config.yaml`

확인 방법: 파일 전체 열람.

| 키 | 값 | 비고 |
|---|---|---|
| `network.attacker_ssh` | **주석 처리됨** (`#  attacker_ssh: "vm-a@192.168.16.129"`) | → 2.7 하네스 메모리 리셋 skip(비활성) |
| `experiment` 섹션 | **없음** | `shopflow_only` 기본 False; 격리는 대시보드 `--shopflow-only` 런타임 제어 |
| `target.kubeconfig` | `/home/vm-c/.kube/vmb-admin.kubeconfig` | baseline 리셋이 쓰는 admin kubeconfig |
| `observability.attacker_db_roles` | `["appuser","legacy_admin"]` | 크라운 채점 롤 |
| `vmware` 블록 | agent · `snapshot_agent_url` · `vmx_path` · `vmrun_path` · `baseline_snapshot: clean-baseline` 존재 | 단 코드 경로는 `BaselineManager`(k8s 네이티브 리셋) 사용 — 스냅샷 매니저 미연결(레거시) |
| `network.shared_token` | 기본 자리표시자 `CHANGE_ME` 미변경 | 위생 항목(로컬 LAN 전용이라 데모엔 무해) |

### 2. VM A (공격) — 하네스 systemd·런타임

```bash
ss -tlnp | grep ':8000'
systemctl cat attack-harness
systemctl show attack-harness -p ActiveState,SubState,ExecMainStartTimestamp,User,FragmentPath
sudo -n -l | grep -iE 'systemctl|ALL'
# (VM C에서) ssh -o BatchMode=yes vm-a@192.168.16.129 'systemctl is-active attack-harness; echo RC=$?'
# (VM C에서) ssh -o BatchMode=yes vm-a@192.168.16.129 'sudo -n -l | grep -iE "systemctl|ALL"'
```

| 항목 | 결과 |
|---|---|
| 포트 8000 주인 | `python3` pid=1320691 (user `vm-a`) |
| systemd 유닛 | `attack-harness.service` — enabled · active · running |
| 유닛 정의 | `Type=simple` · `User=vm-a` · `WorkingDirectory=/home/vm-a/capstone` · `ExecStart=/usr/bin/python3 -m attacker.server --config config.yaml --port 8000` · `Restart=on-failure` · `RestartSec=5` |
| drop-in | `Environment=ATTACK_DEBUG_RAW=1` |
| 가동 시작 | `ExecMainStartTimestamp=2026-11-23 01:42:55 KST` (점검 시점 약 32시간 연속 가동) |
| sudoers | `(ALL) NOPASSWD: /bin/systemctl restart attack-harness` |
| VM C→VM A 키 SSH | 통과(BatchMode) · `systemctl is-active` → `active` · `RC=0` |
| SSH 세션 sudo NOPASSWD | 조회 성공(requiretty 함정 없음) |

**함의**: 하네스 재시작 자동화(`attacker_ssh`)의 전제조건(유닛명 일치·NOPASSWD·키 SSH·requiretty 없음)은 **모두 충족** — 켜는 데 남은 건 VM C config의 주석 해제뿐. `Type=simple`이라 재시작 후 `:8000` 바인드까지 콜드스타트 창 존재.

### 3. VM A (공격) — `~/capstone/config.yaml`

확인 방법: 파일 전체 열람. (공격자 하네스가 실제로 읽는 config — VM C의 것과 별개)

| 키 | 값 |
|---|---|
| `attack.graph_backend` | **`neo4j`** |
| `attack.mode` | `parallel` (플래너+워커) |
| `attack.n_workers` | `2` |
| `attack.intent_budget_sec` / `intent_max_steps` / `max_waves` | `120` / `20` / `6` |
| `attack.exec_namespace` / `exec_pod` | `corp-ext` / `deploy/corp-attacker-foothold` (대시보드가 런마다 오버라이드) |
| `attack.exec_kubeconfig` | `/home/vm-a/harness-exec.kubeconfig` |
| `dgx.request_timeout_sec` | `300` |
| `dgx.attacker_model` / `defender_model` | Qwen3.8-27B Uncensored FP8 / `qwen3.8:27b` |
| `neo4j` | `bolt://127.0.0.1:7687` · user `neo4j` · password 로컬 기본값(미기재) |
| `observability.attacker_db_roles` | `[]` (VM A쪽은 비어 있음 — 판정은 VM C 담당) |
| `refiner.enabled` | `false` |
| `experiment` | `time_limit_sec 300` · `max_rounds 20` · `episodes 50` (CLI로 덮어씀) |

**함의**: 공격자 탐색 그래프·자산·ATTEMPTS·closure가 **Neo4j에 영속**(in-RAM 아님). 따라서 `systemctl restart`는 학습을 비우지 못하며, 회차별 초기화는 앱의 `reset_episode()`가 담당한다.

### 4. Neo4j (VM A 로컬 `bolt://127.0.0.1:7687`)

```bash
cypher-shell -u neo4j -p <pw> "CALL dbms.components() YIELD edition RETURN edition"
cypher-shell -u neo4j -p <pw> "MATCH (s:KnowledgeSource {id:'KS-coevolution-loop'}) RETURN count(s)"
cypher-shell -u neo4j -p <pw> "MATCH (s:KnowledgeSource {id:'KS-coevolution-loop'})--(n) RETURN count(n)"
cypher-shell -u neo4j -p <pw> "MATCH (n) WHERE n.validation_level IS NOT NULL RETURN n.validation_level, count(*)"
```

| 항목 | 결과 |
|---|---|
| 에디션 | **`community`** |
| coevolution 출처 노드(`KS-coevolution-loop`) | **0** |
| 그 출처에 붙은 노드 | **0** |
| validation_level 분포 | **`THEORETICAL` 3121** (OBSERVED·VERIFIED **0**) |

**함의**: ① community라 한 인스턴스에 복수 named database 불가. ② `promote --load`를 한 번도 실행한 적 없음 = KG에 **학습(실증) 지식 미유입, 아레나 중립**. ③ validation_level 보유 노드는 전부 THEORETICAL(제안) — 실증 승급(OBSERVED/VERIFIED) 0회.

### 5. VM B (대상) — k3s 클러스터

```bash
free -h; nproc; df -h /
systemctl is-active k3s
docker version; k3d version
sudo k3s kubectl get nodes -o wide
sudo k3s kubectl get ns
sudo k3s kubectl get pods -A --no-headers | awk '{print $1}' | sort | uniq -c | sort -rn
sudo k3s kubectl describe node | grep -A8 "Allocated resources"
```

#### 호스트 자원
| 항목 | 값 |
|---|---|
| RAM | 7.7Gi (used 1.9 · **available 5.4**) · swap 4Gi(127Mi 사용) |
| CPU | **6 cores** |
| 디스크 `/` | 70G (used 35G · **free 32G** · 53%) |
| k3s 서비스 | `active` (systemd) |
| Docker | CLI 존재하나 **데몬 응답 불가**(현재 사용 불가) |
| k3d | **미설치** |

#### 클러스터
| 항목 | 값 |
|---|---|
| 노드 | `vm-b` Ready control-plane · 44일 · `v1.36.5+k3s1` · IP `192.168.16.128` · containerd |
| 네임스페이스(아레나) | ShopFlow: `frontend`·`backend`·`database`·`internal` (44d) / corp: `corp-ext`·`corp-dmz`·`corp-internal`·`corp-crown`·`corp-defense` (14d) / 기타: `godview`(38d)·`falco`(43d)·`harness`(8d)·`targets`(20d) |
| 파드 수(네임스페이스별) | kube-system 7 · frontend 3 · backend 3 · targets 2 · internal 2 · database 2 · godview 1 · falco 1 · **corp-\* = 0** |
| 노드 자원 할당 | CPU requests 375m(6%) / limits 2250m(37%) · MEM requests 836Mi(10%) / limits 1930Mi(24%) |

**함의**: ① 자원 여유 충분(노드 10% 사용, 6코어, 디스크 32G) — 2번째 클러스터 수용 가능. ② **corp는 이미 네임스페이스로 14일째 존재하나 워크로드(파드) 0** — 어느 방향이든 corp 워크로드 재배포 필요. ③ k3d 분리는 **Docker 데몬 복구부터** 필요.

### 미결정 (점검 아님 — 본 로그 범위 밖)

- corp 배치: (가) 네임스페이스 현행 유지 vs (나) k3d 별도 클러스터 분리
- Neo4j 아레나 격리 정책: C(단일 DB + 운영 규율) 확정 여부
- `attacker_ssh`(2.7) 활성화 여부
