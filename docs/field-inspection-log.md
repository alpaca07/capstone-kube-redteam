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

### 6. 전환 표면·관측 파이프라인 (corp 배치 결정용)

**(나) corp 별도 클러스터 시 바뀌어야 하는 지점** (레포 + 실측):

| # | 위치 | 현재 | 근거 |
|---|---|---|---|
| 1 | VM C baseline 리셋 | `target.kubeconfig` → `192.168.16.128:6443` | config |
| 2 | VM A 발판 exec | `exec_kubeconfig`/foothold → `:6443` | `gen-*-kubeconfig.sh` |
| 3 | VM D 방어 패치 적용 | `/home/vm-d/.kube/vmb-admin.kubeconfig` → `192.168.16.128:6443` | 실측 |
| 4 | god-view 로그 수집 5종 | `vmc-sync-*` 전부 vmb-admin로 단일 k3s pull | 실측 |
| 5 | 공격 엔드포인트 | `192.168.16.128:30080` | config |

→ (나)는 kubeconfig 3곳(A·C·D 전부 현재 `192.168.16.128:6443`) + 관측 5서비스 + 엔드포인트를 corp용으로 복제하는 작업. (가)는 이 배선이 이미 corp까지 돌아감(`vmc-sync-corp-services.sh`, dblog 서비스가 corp-crown 커버).

**VM C — god-view sync 상태 (11:58)**
| 서비스 | 상태 |
|---|---|
| `capstone-sync-audit` / `-dblog` / `-falco` / `-applog` | **active** |
| `capstone-falco-tail` | inactive (falco sync 자체는 active라 데이터는 흐름) |

- dblog 서비스 설명: "VM B database·corp-crown → VM C god-view" (한 서비스가 둘 커버)
- ShopFlow 로그 live(11:58 갱신): `vmb-applog.log` 32MB · `vmb-audit.log` 6.3MB · `vmb-dblog.log` 160MB · `vmb-falco.log` 8.2MB
- corp 로그 **stale**(corp 워크로드 내려감): `vmb-corp-postgres.log`·`vmb-dblog-corp.log` Nov 23 11:03 · `vmb-corp-samba.log` 0B · `vmb-corp-waf.log` Nov 23 04:07

**VM D (192.168.16.131) — 방어자**
| 항목 | 값 |
|---|---|
| `defense-harness` | **active** (python3 pid=329545, `:8000`) |
| 패치 적용 kubeconfig | `/home/vm-d/.kube/vmb-admin.kubeconfig` → `server: https://192.168.16.128:6443` (단일 k3s) |
| `attack_endpoint` | `127.0.0.1:30080` (방어자라 사실상 미사용) |

**VM B — corp 네임스페이스 잔여 객체(파드 0)**
| 네임스페이스 | 객체 수(all/cm/secret/networkpolicy) |
|---|---|
| corp-ext · corp-dmz · corp-internal · corp-crown · corp-defense | 15 · 26 · 16 · 10 · 1 |

- 설정·서비스·시크릿·NetworkPolicy는 남아 있고 **워크로드(파드)만 내려감** → 재배포 = `kubectl apply -f k8s/corp/`

### 7. 아레나 격리 검증 (corp 재배포 후 — (가) 네임스페이스 공존 방식)

corp 워크로드 재배포 완료(8 Deployment Running, 로컬 이미지 `attacker-toolkit`·`corp-waf` containerd 존재 확인).

**네트워크 (cross-arena) — 라이브 `nc` 프로브**
| 방향/구간 | 프로브 | 결과 |
|---|---|---|
| corp→ShopFlow | `postgres.database:5432`(ClusterIP) · `192.168.16.128:30080`(NodePort) | **둘 다 차단(timeout)** |
| ShopFlow→corp | `postgres.corp-crown:5432` · `waf.corp-dmz:80` | **둘 다 차단** |
| corp 존 내부 | ext→WAF **open** · ext→Tomcat/Jenkins/crown **차단** | WAF 유일진입·건너뛰기 차단(README 4a) |
| corp→정상경로 | DNS `kube-dns:53` **open** · 외부 `192.168.16.129:8000` **open** | 격리가 과하지 않음(콜백 정상) |

근거 정책: `egress-isolate-shopflow`(corp 4개 ns, egress=외부+corp+DNS만, 클러스터 CIDR `10.42/10.43` except) + corp `default-deny-ingress`.

**채점 소스 — 아레나별 자동 분리 (대시보드 타깃→배선, `server.py`)**
| 설정 | corp 타깃 | ShopFlow 타깃 |
|---|---|---|
| DB 크라운 로그 | `--db-log-corp` → `vmb-dblog-corp.log` | `vmb-dblog.log` |
| DB 크라운 롤 | `[]` | `appuser,legacy_admin` |
| baseline 리셋 | 전체 | `--shopflow-only`(corp 생략) |
| 크라운 목표물 | `crown-ops`(ops_secrets)+`crown-pii`(customers) | `crown-secrets`(internal_secrets)+`crown-pii` |

→ god-view가 corp 런에선 corp DB 로그만, ShopFlow 런에선 ShopFlow DB 로그만 읽음 — 로그 소스 자체가 바뀌어 교차 오탐 경로 없음.

**탐색그래프 (Neo4j) — episode 분리 + KG 온전**
- `:Explore` episode별 노드: 0=6 · 1=27 · 2=132 · 3=29 · 4=155 · 5=36 · 9000=1 (과거 런 잔여, episode 키로 분리)
- `:Asset` episode별: 0=20 · 1=24 · 2=58 · 3=29 · 4=108 · 5=25
- KG(비 `:Explore`/`:Asset`/`:Counter`): **25,639 노드** — episode 리셋과 무관하게 온전
- `reset_episode()`가 런 시작 때 해당 episode만 `DETACH DELETE` → 한 번에 한 아레나면 교차 없음

**종합**: 네트워크·채점은 아레나별 **하드 격리 확인(라이브)**. 탐색그래프는 **episode-번호 스코프**(아레나 스코프 아님) — "한 번에 하나 + 아레나 간 `promote --load` 비전파"(C) 전제에서 격리 성립. 두 아레나 그래프 동시 보존이 필요하면 회차번호 네임스페이싱(선택).

### 결정·미결정

- **corp 배치 → (가) 네임스페이스 공존 채택** — 재배포 + 격리 검증 완료(§7). (나) k3d 분리는 전환 표면 5곳(§6) 대비 실익 낮아 보류.
- **Neo4j 격리 → C(단일 DB + 운영 규율)** — KG 학습지식 미유입 상태, "한 번에 하나 + 비전파"로 운용.
- (미결정) `attacker_ssh`(2.7) 활성화 — neo4j 백엔드라 학습 리셋은 `reset_episode`가 담당, 현재 불필요.
- (readiness) corp-services 로그 sync 활성화 — corp 런 전 god-view가 corp 서비스 로그(postgres/samba/waf) 보도록.
