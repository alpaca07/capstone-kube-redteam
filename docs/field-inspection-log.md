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
| 커서 버그(방어 observer) | `window_start_ts` floor 수정 → 재시작 직후 유령 0(라이브) | 수정·확정 |
| corp 공진화(회차1 R3) | R1 침해→패치→R2·R3 차단(라이브) | 성립 |
| 전환 격리(공격자) | ShopFlow R1 `자산 0개` 시작 → `reset_episode` 동작 | 확정 |
| 전환 격리(방어자)(11) | ShopFlow R3 탐지·패치 전부 ShopFlow ns, corp 흔적 0, 크라운 차단 | 확정 |
| ShopFlow 공진화(11) | R3 패치 → R4 재공격 차단(DB refused, dashboard timeout) | 성립 |
| DGX 호스트 정리(11) | `.109` attacker · `.110` planner+defender(웜) · `.111` 미사용 | 확인 |

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

### 8. 방어 observer 관측창(커서) 수정·실증

- **버그**: observer `collect(since_ts=self._cursor)` + `_cursor` 초기값 `0.0` → VM D 재시작 직후 첫 턴이 1970부터 전체 로그(이전 run·회차·격리테스트)를 현재 공격으로 읽음. corp 런 #1에서 12:51 nc 격리테스트(T1046)·백로그 유입 → `delete_pod frontend`(ShopFlow 파드) 유령 패치 관측.
- **수정**(scorer `crowns_in_window(t0,t1)`와 동일 기준): 라운드 t0 → `DefenseTurnStart.window_start_ts` 전달, observer `since_ts=max(_cursor, window_start_ts)`, `_cursor` 초기값 `time.time()`. 커밋 `cdcdcfa`(`common/messages.py`·`orchestrator/sequencer.py`·`defender/server.py` + 테스트 634 통과). VM C·VM D 반영.
- **실증(라이브)**: VM D 재시작(=커서 리셋 조건) 직후 corp 재런 → **R1 패치 `corp-tomcat`·`corp-jenkins` 둘뿐, `delete_pod frontend`·T1046 유령 0.** 백로그 유입 없음 → 확정.

### 9. corp 공진화 실행 결과 (회차1 라운드3, 라이브)

- **R1**: `crown-read`(PII `customers`)+`crown-read-ops`(`ops_secrets`) 둘 다 반출 성공 → 방어 T1213 정탐 → `patch_app corp-tomcat`·`corp-jenkins` 적용+재기동 → 검증 **차단**(재생 시 크라운 재도달 없음).
- **R2·R3**: `healthcheck.jsp` **404**(tomcat 하드닝 제거)·`shell.jsp` **500**. 공격자 대안(직접 postgres·nmap·tomcat `manager` 403) 전부 실패 → 크라운 미반출 → 방어·검증 skip. 공격→패치→재공격 차단 루프 성립.
- **R1 탐지 품질**: 정탐 `T1213`(jenkins→corp-crown) / 오탐 `T1190`(공격자 PUT 웹셸 컴파일에러 500·미발현, 실제 유출은 사전배치 `crown-read` 래퍼 T1213) / 미탐 `T1068`·`T1548`(래퍼 권한상승 하위기법, god-view log-observed인데 방어 못 봄).
- **대시보드 수정**: skip 라운드 건강상태 '서비스 중단' 오표기 → `end_reason="skipped"` 분기로 '해당 없음'(렌더 10곳, `_dSkipped`). 채점 불변(과잉차단은 `patch_applied` 가드). 커밋 `994671d`·UI/SERVER_BUILD 18. 라이브 '해당 없음' 확인.

### 10. 타깃 전환 격리 실증 (corp→ShopFlow)

- **공격자(라이브) — 전환 격리 완전 확정**: ShopFlow R1 wave1이 **`자산 0개(미탐색 0)·지난라운드침해 0건`**으로 시작 — 상주 하네스(PID 동일)인데 corp 최종 자산(14개) 미인수. `attacker/server.py:236` R1 조건(`round<=1`) → `reset_episode(1)`(`MATCH (n:Explore {episode:1}) DETACH DELETE`) → corp episode-1 노드 제거 후 백지 탐색. R3에서 `FLAG{shopflow_…}` 반출(크라운 도달), 공격 대상 전부 ShopFlow(`postgres.database`·`legacy_admin`·`internal_secrets`/`customers`) — **corp 흔적 0**.
- **baseline revert 비대칭(라이브)**: corp 런(`so:false`)은 init 때 ShopFlow patch_app까지 역산(`main.py:127` `_corp_patch_app + _shopflow_patch_app`) → ShopFlow 4파드 재생성(kubectl age 38분). ShopFlow 단독 런(`so:true`)은 corp 무간섭. 리셋 범위 비대칭이지 학습·채점 누수 아님.
- **방어 floor(시간) 확정**: ShopFlow R3 floor=R3 t0(~15:54)라 15:00 corp 런이 시간상 제외 — 시간 누수 0(`observer.py:170` audit·falco 둘 다 since_ts 하한).
- **방어 아레나-범위 누수 발견(별개 축)** 🚨: ShopFlow R3 저널에 corp 3군데 — T1611 오탐(`corp-internal/redis`, 실재 redis가 Falco 발화), `delete_pod corp-ext/corp-attacker-foothold`, `restrict_pod_security corp-ext`. 원인: 방어자 전역 관측·패치(`topology._discover_namespaces` 전역, observer ns 필터 없음) — (가) 공유클러스터 성질. corp 런이 안 샜던 건 그땐 패치가 app 단위(target 키 지정)였기 때문.
- **영향**: 채점 판정(차단) 무사(크라운 기반). 탐지 정밀도에 corp 오탐 혼입 + corp-ext 부작용(발판은 Deployment 자가복구, **PSA `enforce=baseline` 라벨 눌어붙음** → 수동 복구함).
- **수정(라이브 점검 반영)**: 아레나 네임스페이스 스코프 — observer/topology/patcher 3중 방어. 커밋 `26853b2`(636 통과). 점검분: ns 맵 확정 ShopFlow`{frontend,backend,database,internal,targets}`/corp`{corp-ext,corp-dmz,corp-internal,corp-crown}`(`corp-defense`는 방어장비라 제외), Falco `k8s.ns.name` 채워짐(R3 렌더가 증명), corp-ext PSA 라벨 `kubectl label … enforce-` 수동 복구.

### 11. 방어 아레나-스코프 최종 실증 (ShopFlow 회차1 R4, 라이브)

defender_host `.111`→`.110` 변경(VM D `config.yaml` sed + `systemctl restart defense-harness`) 후 ShopFlow 4라운드 실행. `.110`은 `qwen3.8:27b` 웜 상태(expires 2319, 11ms), 플래너와 같은 호스트이나 라운드 내 순차(attack→defense)라 경합 없음.

**타임라인 (21:43~22:14 KST)**
| 라운드 | 크라운 | 방어 | 비고 |
|---|---|---|---|
| R1 | 미반출 | skipped | 탐색·자산 발견 단계 |
| R2 | 도달(customers_pii+internal_secrets) | **LLMTimeout(300s)** `.111` | 설정 변경 직전 — 무효 패치 |
| R3 | 도달(FLAG{shopflow_…}) | **탐지3·패치4·차단** `.110` | ⭐ 핵심 검증 라운드 |
| R4 | 미도달(DB refused) | skipped | R3 패치가 재공격 차단 |

**R3 아레나 격리 검증 — corp 아티팩트 0건:**
- 탐지: T1552.001(`internal`)·T1210(`frontend→database`)·T1078(`database+internal`) — **전부 ShopFlow 네임스페이스**
- 패치: `delete_pod frontend/attacker-foothold`·`restrict_rbac admin-tools-binding`(cluster)·`add_networkpolicy database`·`add_networkpolicy internal` — **전부 ShopFlow + cluster-scoped**
- §10 누수(T1611 `corp-internal/redis`, `delete_pod corp-ext`, `restrict_pod_security corp-ext`) → **재현 0**
- 검증: replay-crown 재도달 없음 → **차단**

**공진화 확인 (R3→R4):** R4 공격이 `postgres.database:5432` connection-refused(R3 NetworkPolicy), `admin-dashboard` timeout(R3 delete_pod+netpol) — R3 패치가 재진입 경로 봉쇄.

**R2 LLMTimeout 원인:** defender_host `.111`→`.110` 변경이 R2~R3 사이에 적용. R2 방어는 `.111`(40B 모델 `qwen3.8-40b-heretic` 로드 중 → 27B 스왑 타임아웃), R3부터 `.110` 웜 `qwen3.8:27b` 사용(167s 정상 완료).

### 결정·미결정

- **corp 배치 → (가) 네임스페이스 공존 채택** — 재배포 + 격리 검증 완료(§7). (나) k3d 분리는 전환 표면 5곳(§6) 대비 실익 낮아 보류.
- **Neo4j 격리 → C(단일 DB + 운영 규율)** — KG 학습지식 미유입 상태, "한 번에 하나 + 비전파"로 운용.
- (미결정) `attacker_ssh`(2.7) 활성화 — neo4j 백엔드라 학습 리셋은 `reset_episode`가 담당, 현재 불필요.
- (readiness) corp-services 로그 sync 활성화 — corp 런 전 god-view가 corp 서비스 로그(postgres/samba/waf) 보도록.
- **커서 버그(방어 observer) 수정·실증 완료**(§8·§9) — `window_start_ts` floor, 커밋 `cdcdcfa`. 재시작 직후 corp R1 유령 0.
- **대시보드 skip 건강상태 '해당 없음' 수정**(§9) — 커밋 `994671d`, BUILD 18.
- **방어 아레나 네임스페이스 스코프 구현+실증 완료**(§10·§11) — observer/topology/patcher 3중 방어, 커밋 `26853b2`, 636 통과. §11에서 R3 corp 아티팩트 0건 확인 → 교차오염 봉합 **확정**.
- **공격자 전환 격리 실증 완료**(§10) — `자산 0개` 시작, `reset_episode` 동작 확인.
- **방어 전환 격리 실증 완료**(§11) — ShopFlow R3 탐지·패치 전부 ShopFlow 네임스페이스 + cluster-scoped, corp 흔적 0, 크라운 차단. 공진화(R3→R4 재공격 봉쇄)도 확인.
