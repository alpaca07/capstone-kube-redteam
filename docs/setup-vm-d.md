# VM D 셋업 런북 — VMware 생성부터 end-to-end 검증까지

> 방어 하네스를 VM B 에서 분리해 **VM D** 로 올리는 전체 실전 절차. 설계·이유·체크리스트는
> [migration-vm-d-defender.md](migration-vm-d-defender.md), 토폴로지는
> [diagrams/topology-4vm.svg](diagrams/topology-4vm.svg). 작성 2026-10-31.
>
> 기준 주소(관리망 192.168.16.0/24): VM A `.129` · VM B `.128` · VM C `.130` · 호스트 `.1` ·
> **VM D `.131`(신규)**. DGX 방어 모델 = `211.170.162.110:11434`(HANDOVER DGX #2).
> k3s 는 containerd(도커 없음).

---

## 0. VM D 자원·네트워크 계획

| 항목 | 값 | 비고 |
|------|----|------|
| OS | 기존 VM 과 동일(Ubuntu Server 22.04 LTS 권장) | k3s/systemd/Python 환경 일치 |
| vCPU / RAM / Disk | 2 vCPU / 4 GB / 30 GB | LLM 은 DGX 라 가벼움 |
| **NIC 1 (단일)** | VM C 와 동일 VMnet (= `192.168.16.0/24` 서빙 — 이 랩은 VMnet8 NAT) | static `192.168.16.131/24`, gw `.2`. **VM↔VM(관리) + DGX(모델) 모두 이 한 망** |
| 공격망 | **연결하지 않음** | 공격자와 격리 |

> ⚠️ **NIC 은 1개만.** 이 랩은 `192.168.16.0/24`(VMnet8 NAT) 한 망이 VM 간 통신과 DGX 외부
> egress 를 모두 처리한다(2026-10-31 실측 확인: VM A/B/C `.128/.129/.130` 이 이 NAT 대역). NIC 을
> 2개(관리망+모델망) 붙이면 둘 다 같은 서브넷이 돼 라우팅이 split → 한쪽 ARP 실패(No route to host).
> VM B/C 의 어댑터 VMnet 번호를 확인해 VM D 도 **동일한 하나**로 맞춘다. (공격망만 별도 Host-only 로 격리)

---

## 1. VMware Workstation — VM 생성

1. **File > New Virtual Machine** → *Custom(advanced)* → Hardware compat 기본값.
2. *Installer disc image(ISO)* 에 Ubuntu Server ISO 선택(또는 "I will install the OS later").
3. Guest OS: Linux → Ubuntu 64-bit.
4. VM 이름 `vm-d-defender`, 저장 위치 지정.
5. Processors 2, Memory 4096 MB.
6. Network type 기본(나중에 조정). **Disk**: *Create a new virtual disk* → 30 GB. 디스크 옵션:
   - **Store virtual disk as a single file** 선택 **(권장)** — NTFS(Windows) 호스트는 단일 `.vmdk` 에 파일 크기 제한이 없고, I/O 가 조금 더 빠르며 파일 관리가 단순하다.
   - *Split virtual disk into multiple files*(2 GB 조각)는 **FAT32/exFAT 처럼 큰 단일 파일을 못 담는 매체**에 VM 을 두거나 그런 곳으로 옮길 때만. 랩 호스트가 NTFS 면 쓸 이유 없음.
   - *Allocate all disk space now*(사전할당·thick)는 체크하지 않음 — VM D 는 가벼워 **grow as needed(thin)** 로 공간 절약.
   - 참고: 스냅샷은 단일/분할과 **무관하게** 델타 파일로 생기므로 이 선택이 스냅샷 동작엔 영향 없다.
7. **Customize Hardware** 에서 네트워크 어댑터는 **VM C 와 동일한 VMnet 하나만** 둔다
   (= VM A/B/C 가 쓰는 `192.168.16.0/24` 망 — 이 랩은 NAT/VMnet8).
   - VM B/C 의 Settings > Network Adapter 에서 그 VMnet 번호를 확인해 VM D 도 동일하게 맞춘다.
   - 공격망 어댑터는 추가하지 않음.
   - ⚠️ 어댑터를 2개(관리망+모델망) 붙이지 말 것 — 둘 다 같은 서브넷이 돼 라우팅이 split 된다(§3).
8. Finish → VM 전원 ON → ISO 로 부팅.

---

## 2. OS 설치 + 기본 설정

Ubuntu Server 설치 중:
- Hostname: `vm-d`
- 사용자: `vm-d`(기존 VM 네이밍과 맞춤)
- **Install OpenSSH server** 체크
- 디스크 전체 사용(기본)

설치 후 첫 로그인:
```bash
sudo apt update && sudo apt -y upgrade
sudo timedatectl set-timezone Asia/Seoul
sudo apt -y install chrony           # NTP 동기(시계 스큐 방지)
```

---

## 2.5 Tailscale 설치 (원격 관리 접속 — 기존 VM 과 동일)

개발 중 어디서든 SSH·코드 pull 하려고 기존 VM(A/B/C)처럼 Tailscale 를 깐다. **실험 중에는
끄는 게 원칙**(격리 — 랩은 관리망/모델망만으로 돈다. README 의 개발/실험 모드 표와 동일).

```bash
# (VM D) 설치
curl -fsSL https://tailscale.com/install.sh | sh
# 로그인 (인터랙티브: 출력된 URL 을 브라우저로 인증)
sudo tailscale up --hostname vm-d --ssh
#   재사용 auth key 가 있으면 무인 가입:  sudo tailscale up --authkey tskey-... --hostname vm-d --ssh
tailscale ip -4          # 할당된 100.x 주소 확인
tailscale status         # 다른 VM(A/B/C) 이 보이면 정상
```

- `--ssh` 는 Tailscale SSH(태일넷 내 키 없이 SSH). 기존 VM 이 일반 SSH 만 쓰면 생략 가능.
- **실험 돌릴 때는 끈다:**
  ```bash
  sudo tailscale down                       # 세션만 내림(다시 up 하면 복구)
  # 완전 비활성(부팅에도 안 뜨게): sudo systemctl disable --now tailscaled
  ```
- ⚠️ 공수 루프(방어자 ↔ VM B ↔ DGX)는 **관리망·모델망**으로 도므로 Tailscale 를 꺼도 영향 없다.
  Tailscale 는 '운영자의 원격 접속' 편의일 뿐 데이터 경로가 아니다.

---

## 3. 네트워크 설정 (netplan) — 단일 NIC

> 이 랩은 `192.168.16.0/24`(VMnet8 NAT) **한 망**이 VM↔VM 통신과 DGX 외부 egress 를 모두
> 처리한다(2026-10-31 실측: `ping -I <iface>` 로 VM B/C 도달 확인). 2-NIC 분리는 불필요·금물.

인터페이스명 확인(보통 `ens33`):
```bash
ip -br a           # 192.168.16.x 를 받은(또는 받을) 인터페이스 확인
```

`/etc/netplan/50-cloud-init.yaml` (인터페이스명은 위 결과로 교체):
```yaml
network:
  version: 2
  ethernets:
    ens33:                         # VM A/B/C + DGX 모두 이 망(VMnet8 NAT)
      addresses: [192.168.16.131/24]
      routes:
        - to: default
          via: 192.168.16.2        # NAT 게이트웨이
      nameservers:
        addresses: [192.168.16.2, 8.8.8.8]
```
```bash
sudo chmod 600 /etc/netplan/50-cloud-init.yaml   # netplan '권한 너무 열림' 경고 방지
sudo netplan apply
```
> ⚠️ **NIC 을 2개 붙이지 말 것.** 둘 다 `192.168.16.0/24` 가 되면 라우팅이 split 돼 한쪽이
> ARP 실패(No route to host) 한다. VM C 처럼 **단일 NIC** 로 간다.

**도달성 확인(중요):**
```bash
ip -br a                                              # .131 이 그 NIC 에만 떠야
ping -c1 192.168.16.128                               # VM B
ping -c1 192.168.16.130                               # VM C
nc -zv 192.168.16.128 6443                            # VM B k3s API
curl -s http://211.170.162.110:11434/api/tags | head  # DGX 방어 모델(.110)
```
- VM B 6443, DGX 11434 가 안 열리면 **VMware NAT/방화벽 allowlist** 를 먼저 손본다(여기서 막히면 뒤가 전부 막힘).

---

## 4. 필수 패키지

```bash
sudo apt -y install python3-pip git curl
# kubectl (하네스가 subprocess 로 호출) — k3s 와 호환되는 안정 버전
curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl"
sudo install -m 0755 kubectl /usr/local/bin/kubectl && rm kubectl
kubectl version --client
```

---

## 5. (VM B 에서 1회) VM D 용 admin kubeconfig 발급

VM D 가 VM B 의 k3s API 에 붙어 패치·조회를 하려면 admin kubeconfig 가 필요하다. VM C 가 쓰는 것과
동일 패턴:
```bash
# (VM B)
sudo sed "s/127.0.0.1/192.168.16.128/" /etc/rancher/k3s/k3s.yaml > /tmp/vmb-admin.kubeconfig
# VM D 로 복사(관리망). scp 가 되면:
scp /tmp/vmb-admin.kubeconfig vm-d@192.168.16.131:~/.kube/vmb-admin.kubeconfig
#   (디렉토리 없으면 VM D 에서: mkdir -p ~/.kube)
```
- 전제: VM B k3s 가 이미 `write-kubeconfig-mode: "0644"` 로 떠 있음(§9 HANDOVER, 이미 적용됨).
- TLS: k3s 기본 서버 인증서에 노드 IP(`192.168.16.128`)가 SAN 으로 들어가 있어 VM C 가 이미 이 방식으로
  붙고 있으므로 VM D 도 그대로 된다. 혹시 핸드셰이크 실패하면 VM B k3s 에
  `--tls-san 192.168.16.128` 추가 후 재기동, 또는 kubeconfig 에 `insecure-skip-tls-verify: true`.

---

## 6. 코드 배포 (sparse-checkout)

VM D 는 방어 코드 + 공통 + 스크립트 + docs 를 받는다(k8s/ 는 클러스터 호스팅 VM B 전용). `orchestrator/`
도 포함하는데, 스모크용 `scripts/probe_defender.py` 가 `orchestrator.http_clients`(HTTP 클라이언트)를
import 하기 때문(VM D 가 orchestrator 를 *실행*하진 않음 — 코드만 있으면 됨):
```bash
# (VM D)
cd ~
git clone --no-checkout https://github.com/alpaca07/capstone-kube-redteam.git capstone
cd capstone
git sparse-checkout init --cone
git sparse-checkout set common defender orchestrator scripts docs
git checkout main
pip install -r requirements.txt     # fastapi·uvicorn·pydantic·requests·pyyaml
mkdir -p ~/capstone/logs
```

---

## 7. kubeconfig 검증 (여기서 막히면 패치가 전부 실패)

```bash
export KC=~/.kube/vmb-admin.kubeconfig
kubectl --kubeconfig $KC get ns                                    # 0.x초로 떠야
kubectl --kubeconfig $KC get deploy -A | head                      # healthcheck 가 쓰는 조회
kubectl --kubeconfig $KC auth can-i get secrets -A \
  --as system:serviceaccount:internal:admin-sa                     # state_query 임퍼소네이션 → yes
kubectl --kubeconfig $KC auth can-i delete clusterrolebinding      # restrict_rbac → yes
```
- `get ns` 가 느리거나 timeout → 관리망/6443 문제(§3).
- `can-i … --as` 가 `no`/에러 → kubeconfig 가 admin 이 아님(비관리 토큰 kubeconfig 를 받았을 때).

---

## 8. 로그 sync 기동 (방어자의 '눈')

VM D 는 VM B 의 감사로그·Falco 로그를 **원격 pull** 해 로컬 파일로 떨군다(VM C 와 동일 메커니즘).

수동 테스트:
```bash
# 감사로그 (godview/audit-tail DaemonSet)
KUBECONFIG=~/.kube/vmb-admin.kubeconfig \
  bash ~/capstone/scripts/vmc-sync-audit.sh ~/capstone/logs/vmb-audit.log &
# Falco
KUBECONFIG_VMB=~/.kube/vmb-admin.kubeconfig \
  FALCO_LOCAL=~/capstone/logs/vmb-falco.log \
  bash ~/capstone/scripts/vmc-sync-falco.sh &
sleep 10
wc -l ~/capstone/logs/vmb-audit.log ~/capstone/logs/vmb-falco.log   # ★ 0 이 아니어야(채워져야)
```
- **이 두 파일이 채워지지 않으면 방어자는 조용히 NOOP** 한다. 반드시 먼저 확인.
- 확인되면 위 임시 프로세스는 kill 하고 §11 에서 systemd 로 상주화.

---

## 9. config.yaml 작성

`~/capstone/config.yaml` (민감값은 gitignore). VM D 기준으로 바뀌는 핵심 블록:
```yaml
dgx:
  attacker_host: "211.170.162.109"     # VM D 는 미사용(스키마용)
  defender_host: "211.170.162.110"     # ★ 방어 모델 (DGX #2)
  port: 11434
  attacker_model: "hf.co/.../Qwen3.8-27B-Uncensored-...-GGUF"
  defender_model: "qwen3.8:27b"
  temperature: 0
  request_timeout_sec: 300
  max_tokens: 1024

network:
  attacker_url: "http://192.168.16.129:8000"
  defender_url: "http://192.168.16.131:8000"   # VM D 자신(스키마용)
  shared_token: "<기존과 동일한 관리망 토큰>"

target:
  attack_endpoint: "192.168.16.128"
  kubeconfig: "/home/vm-d/.kube/vmb-admin.kubeconfig"     # ★ 원격 admin kubeconfig

observability:
  audit_log_path: "/home/vm-d/capstone/logs/vmb-audit.log"   # ★ VM D 로컬 동기본(절대경로)
  falco_log_path: "/home/vm-d/capstone/logs/vmb-falco.log"   # ★

experiment:          # 방어 하네스는 time_limit_sec(LLM 타임아웃)만 참조
  time_limit_sec: 900
  max_rounds: 20
  episodes: 50
  n_consecutive_defense: 3

flags:
  format: "FLAG{...}"
```
> 나머지(`vmware`, `attack` 블록 등)는 `common/config.example.yaml` 기본값 그대로 둬도 방어 하네스
> 동작엔 무관. 경로는 **절대경로**(Observer 가 `~` 확장 안 함).
>
> ⚠️ **DGX 방어 IP는 쓰기 전에 `curl http://<IP>:11434/api/tags` 로 서빙 확인.** 이 랩 기준 `.110`
> 이 정상이지만, 다운이면 빈 응답/`Connection refused`(네트워크는 OK, 서비스만 없음 — `curl -v`로 구분)
> → 그때 **현재 서빙 중인 DGX(예: `.111`)로 임시 교체**하고 `defender_model`이 그 서버 `/api/tags`에
> 뜨는지 확인. 복구되면 `defender_host` 한 줄만 되돌림.

---

## 10. 스모크 테스트 (systemd 전에 손으로)

로그 sync 가 떠 있는 상태에서:
```bash
cd ~/capstone
python3 -m defender.server --config config.yaml --port 8000     # 창 1
```
다른 창(VM D 또는 VM C)에서 방어자 단독 probe:
```bash
python3 -m scripts.probe_defender --config config.yaml           # 창 2
```
- 기대: `patch_applied`/`end_reason`/`detected`/`patch_attempts` 가 찍힘. 현재 클러스터에 공격 흔적이
  있으면 `detected` 에 기법이, 없으면 비어 있을 수 있음(정상).
- `end_reason=error` + `k3s.yaml: permission denied` → §5 kubeconfig 권한.
- `detected=[]` 가 계속 → 로그 sync 파일이 비어 있거나 경로 오타(§8).

---

## 11. systemd 상주화 (VM D)

**방어 하네스** `/etc/systemd/system/defense-harness.service`
(기존 `docs/deploy/defense-harness.service` 를 경로만 VM D 로):
```ini
[Unit]
Description=Capstone defense harness (VM D)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vm-d
WorkingDirectory=/home/vm-d/capstone
Environment=PATH=/usr/local/bin:/usr/bin:/bin
ExecStart=/usr/bin/python3 -m defender.server --config config.yaml --port 8000
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

**로그 sync 2종** — ⚠️ **audit 는 `KUBECONFIG` 기본값이 VM C 경로라 반드시 override**(안 하면 로그가
안 쌓여 방어자가 조용히 NOOP). falco 는 `$HOME` 기반이라 vm-d 기본값과 일치하지만 명시한다.

`/etc/systemd/system/capstone-sync-audit.service`:
```ini
[Unit]
Description=Capstone 감사로그 동기 (VM B -> VM D)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=vm-d
WorkingDirectory=/home/vm-d/capstone
Environment=PATH=/usr/local/bin:/usr/bin:/bin
Environment=KUBECONFIG=/home/vm-d/.kube/vmb-admin.kubeconfig
ExecStart=/usr/bin/bash scripts/vmc-sync-audit.sh /home/vm-d/capstone/logs/vmb-audit.log
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
```
`/etc/systemd/system/capstone-sync-falco.service`:
```ini
[Unit]
Description=Capstone Falco 로그 동기 (VM B -> VM D)
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
User=vm-d
WorkingDirectory=/home/vm-d/capstone
Environment=PATH=/usr/local/bin:/usr/bin:/bin
Environment=KUBECONFIG_VMB=/home/vm-d/.kube/vmb-admin.kubeconfig
Environment=FALCO_LOCAL=/home/vm-d/capstone/logs/vmb-falco.log
ExecStart=/usr/bin/bash scripts/vmc-sync-falco.sh
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
```
적용:
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now capstone-sync-audit capstone-sync-falco   # 로그 먼저
sleep 10 && wc -l ~/capstone/logs/vmb-*.log                            # 채워지는지 확인
sudo systemctl enable --now defense-harness                           # 그 다음 하네스
curl -sS -o /dev/null -w '%{http_code}\n' http://localhost:8000/status # 405 면 살아있음
```

---

## 12. VM C 전환 + VM B 정리

**VM C** — 방어 하네스 호출 대상을 VM D 로:
```bash
# (VM C) config.yaml 수정: network.defender_url → http://192.168.16.131:8000
sed -i 's#defender_url:.*#defender_url: "http://192.168.16.131:8000"#' ~/capstone/config.yaml
sudo systemctl restart capstone-dashboard    # 오케스트레이터/대시보드 재시작
```

**VM B** — 방어 하네스 내리기 **(분리의 보안 이점은 여기서 완성됨 — 안 내리면 탈출 노드에 방어자+admin 접근이 그대로 남아 분리 의미가 없다):**
```bash
# (VM B)
sudo systemctl disable --now defense-harness        # ① 실행 중지·부팅 비활성(필수)
sudo systemctl disable --now capstone-falco-tail    # ② 방어자 전용 로컬 tail(god-view 는 VM C 가 별도 sync)
git sparse-checkout set common k8s docs tests       # ③ 로컬 체크아웃에서 defender 코드 제거(위생)
# ④ (선택 하드닝) 로컬 비root 방어자가 떠났으니 k3s admin kubeconfig 를 다시 600 으로 되돌려도 됨:
#    sudo sed -i '/write-kubeconfig-mode/d' /etc/rancher/k3s/config.yaml && sudo systemctl restart k3s
#    — 이후 VM C/VM D 는 각자 복사해 둔 vmb-admin.kubeconfig 로 붙으니 영향 없음
#    — 단 privileged 호스트 탈출은 root 권한이라 600 도 읽음(완화일 뿐 차단은 아님)
```
> ⚠️ 리포지토리의 `defender/` 는 **삭제하지 않는다** — VM D 가 받아 쓴다. VM B 에서 '없앤다'는 건
> 그 VM 에서 **안 돌리고(서비스)·안 두는(체크아웃)** 것이지 코드 삭제가 아니다.

---

## 13. end-to-end 검증

```bash
# (VM C) 1 에피소드로 전체 루프
cd ~/capstone
python3 -m orchestrator.main --episodes 1 --max-rounds 3 --time-limit 900 --max-tokens 1024
```
확인 포인트:
- 방어 턴이 **VM D 에서** 수행되는가 — `journalctl -u defense-harness -f` (VM D) 에 로그
- 패치가 VM B 클러스터에 적용되는가 — `kubectl --kubeconfig ~/.kube/vmb-admin.kubeconfig get netpol -A`
- god-view 채점·대시보드 정상(VM C `orchestrator/logs/rounds.jsonl`, `:8090`)

---

## 14. (선택) VM D 클린 스냅샷

전부 녹색이면 VMware 에서 VM D 스냅샷(`vm-d-clean`) 하나 떠두면 재설치 없이 되돌릴 수 있다.

---

## 롤백

문제 시 VM C `defender_url` 을 `http://192.168.16.128:8000`(VM B)로 되돌리고 VM B 의
`defense-harness` 를 다시 `enable --now` 하면 즉시 원복(코드·클러스터 상태 변경 없음).

## 자주 터지는 3가지 (재강조)
1. **kubeconfig** — 원격 접속/임퍼소네이션 권한(§5·§7).
2. **로그 sync** — VM D 에 안 뜨면 방어자가 조용히 NOOP(§8·§11, 하네스보다 먼저).
3. **VM C `defender_url`** — 안 바꾸면 계속 VM B 를 호출(§12).
