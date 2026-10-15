# 공격 발판 (in-cluster exec) — 설치 절차

자동 공격 하네스가 "웹 계층이 침해된 클러스터 내부 위치"에서 공격하도록, frontend ns 에 유휴
발판 파드를 두고 명령을 그 안에서 `kubectl exec` 로 실행한다. 왜 필요한지는
[`../README.md`](../README.md) 와 [`00-attacker-foothold.yaml`](../00-attacker-foothold.yaml) 주석 참고.

> 핵심: 킬체인 ①③④ 는 전부 `.svc.cluster.local`(ClusterIP) 내부 주소 → 클러스터 밖(VM A)에선
> 못 닿는다. 이 발판이 그 간극을 메운다. 발판 kubeconfig 는 **frontend 파드 exec 전용**이라
> ②(admin-sa 과권한)는 공격자가 여전히 스스로 털어야 한다.

**이미지 = `postgres:16-alpine`** — ShopFlow 가 이미 쓰는 공식 이미지(수동 walkthrough 의 dbattack
과 동일). 커스텀 빌드·도커 **불필요**. 내장 도구: `psql`(④ DB) · `wget`(① HTTP) · `nc`(③ 포트) ·
`nslookup`(DNS) · `sh` (alpine busybox). 이미 노드 containerd 에 캐시돼 있을 것(DB 가 같은 이미지).

## 1. 이미지 캐시 확인 (VM B)
```bash
sudo k3s ctr images ls | grep 'postgres:16-alpine'    # 이미 있으면 OK (DB 와 동일 이미지)
# 혹시 없으면(인터넷 ON 상태에서) 미리 당겨두기:
sudo k3s crictl pull docker.io/library/postgres:16-alpine
```

## 2. 발판 리소스 적용 (VM B)
```bash
kubectl apply -f k8s/killchain/00-attacker-foothold.yaml
kubectl -n frontend rollout status deploy/attacker-foothold      # Running 확인
```

## 3. exec 전용 kubeconfig 생성 → VM A 로 (VM B)
```bash
bash k8s/killchain/gen-foothold-kubeconfig.sh foothold.kubeconfig https://<VM_B_공격망_IP>:6443
scp foothold.kubeconfig vm-a:~/foothold.kubeconfig
# 동작/경계 확인:
kubectl --kubeconfig foothold.kubeconfig -n frontend exec deploy/attacker-foothold -- psql --version   # psql 버전
kubectl --kubeconfig foothold.kubeconfig -n database get secret                                         # forbidden(정상)
```

## 4. VM A 준비
- `kubectl` 설치돼 있어야 함 (`which kubectl`).
- `config.yaml` 의 `attack` 섹션:
  ```yaml
  attack:
    exec_mode: true
    exec_kubeconfig: "/home/vm-a/foothold.kubeconfig"
    exec_namespace: "frontend"
    exec_pod: "deploy/attacker-foothold"
  ```

## 5. VM C 준비
- VM C `config.yaml` 에도 `attack.exec_mode: true` (오케스트레이터가 외부 발판 endpoint 를 안 주도록).
  VM A→VM B:6443(k3s API) 도달 가능해야 함(지금 flat 망은 OK, 3망 땐 공격망에 6443 허용).

## 6. clean-baseline 재스냅샷 (발판 파드가 떠 있는 상태로)
발판 파드가 베이스라인에 포함돼야 매 라운드 revert 후에도 존재한다. 방어자까지 떠 있는 상태에서
clean-baseline 을 다시 저장(호스트 스냅샷 에이전트).

## 7. attack-harness 재시작 (VM A)
```bash
sudo systemctl restart attack-harness
```

## 확인
오케스트레이터 시작 로그에 `발판=in-cluster exec(frontend/deploy/attacker-foothold)` 가 찍히면 OK.
VM A journalctl 의 step 명령이 `wget ... internal-wiki...`, `psql ...postgres.database.svc...` 처럼
내부 주소를 향하고, rounds.jsonl attack_summary 에 DB 커넥션 스트링·내부 서비스가 나오면 ①③④ 진행.
