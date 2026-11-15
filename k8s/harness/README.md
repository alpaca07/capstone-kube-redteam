# k8s/harness — 하네스 exec 자격 (시나리오 무관 단일 kubeconfig)

VM A 공격 하네스가 **어느 시나리오의 발판이든** `kubectl exec` 로 명령을 주입할 때 쓰는
**단일 자격**(`harness-exec`)을 정의한다. ShopFlow(`frontend`)·corp(`corp-ext`) 양쪽에서 exec 가능.

## 왜 있나
`exec_kubeconfig` 는 config 전용이라 대시보드 타깃을 바꿔도 **자동 전환되지 않는다**. 그래서
ShopFlow 발판 kubeconfig 로 두고 corp 타깃을 돌리면 corp-ext 에서 exec 권한이 없어 **모든 명령이
거부**된다(`exec=0.0s`, "Kubernetes API permission error"). 반대도 같다. `harness-exec` 는 두
네임스페이스에 걸친 exec 권한을 한 SA 에 모아 이 함정을 없앤다 — exec_kubeconfig 를 한 번만 박으면 끝.

## 설계 경계 (초과권한 아님)
exec_kubeconfig 는 '하네스가 발판 파드에 명령을 넣는 plumbing'일 뿐 공격 시나리오의 일부가 아니다.
공격 리얼리즘(파드 안 토큰·권한)은 발판 SA(`foothold-sa`/`corp-foothold-sa`)가 따로 정한다. 동사는
발판 exec Role 과 동일(`deployments:get`, `pods:get/list`, `pods/exec:create/get`) — 넓힌 게 아니다.

## 배포 (VM B)
```bash
kubectl apply -f k8s/harness/00-harness-exec.yaml
bash k8s/harness/gen-harness-kubeconfig.sh harness-exec.kubeconfig https://192.168.16.128:6443
```
생성된 `harness-exec.kubeconfig` 를 VM A 로 복사 → `config.yaml` 의
`attack.exec_kubeconfig: ~/harness-exec.kubeconfig` 로 지정 → 공격자 재시작.

## 검증 (한 자격으로 둘 다 돼야 정상)
```bash
kubectl --kubeconfig harness-exec.kubeconfig -n frontend exec deploy/attacker-foothold -- echo ok
kubectl --kubeconfig harness-exec.kubeconfig -n corp-ext exec deploy/corp-attacker-foothold -- echo ok
```

## 새 시나리오 추가 시
`00-harness-exec.yaml` 에 그 네임스페이스용 `RoleBinding`(harness-exec → ClusterRole harness-exec)을
하나 더 추가하고 재적용하면 된다. 기존 `foothold.kubeconfig`·`corp-foothold.kubeconfig` 는
그대로 둬도 되지만, exec_kubeconfig 를 harness-exec 로 고정하면 더는 쓰지 않는다.

## 리셋 영향
baseline 리셋의 대상(`target_namespaces`=frontend/backend/database/internal 의 NetworkPolicy 삭제 +
killchain 재적용) 밖이라, 수동 적용 후 **에피소드 넘어 영구 지속**한다.
