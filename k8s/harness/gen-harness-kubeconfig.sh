#!/usr/bin/env bash
# harness-exec kubeconfig 생성 — VM A 공격 하네스가 '모든 시나리오 발판'에 kubectl exec 할 때 쓴다.
# VM B(클러스터 접근 가능)에서 실행 후, 생성된 파일을 VM A 로 복사.
#
#   bash k8s/harness/gen-harness-kubeconfig.sh [출력파일] [API서버URL]
#   예) bash k8s/harness/gen-harness-kubeconfig.sh harness-exec.kubeconfig https://192.168.16.128:6443
#
# API서버URL = VM A 가 '공격망에서' 닿는 VM B 의 k3s API 주소(6443). 생략 시 아래 기본값.
# TLS 는 lab 간소화를 위해 insecure-skip-tls-verify(서버 인증서 SAN 문제 회피). 자격은 토큰으로 제한.
# context 네임스페이스는 무의미하다 — 하네스가 exec 때 -n <네임스페이스>를 항상 명시한다.
set -euo pipefail

NS=harness
SECRET=harness-exec-token
OUT="${1:-harness-exec.kubeconfig}"
APISERVER="${2:-https://192.168.16.128:6443}"

# k3s 는 보통 sudo kubectl. 접근 가능하면 그냥 kubectl.
KC="kubectl"
if ! kubectl get ns "$NS" >/dev/null 2>&1; then KC="sudo kubectl"; fi

echo "[*] $NS/$SECRET 에서 토큰 추출…"
TOKEN=$($KC -n "$NS" get secret "$SECRET" -o jsonpath='{.data.token}' | base64 -d)
if [ -z "$TOKEN" ]; then
  echo "[!] 토큰이 비었음. 00-harness-exec.yaml 적용 후 몇 초 뒤 재시도(컨트롤러가 토큰을 채움)."
  exit 1
fi

cat > "$OUT" <<EOF
apiVersion: v1
kind: Config
clusters:
- name: target
  cluster:
    server: ${APISERVER}
    insecure-skip-tls-verify: true
contexts:
- name: harness-exec
  context:
    cluster: target
    namespace: ${NS}
    user: harness-exec
current-context: harness-exec
users:
- name: harness-exec
  user:
    token: ${TOKEN}
EOF

chmod 600 "$OUT"
echo "[✓] ${OUT} 생성."
echo "    1) VM A 로 복사:  scp ${OUT} vm-a:~/harness-exec.kubeconfig"
echo "    2) VM A config.yaml:  attack.exec_kubeconfig: ~/harness-exec.kubeconfig  → 공격자 재시작"
echo "    3) 양쪽 검증(한 자격으로 둘 다 exec 돼야 정상):"
echo "       kubectl --kubeconfig ${OUT} -n frontend exec deploy/attacker-foothold -- echo ok"
echo "       kubectl --kubeconfig ${OUT} -n corp-ext exec deploy/corp-attacker-foothold -- echo ok"
