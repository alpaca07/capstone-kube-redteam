#!/usr/bin/env bash
# frontend exec 전용 kubeconfig 생성 — 공격 하네스(VM A)가 발판 파드에 kubectl exec 할 때 쓴다.
# VM B(클러스터 접근 가능한 곳)에서 실행한 뒤, 생성된 파일을 VM A 로 복사.
#
#   bash k8s/killchain/gen-foothold-kubeconfig.sh [출력파일] [API서버URL]
#   예) bash k8s/killchain/gen-foothold-kubeconfig.sh foothold.kubeconfig https://192.168.16.128:6443
#
# API서버URL = VM A 가 '공격망에서' 닿는 VM B 의 k3s API 주소(6443). 생략 시 아래 기본값.
# TLS 는 lab 간소화를 위해 insecure-skip-tls-verify(서버 인증서 SAN 문제 회피). 자격은 토큰으로 제한.
set -euo pipefail

NS=frontend
SECRET=foothold-sa-token
OUT="${1:-foothold.kubeconfig}"
APISERVER="${2:-https://192.168.16.128:6443}"

# sudo 가 필요하면 쓰고, 아니면 그대로(k3s 는 보통 sudo kubectl).
KC="kubectl"
if ! kubectl get ns "$NS" >/dev/null 2>&1; then KC="sudo kubectl"; fi

echo "[*] $NS/$SECRET 에서 토큰 추출…"
TOKEN=$($KC -n "$NS" get secret "$SECRET" -o jsonpath='{.data.token}' | base64 -d)
if [ -z "$TOKEN" ]; then
  echo "[!] 토큰이 비었음. 00-attacker-foothold.yaml 적용 후 몇 초 뒤 재시도(컨트롤러가 토큰을 채움)."
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
- name: foothold
  context:
    cluster: target
    namespace: ${NS}
    user: foothold
current-context: foothold
users:
- name: foothold
  user:
    token: ${TOKEN}
EOF

chmod 600 "$OUT"
echo "[✓] ${OUT} 생성."
echo "    1) VM A 로 복사:  scp ${OUT} vm-a:~/foothold.kubeconfig"
echo "    2) VM A config.yaml:  attack.exec_mode: true / attack.exec_kubeconfig: ~/foothold.kubeconfig"
echo "    3) 확인:  kubectl --kubeconfig ${OUT} -n ${NS} exec deploy/attacker-foothold -- echo ok"
echo "       (exec 전용인지 경계 확인:  kubectl --kubeconfig ${OUT} -n database get secret  → forbidden 이어야 정상)"
