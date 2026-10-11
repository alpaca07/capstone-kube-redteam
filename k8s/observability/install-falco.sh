#!/usr/bin/env bash
# Falco 설치 (런타임 관측, DaemonSet, modern eBPF). VM B, 인터넷 필요.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v helm >/dev/null 2>&1 || { echo "[!] helm 필요 (Goat 배포 때 설치함)"; exit 1; }
kubectl get nodes >/dev/null 2>&1 || { echo "[!] 클러스터 연결 실패"; exit 1; }

helm repo add falcosecurity https://falcosecurity.github.io/charts 2>/dev/null || true
helm repo update falcosecurity

helm upgrade --install falco falcosecurity/falco \
  --namespace falco --create-namespace \
  -f "$DIR/falco-values.yaml" \
  --wait --timeout 5m

cat <<'EOF'

[✓] Falco 설치 완료 (DaemonSet).
    상태:    kubectl -n falco get pods
    이벤트:  kubectl -n falco logs -l app.kubernetes.io/name=falco -c falco -f
    테스트:  kubectl -n frontend run t --rm -it --image=busybox --restart=Never -- sh
             → 셸 뜨는 순간 Falco가 "Terminal shell in container" 경고를 찍어야 정상
EOF
