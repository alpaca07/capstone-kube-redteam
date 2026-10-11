#!/usr/bin/env bash
# k3s 감사로그 활성화 (VM B, sudo 필요). API 서버를 재기동한다(실행 중 파드는 유지).
# ⚠ 정책/경로 오류 시 API 서버가 안 뜰 수 있음 → 하단 복구 방법 참고.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRV=/var/lib/rancher/k3s/server
CFG=/etc/rancher/k3s/config.yaml

command -v k3s >/dev/null 2>&1 || { echo "[!] k3s 없음(여기는 VM B에서 실행)"; exit 1; }

sudo mkdir -p "$SRV/logs"
sudo cp "$DIR/audit-policy.yaml" "$SRV/audit-policy.yaml"

# 기존 config.yaml 있으면 백업 (덮어쓰기 주의)
if [ -s "$CFG" ]; then
  sudo cp "$CFG" "${CFG}.bak.$(date +%s)"
  echo "[*] 기존 $CFG 백업함. (커스텀 설정 있었으면 병합 필요)"
fi
sudo mkdir -p /etc/rancher/k3s
sudo tee "$CFG" >/dev/null <<EOF
kube-apiserver-arg:
  - audit-log-path=$SRV/logs/audit.log
  - audit-policy-file=$SRV/audit-policy.yaml
  - audit-log-maxage=7
  - audit-log-maxbackup=3
  - audit-log-maxsize=50
EOF

echo "[*] k3s 재시작 (API 서버 재기동, ~15초)..."
sudo systemctl restart k3s

echo "[*] 확인 중..."
sleep 10
if sudo kubectl get --raw='/readyz' >/dev/null 2>&1 || kubectl get nodes >/dev/null 2>&1; then
  echo "[✓] 감사로그 활성화 완료."
  echo "    실시간:  sudo tail -f $SRV/logs/audit.log"
  echo "    ② 탐지 테스트:  kubectl -n internal exec deploy/admin-dashboard -- sh -c 'curl -sk -H \"Authorization: Bearer \$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://kubernetes.default.svc/api/v1/namespaces/database/secrets/postgres-credentials' >/dev/null; sudo grep admin-sa $SRV/logs/audit.log | tail -1"
else
  cat <<'RECOVER'
[!] API 서버 확인 실패. 복구:
    sudo rm /etc/rancher/k3s/config.yaml   # (백업 있으면 복원)
    sudo systemctl restart k3s
RECOVER
  exit 1
fi
