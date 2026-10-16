#!/usr/bin/env bash
# #6 god-view 측정 배관 — VM C: audit-tail 파드 로그를 로컬 파일로 지속 수집(관리망, admin kubeconfig).
# 사용:  bash scripts/vmc-sync-audit.sh [LOCAL_PATH]    (백그라운드로:  nohup ... &)
#  → config.yaml 의 observability.audit_log_path 를 이 LOCAL_PATH 로 맞출 것.
# 끊겨도 2초 뒤 재연결. --since 로 중복 최소화(로그소스는 set 이라 중복 무해).
set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KC="${KUBECONFIG:-/home/vm-c/.kube/vmb-admin.kubeconfig}"
LOCAL="${1:-$DIR/logs/vmb-audit.log}"
mkdir -p "$(dirname "$LOCAL")"
echo "[*] audit-tail(godview) → $LOCAL  (kubeconfig=$KC). Ctrl-C 로 중지."
while true; do
  kubectl --kubeconfig "$KC" -n godview logs -f ds/audit-tail --since=2h > "$LOCAL" 2>/dev/null \
    || echo "[!] logs 스트림 실패(파드 준비 전?) — 재시도" >&2
  echo "[!] 스트림 끊김 — 2s 후 재연결" >&2
  sleep 2
done
