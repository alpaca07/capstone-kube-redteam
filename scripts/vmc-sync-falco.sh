#!/usr/bin/env bash
# VM C god-view: Falco 파드 stdout(JSON) → 로컬 파일로 동기. config observability.falco_log_path 가 이걸 읽음.
# #6 audit 동기(vmc-sync-audit.sh)와 같은 패턴 — 관리망 kubeconfig 만 있으면 됨(SSH·VM B 직접접속 불필요).
# Falco 는 falco-values.yaml 에서 json_output=true 로 stdout 에 JSON 을 뿌리므로 그걸 그대로 받아 적는다.
#
#   nohup bash scripts/vmc-sync-falco.sh > logs/sync-falco.out 2>&1 &
set -euo pipefail

KC="${KUBECONFIG_VMB:-$HOME/.kube/vmb-admin.kubeconfig}"
LOCAL="${FALCO_LOCAL:-$HOME/capstone/logs/vmb-falco.log}"
mkdir -p "$(dirname "$LOCAL")"
echo "[*] Falco → $LOCAL 동기 시작 (kubeconfig=$KC)"

while true; do
  POD="$(kubectl --kubeconfig "$KC" -n falco get pods \
          -l app.kubernetes.io/name=falco -o name 2>/dev/null | head -1)"
  if [ -n "$POD" ]; then
    # -f(follow)는 파드 재시작/끊김 때 반환 → 루프가 재접속하며 최근 2h 로 덮어씀(무한증식 방지).
    kubectl --kubeconfig "$KC" -n falco logs -f "$POD" -c falco --since=2h > "$LOCAL" 2>/dev/null || true
  fi
  sleep 2
done
