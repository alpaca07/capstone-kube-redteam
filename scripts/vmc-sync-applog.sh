#!/usr/bin/env bash
# VM C god-view: 취약 서비스 파드 stdout(JSON 앱 감사 로그 포함) → 로컬 파일.
# config observability.app_log_path 가 이걸 읽음(orchestrator AppLogSource). vmc-sync-falco.sh 와 같은 패턴.
# 서비스가 after_request 훅으로 민감 요청마다 JSON 한 줄을 찍는다 → AppLogSource 가 웹 공격 기법 판정.
# 여러 서비스를 한 파일에 병합(JSON 줄만 파싱, werkzeug 등 비-JSON 줄은 무시).
#
#   nohup bash scripts/vmc-sync-applog.sh > logs/sync-applog.out 2>&1 &
set -euo pipefail

KC="${KUBECONFIG_VMB:-$HOME/.kube/vmb-admin.kubeconfig}"
LOCAL="${APPLOG_LOCAL:-$HOME/capstone/logs/vmb-applog.log}"
mkdir -p "$(dirname "$LOCAL")"
: > "$LOCAL"
echo "[*] app logs → $LOCAL (kubeconfig=$KC)"

follow() {   # $1=ns  $2=deploy
  while true; do
    # -f(follow)는 파드 재시작(patch_app rollout)·끊김 때 반환 → 루프가 재접속.
    kubectl --kubeconfig "$KC" -n "$1" logs -f "deploy/$2" --since=2h --prefix >> "$LOCAL" 2>/dev/null || true
    sleep 2
  done
}

follow backend  catalog-api &
follow backend  order-api &
follow internal admin-dashboard &
wait
