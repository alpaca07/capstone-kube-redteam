#!/usr/bin/env bash
# corp 서비스 로그 → 로컬 파일 동기 (방어 observer 의 service_log_paths 가 읽는다).
#   postgres(접근 기록 log_statement=all)·samba·waf 세 파드 stdout 을 각각 받아 적는다.
#   vmc-sync-falco.sh / vmc-sync-audit.sh 와 같은 패턴 — 관리망 kubeconfig 만 있으면 된다.
#
#   nohup bash scripts/vmc-sync-corp-services.sh > logs/sync-corp.out 2>&1 &
set -euo pipefail

KC="${KUBECONFIG_VMB:-$HOME/.kube/vmb-admin.kubeconfig}"
DIR="${CORP_LOG_DIR:-$HOME/capstone/logs}"
mkdir -p "$DIR"
echo "[*] corp 서비스 로그 동기 시작 (kubeconfig=$KC, dir=$DIR)"

# ns  라벨  출력파일 — 파드 재시작/끊김 때 -f 가 반환되면 루프가 재접속(최근 2h 로 덮어써 무한증식 방지).
tail_svc() {
  local ns="$1" sel="$2" out="$3"
  while true; do
    POD="$(kubectl --kubeconfig "$KC" -n "$ns" get pods -l "$sel" -o name 2>/dev/null | head -1)"
    if [ -n "$POD" ]; then
      kubectl --kubeconfig "$KC" -n "$ns" logs -f "$POD" --since=2h > "$out" 2>/dev/null || true
    fi
    sleep 2
  done
}

tail_svc corp-crown    "app=postgres" "$DIR/vmb-corp-postgres.log" &
tail_svc corp-internal "app=samba"    "$DIR/vmb-corp-samba.log" &
tail_svc corp-dmz      "app=waf"      "$DIR/vmb-corp-waf.log" &
wait
