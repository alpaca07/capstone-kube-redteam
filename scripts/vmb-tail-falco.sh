#!/usr/bin/env bash
# VM B: 로컬 Falco 파드 stdout(JSON) → ~/capstone/logs/falco.log. 방어자 Observer 가 읽는 입력.
# vmc-sync-falco.sh 와 같은 패턴이되 VM B 로컬이라 kubeconfig 불필요(기본 kubectl).
# Falco 파드는 재시작 시 이름이 바뀌므로 매 루프에 재해석. systemd(capstone-falco-tail) 로 상주.
set -euo pipefail

LOCAL="${FALCO_LOCAL:-$HOME/capstone/logs/falco.log}"
mkdir -p "$(dirname "$LOCAL")"
echo "[*] VM B Falco tail → $LOCAL"

while true; do
  POD="$(kubectl -n falco get pods -l app.kubernetes.io/name=falco -o name 2>/dev/null | head -1)"
  if [ -n "$POD" ]; then
    # -f(follow)는 파드 재시작/끊김 때 반환 → 루프가 재접속하며 최근 2h 로 덮어씀(무한증식 방지).
    kubectl -n falco logs -f "$POD" -c falco --since=2h > "$LOCAL" 2>/dev/null || true
  fi
  sleep 2
done
