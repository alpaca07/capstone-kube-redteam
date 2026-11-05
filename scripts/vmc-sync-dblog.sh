#!/usr/bin/env bash
# VM C god-view: postgres 파드 stdout(statement 로그) → 로컬 파일.
# config observability.db_log_path 가 이걸 읽음(orchestrator DbLogSource). vmc-sync-applog.sh 와 같은 패턴.
#
# 전제: 12-postgres.yaml 에 log_statement=all 설정 → 모든 SQL 이 stdout 에 찍힌다.
# DbLogSource 가 그 중 민감 테이블 조회(internal_secrets / customers PII)만 크라운 반출로 판정한다.
# 직접 DB 접속(③ NetworkPolicy 부재)으로 ④ 를 터는 경로를 잡는다 — 앱을 안 거쳐 app 자백이 없는 경로.
#
#   nohup bash scripts/vmc-sync-dblog.sh > logs/sync-dblog.out 2>&1 &
#
# ※ DBLOG_LOCAL 은 config observability.db_log_path 와 같은 경로로 맞출 것(DbLogSource 가 읽는 파일).
set -euo pipefail

KC="${KUBECONFIG_VMB:-$HOME/.kube/vmb-admin.kubeconfig}"
LOCAL="${DBLOG_LOCAL:-$HOME/capstone/logs/vmb-dblog.log}"
mkdir -p "$(dirname "$LOCAL")"
: > "$LOCAL"
echo "[*] postgres statement logs → $LOCAL (kubeconfig=$KC)"

while true; do
  # -f(follow)는 파드 재시작(리셋)·끊김 때 반환 → 루프가 재접속.
  kubectl --kubeconfig "$KC" -n database logs -f "deploy/postgres" --since=2h --prefix >> "$LOCAL" 2>/dev/null || true
  sleep 2
done
