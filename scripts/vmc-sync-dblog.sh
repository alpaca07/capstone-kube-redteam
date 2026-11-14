#!/usr/bin/env bash
# VM C god-view: postgres 파드 stdout(statement 로그) → 로컬 파일.
# config observability.db_log_path 가 이걸 읽음(orchestrator DbLogSource). vmc-sync-applog.sh 와 같은 패턴.
#
# 전제: 12-postgres.yaml 에 log_statement=all 설정 → 모든 SQL 이 stdout 에 찍힌다.
# DbLogSource 가 그 중 민감 테이블 조회(internal_secrets / customers PII / ops_secrets)만 크라운 반출로 판정한다.
#
# ★ 타깃 자동전환: database(ShopFlow)·corp-crown(corp) 두 네임스페이스를 '동시에' 수집해 각각 다른 파일로 떨군다.
#    대시보드 타깃만 고르면 orchestrator(--db-log-corp)가 읽을 파일을 전환 → sync 재시작 불필요.
#      database   → $LOCAL                (config observability.db_log_path, ShopFlow 기본)
#      corp-crown → ${LOCAL%.log}-corp.log (orchestrator --db-log-corp 가 이걸 읽음)
#    두 DB 를 한 파일에 섞지 않는 이유: ShopFlow database 는 앱(appuser) 상시 트래픽이 있어 corp 런(스코핑 off)에서
#    가짜 크라운이 된다. 파일을 가르면 corp 런은 corp-crown 로그만 보므로 오염이 없다.
#
#   nohup bash scripts/vmc-sync-dblog.sh > logs/sync-dblog.out 2>&1 &
#
# ※ DBLOG_LOCAL 은 config observability.db_log_path(ShopFlow 기본)와 같은 경로로 맞출 것.
# ※ 역할 스코핑(attacker_db_roles)도 타깃별로 다름(대시보드가 --attacker-db-roles 로 자동 전달):
#      corp-crown = [] (정상 트래픽 없는 단독 postgres) / database = appuser,legacy_admin (앱·유출 role 분리).
set -euo pipefail

KC="${KUBECONFIG_VMB:-$HOME/.kube/vmb-admin.kubeconfig}"
LOCAL="${DBLOG_LOCAL:-$HOME/capstone/logs/vmb-dblog.log}"   # ShopFlow(database) 수집 경로 = config db_log_path
CORP="${LOCAL%.log}-corp.log"                               # corp(corp-crown) 수집 경로 = orchestrator --db-log-corp
mkdir -p "$(dirname "$LOCAL")"

# 한 네임스페이스 postgres stdout 을 한 파일로 follow(끊김·파드리셋 때 재접속). 없는 ns 는 무해하게 재시도.
tail_ns() {   # $1=namespace  $2=출력파일
  : > "$2"
  echo "[*] postgres statement logs (ns=$1) → $2"
  while true; do
    kubectl --kubeconfig "$KC" -n "$1" logs -f "deploy/postgres" --since=2h --prefix >> "$2" 2>/dev/null || true
    sleep 2
  done
}

tail_ns database   "$LOCAL" &
tail_ns corp-crown "$CORP"  &
trap 'kill 0' INT TERM         # Ctrl-C 로 두 수집 프로세스 모두 종료
wait
