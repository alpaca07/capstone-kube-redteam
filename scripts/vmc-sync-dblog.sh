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
# ※ DBLOG_NS 로 대상 네임스페이스 선택: 기본 database(ShopFlow), corp 회차는 DBLOG_NS=corp-crown.
#    corp-crown 은 정상 트래픽이 없는 단독 postgres라 config attacker_db_roles 는 [] 로 비울 것
#    (역할 스코핑을 켜면 %u@%d prefix 없는 corp 로그가 전부 제외돼 크라운 0건이 된다).
set -euo pipefail

KC="${KUBECONFIG_VMB:-$HOME/.kube/vmb-admin.kubeconfig}"
LOCAL="${DBLOG_LOCAL:-$HOME/capstone/logs/vmb-dblog.log}"
NS="${DBLOG_NS:-database}"      # 채점 대상 postgres 네임스페이스: ShopFlow=database / corp=corp-crown
mkdir -p "$(dirname "$LOCAL")"
: > "$LOCAL"
echo "[*] postgres statement logs (ns=$NS) → $LOCAL (kubeconfig=$KC)"

while true; do
  # -f(follow)는 파드 재시작(리셋)·끊김 때 반환 → 루프가 재접속.
  kubectl --kubeconfig "$KC" -n "$NS" logs -f "deploy/postgres" --since=2h --prefix >> "$LOCAL" 2>/dev/null || true
  sleep 2
done
