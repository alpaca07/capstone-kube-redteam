#!/usr/bin/env bash
# ④ 값 기반 FLAG 생성·주입 (4단계). VM B에서 실행.
# 실제 FLAG 값은 레포에 안 들어간다 — gitignore된 참조파일 + database ns secret 에만 존재.
# → 공격자는 레포를 읽어서가 아니라 DB를 실제로 뚫어야 FLAG를 얻는다.
# 재실행하면 새 FLAG 생성(에피소드 로테이션). 나중엔 오케스트레이터가 리셋 때 호출.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v kubectl >/dev/null 2>&1 || { echo "[!] kubectl 없음."; exit 1; }
kubectl get ns database >/dev/null 2>&1 || { echo "[!] database 네임스페이스 없음. 먼저 setup-services.sh"; exit 1; }

# 랜덤 FLAG 생성 (16바이트 = 32 hex)
RAND=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
FLAG4="FLAG{shopflow_${RAND}}"

# gitignore된 참조 파일 (사람이 채점 대조용으로만)
printf 'FLAG_4=%s\n' "$FLAG4" > "$DIR/flag-values.secret"
chmod 600 "$DIR/flag-values.secret"

# 클러스터 secret (database ns) — postgres가 env로 읽어 주입
kubectl -n database create secret generic flag-values \
  --from-literal=FLAG_4="$FLAG4" \
  --dry-run=client -o yaml | kubectl apply -f -

# postgres 재기동 → emptyDir 재초기화 → 03-inject-flag.sh 가 새 FLAG 주입
kubectl -n database rollout restart deploy/postgres >/dev/null 2>&1 || true

echo "[✓] FLAG 생성·주입 완료 (postgres 재기동 ~15~30초 뒤 반영)."
echo "    값 보관: $DIR/flag-values.secret (gitignore) + database/flag-values secret"
echo "    확인:  kubectl -n database exec deploy/postgres -- psql -U appuser -d customerdb -c \"SELECT value FROM internal_secrets;\""
