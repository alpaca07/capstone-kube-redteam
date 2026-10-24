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

# [Wave1] 호스트 objective FLAG — 노드 파일에만 존재(탈출로만 획득). ④와 별개 크라운 주얼.
RANDH=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
FLAGH="FLAG{hostpwn_${RANDH}}"

# gitignore된 참조 파일 (사람·god-view 채점 대조용). FLAG_4 + FLAG_HOST 둘 다.
printf 'FLAG_4=%s\nFLAG_HOST=%s\n' "$FLAG4" "$FLAGH" > "$DIR/flag-values.secret"
chmod 600 "$DIR/flag-values.secret"

# 클러스터 secret (database ns) — postgres가 env로 읽어 주입 (④)
kubectl -n database create secret generic flag-values \
  --from-literal=FLAG_4="$FLAG4" \
  --dry-run=client -o yaml | kubectl apply -f -

# postgres 재기동 → emptyDir 재초기화 → 03-inject-flag.sh 가 새 FLAG 주입
kubectl -n database rollout restart deploy/postgres >/dev/null 2>&1 || true

# [Wave1] 호스트 FLAG 를 '노드 파일'에 심기. VM B = k3s 단일 노드이므로 여기 파일시스템이 곧 노드.
#   탈출 파드가 hostPath 로 /host/etc/shopflow/host.flag 를 읽어 획득(Falco "Escape to host
#   filesystem" 이 포착 → T1611). 600=root 전용(탈출=privileged/root 라야 읽힘, 평상시 파드 불가).
if sudo -n true 2>/dev/null || sudo true; then
  sudo mkdir -p /etc/shopflow
  printf '%s\n' "$FLAGH" | sudo tee /etc/shopflow/host.flag >/dev/null
  sudo chmod 600 /etc/shopflow/host.flag
  echo "[✓] 호스트 FLAG 노드 설치: /etc/shopflow/host.flag (600, root 전용)"
else
  echo "[!] sudo 불가 — 호스트 FLAG 노드 파일 미설치. 수동:"
  echo "    sudo mkdir -p /etc/shopflow && echo '$FLAGH' | sudo tee /etc/shopflow/host.flag && sudo chmod 600 /etc/shopflow/host.flag"
fi

echo "[✓] FLAG 생성·주입 완료 (postgres 재기동 ~15~30초 뒤 반영)."
echo "    값 보관: $DIR/flag-values.secret (gitignore) + database/flag-values secret + /etc/shopflow/host.flag"
echo "    ※ flag-values.secret 을 VM C(심판)가 읽어야 값대조 채점됨 — 기존 동기 경로 그대로 FLAG_HOST 포함."
echo "    확인(④):  kubectl -n database exec deploy/postgres -- psql -U appuser -d customerdb -c \"SELECT value FROM internal_secrets;\""
echo "    확인(host): sudo cat /etc/shopflow/host.flag"
