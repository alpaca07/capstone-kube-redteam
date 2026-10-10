#!/usr/bin/env bash
# 자체 서비스 스택 배포 (2단계) — VM B, k3s
# 3-tier: nginx(frontend) + Flask(backend) + PostgreSQL(database) + 더미 트래픽
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v kubectl >/dev/null 2>&1 || { echo "[!] kubectl 없음."; exit 1; }
kubectl get nodes >/dev/null 2>&1 || { echo "[!] 클러스터 연결 실패."; exit 1; }

echo "[*] 1/5 네임스페이스 (frontend, database)"
kubectl apply -f "$DIR/00-namespaces.yaml"

echo "[*] 2/5 database 계층 (PostgreSQL + 가짜 고객데이터 + FLAG)"
kubectl apply -f "$DIR/database/"

echo "[*] 3/5 backend (Flask API)"
kubectl apply -f "$DIR/backend/"

echo "[*] 4/5 frontend (nginx + 포털 UI)"
kubectl apply -f "$DIR/frontend/"

echo "[*] 5/5 더미 트래픽 생성기"
kubectl apply -f "$DIR/traffic/"

cat <<'EOF'

[✓] 적용 완료. 파드 기동에 시간 걸림 (backend는 pip 설치로 ~30초+).
    상태 확인:
      kubectl get pods -n database
      kubectl get pods -n frontend
    접근 (전부 Running 후):
      http://<VM B IP>:30080   ← NodePort, 고객 포털 UI
    동작 확인:
      kubectl -n frontend logs deploy/traffic-generator --tail=5   # list=200 detail/..=200 면 정상
EOF
