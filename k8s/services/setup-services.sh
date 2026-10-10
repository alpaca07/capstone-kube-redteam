#!/usr/bin/env bash
# 자체 서비스 스택 배포 (2단계) — VM B, k3s
# 이커머스 회사 구성: frontend / backend / database / internal
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v kubectl >/dev/null 2>&1 || { echo "[!] kubectl 없음."; exit 1; }
kubectl get nodes >/dev/null 2>&1 || { echo "[!] 클러스터 연결 실패."; exit 1; }

echo "[*] 1/6 네임스페이스 (frontend/backend/database/internal)"
kubectl apply -f "$DIR/00-namespaces.yaml"
echo "[*] 2/6 database (PostgreSQL + Redis + 가짜데이터 + FLAG)"
kubectl apply -f "$DIR/database/"
echo "[*] 3/6 backend (catalog-api / order-api / auth-service)"
kubectl apply -f "$DIR/backend/"
echo "[*] 4/6 frontend (web: 쇼핑몰 + 고객센터)"
kubectl apply -f "$DIR/frontend/"
echo "[*] 5/6 internal (admin-dashboard / internal-wiki)"
kubectl apply -f "$DIR/internal/"
echo "[*] 6/6 더미 트래픽 생성기"
kubectl apply -f "$DIR/traffic/"

cat <<'EOF'

[✓] 적용 완료. flask 서비스들이 기동 때 pip 설치 → 첫 배포 ~1~3분.
    상태 확인:
      kubectl get pods -n database
      kubectl get pods -n backend
      kubectl get pods -n frontend
      kubectl get pods -n internal
    공개 접근 (NodePort 30080 하나):
      http://<VM B IP>:30080           쇼핑몰
      http://<VM B IP>:30080/account   고객센터
    내부 도구(ClusterIP, 포트포워딩으로만):
      kubectl -n internal port-forward --address 0.0.0.0 svc/admin-dashboard 30090:8080 &
        → http://<VM B IP>:30090   관리자 콘솔(고객 PII)
EOF
