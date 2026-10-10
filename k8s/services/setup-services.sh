#!/usr/bin/env bash
# 자체 서비스 스택 + 킬체인 배포 (2~3단계) — VM B, k3s
# 이커머스 회사 ShopFlow (frontend/backend/database/internal) + 심긴 취약점(①②③)
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
KC="$DIR/../killchain"

command -v kubectl >/dev/null 2>&1 || { echo "[!] kubectl 없음."; exit 1; }
kubectl get nodes >/dev/null 2>&1 || { echo "[!] 클러스터 연결 실패."; exit 1; }

echo "[*] 1/7 네임스페이스 (frontend/backend/database/internal)"
kubectl apply -f "$DIR/00-namespaces.yaml"
echo "[*] 2/7 킬체인 ② 과권한 RBAC (admin-sa) — admin-dashboard보다 먼저"
kubectl apply -f "$KC/10-admin-overperm-rbac.yaml"
echo "[*] 3/7 database (PostgreSQL + Redis + 가짜데이터 + FLAG)"
kubectl apply -f "$DIR/database/"
echo "[*] 4/7 backend (catalog-api / order-api / auth-service)"
kubectl apply -f "$DIR/backend/"
echo "[*] 5/7 frontend (web: 쇼핑몰 + 고객센터)"
kubectl apply -f "$DIR/frontend/"
echo "[*] 6/7 internal (admin-dashboard[①②] / internal-wiki[①])"
kubectl apply -f "$DIR/internal/"
echo "[*] 7/7 더미 트래픽 생성기"
kubectl apply -f "$DIR/traffic/"

cat <<'EOF'

[✓] 적용 완료 (취약 베이스라인). flask들 pip 설치로 첫 배포 ~1~3분.
    상태:  kubectl get pods -n database -n backend  (아래처럼 ns별)
      kubectl get pods -n backend ; kubectl get pods -n frontend ; kubectl get pods -n internal
    공개:  http://<VM B IP>:30080 (쇼핑몰) · http://<VM B IP>:30080/account (고객센터)
    킬체인 수동 검증(사람이 직접 뚫기):  k8s/killchain/README.md 의 walkthrough 참고
EOF
