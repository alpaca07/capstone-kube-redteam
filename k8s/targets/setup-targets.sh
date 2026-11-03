#!/usr/bin/env bash
# 벤치마크 타깃 배포 (통제 벤치마크 레이어) — VM B, k3s
# 취약점이 '라벨링'된 훈련용 앱들을 targets 네임스페이스에 배포.
# ShopFlow(현실 은닉 타깃)와 분리된 '통제군' — "AI 추론 공수가 정상 측정되는가"용.
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v kubectl >/dev/null 2>&1 || { echo "[!] kubectl 없음."; exit 1; }
kubectl get nodes >/dev/null 2>&1 || { echo "[!] 클러스터 연결 실패."; exit 1; }

echo "[*] 1/2 네임스페이스 (targets)"
kubectl apply -f "$DIR/00-namespace.yaml"
echo "[*] 2/2 타깃 앱 (dvwa / juice-shop / webgoat / bwapp / dvga / vampi)"
kubectl apply -f "$DIR/"

cat <<'EOF'

[✓] 적용 완료. 이미지 풀 + 기동에 수 분(특히 Juice Shop / WebGoat).
    상태:  kubectl get pods -n targets -w
    접속 (VM B IP = 192.168.16.128 기준):
      DVWA        http://192.168.16.128:30081   admin / password → Setup → Create/Reset DB
      Juice Shop  http://192.168.16.128:30082   (스코어보드 API: /api/Challenges)
      WebGoat     http://192.168.16.128:30083/WebGoat   (+ WebWolf :30093/WebWolf)
      bWAPP       http://192.168.16.128:30084   먼저 /install.php → bee / bug
      DVGA        http://192.168.16.128:30085   (GraphiQL + /graphql)
      VAmPI       http://192.168.16.128:30086   (Swagger UI, vulnerable=1)
EOF
