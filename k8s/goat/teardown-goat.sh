#!/usr/bin/env bash
# Goat 제거 래퍼 — 시나리오/헬름/부수 네임스페이스 정리.
# 주의: 완전한 clean 초기화는 VMware 스냅샷 복원이 가장 확실(5단계에서 자동화).
set -euo pipefail

GOAT_DIR="${GOAT_DIR:-$HOME/goat-src/kubernetes-goat}"
[ -d "$GOAT_DIR" ] || { echo "[!] $GOAT_DIR 없음."; exit 1; }

echo "[*] 포트포워딩 종료"
pkill -f "kubectl.*port-forward" 2>/dev/null || true

echo "[*] Goat 시나리오 제거"
( cd "$GOAT_DIR" && bash ./teardown-kubernetes-goat.sh "$@" ) || true

echo "[*] 부수 네임스페이스 정리"
for ns in big-monolith secure-middleware; do
  kubectl delete namespace "$ns" --ignore-not-found
done

echo "[✓] 정리 완료."
