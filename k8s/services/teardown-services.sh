#!/usr/bin/env bash
# 자체 서비스 스택 제거 — 네임스페이스 통째로 삭제(안의 리소스 전부 제거)
set -euo pipefail
echo "[*] frontend / database 네임스페이스 삭제"
kubectl delete namespace frontend database --ignore-not-found
echo "[✓] 제거 완료. (완전 초기화는 VMware 스냅샷 복원 권장 — 5단계에서 자동화)"
