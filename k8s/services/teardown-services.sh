#!/usr/bin/env bash
# 자체 서비스 스택 제거 — 네임스페이스 통째로 삭제
set -euo pipefail
echo "[*] 서비스 네임스페이스 삭제 (frontend/backend/database/internal)"
kubectl delete namespace frontend backend database internal --ignore-not-found
echo "[✓] 제거 완료. (완전 초기화는 VMware 스냅샷 복원 권장 — 5단계에서 자동화)"
