#!/usr/bin/env bash
# 벤치마크 타깃 제거 — targets 네임스페이스를 통째로 삭제(모든 타깃 앱 포함).
set -euo pipefail
echo "[*] targets 네임스페이스 삭제"
kubectl delete namespace targets --ignore-not-found
echo "[✓] 완료."
