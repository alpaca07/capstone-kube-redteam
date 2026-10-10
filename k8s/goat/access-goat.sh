#!/usr/bin/env bash
# Goat 포트포워딩 래퍼 — 로컬 1230~1236 노출 (--address 0.0.0.0 → VM 외부에서도 접근).
# 1단계 수동 검증용. 공격 에이전트는 클러스터 내부로 붙으므로 실험에선 필요 없음.
set -euo pipefail

GOAT_DIR="${GOAT_DIR:-$HOME/goat-src/kubernetes-goat}"
[ -d "$GOAT_DIR" ] || { echo "[!] $GOAT_DIR 없음. 먼저: bash k8s/goat/setup-goat.sh"; exit 1; }

echo "[*] 포트포워딩 시작 (백그라운드)."
echo "    ※ VM B 외부(네 노트북)에서 열려면 방화벽에서 1230-1236 열려 있어야 함."
echo "    ※ SSH 세션 닫으면 끊김. 유지하려면: nohup bash k8s/goat/access-goat.sh &"
( cd "$GOAT_DIR" && bash ./access-kubernetes-goat.sh "$@" )

echo "[*] 접속:  http://<VM B IP>:1234  → Kubernetes Goat home"
