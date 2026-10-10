#!/usr/bin/env bash
# Kubernetes Goat 배포 래퍼 (VM B, k3s) — 환경 구축 1단계
#
# 설계 원칙: 레포가 단일 소스.
#   - 버전관리하는 것 = 이 래퍼 스크립트 + 고정 커밋(GOAT_REF)뿐.
#   - Goat 본체는 VM B 로컬에 clone (레포에 vendoring 안 함).
#     실제 수정/이식은 3단계에서 필요한 시나리오만 골라서 한다.
#   - 고정 커밋으로 받으므로 언제 돌려도 같은 취약 환경이 재현된다(논문 재현성).
set -euo pipefail

GOAT_REPO="${GOAT_REPO:-https://github.com/madhuakula/kubernetes-goat.git}"
GOAT_REF="${GOAT_REF:-723a0db478f050d173d23b4ce5044b65bce0bdd0}"
GOAT_DIR="${GOAT_DIR:-$HOME/goat-src/kubernetes-goat}"

echo "[*] Kubernetes Goat 배포 시작 (pin: ${GOAT_REF:0:12})"

# ── 1) 사전 점검 ────────────────────────────────────────────────
command -v git >/dev/null 2>&1 || { echo "[!] git 없음: sudo apt install -y git"; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "[!] kubectl 없음. k3s/kubeconfig 확인."; exit 1; }
if ! kubectl get nodes >/dev/null 2>&1; then
  echo "[!] 클러스터 연결 실패. 'kubectl get nodes' 먼저 확인 (KUBECONFIG 설정?)."; exit 1
fi
if ! command -v helm >/dev/null 2>&1; then
  cat <<'EOF'
[!] helm CLI가 없습니다. metadata-db 시나리오가 helm chart라서 필요합니다.
    VM B(인터넷 ON)에서 설치 후 다시 실행하세요:
      curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
EOF
  exit 1
fi

# ── 2) 고정 커밋으로 Goat 확보 ──────────────────────────────────
if [ -d "$GOAT_DIR/.git" ]; then
  echo "[*] 기존 clone 갱신: $GOAT_DIR"
  git -C "$GOAT_DIR" fetch --all --tags --quiet
else
  echo "[*] clone: $GOAT_REPO"
  mkdir -p "$(dirname "$GOAT_DIR")"
  git clone --quiet "$GOAT_REPO" "$GOAT_DIR"
fi
git -C "$GOAT_DIR" -c advice.detachedHead=false checkout --quiet "$GOAT_REF"
echo "[*] 체크아웃: $(git -C "$GOAT_DIR" rev-parse --short HEAD)"

# ── 3) Goat 자체 setup 실행 ─────────────────────────────────────
#   Goat 스크립트는 상대경로(scenarios/...)를 쓰므로 repo 루트에서 실행해야 함.
#   순서: insecure-rbac(superadmin) → metadata-db(helm) → 나머지 시나리오 apply.
echo "[*] Goat setup 실행..."
( cd "$GOAT_DIR" && bash ./setup-kubernetes-goat.sh "$@" )

cat <<EOF

[✓] 배포 명령 완료. 이미지 pull·파드 기동에 1~3분 걸릴 수 있습니다.
    상태:   kubectl get pods -A
    접근:   bash k8s/goat/access-goat.sh   (전부 Running 된 뒤)
    정리:   bash k8s/goat/teardown-goat.sh
EOF
