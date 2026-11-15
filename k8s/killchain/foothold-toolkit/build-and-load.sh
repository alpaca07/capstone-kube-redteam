#!/usr/bin/env bash
# attacker-toolkit 이미지 빌드 → VM B k3s containerd 로 적재.
#
# 실행 위치: 인터넷이 열린 '개발기'(또는 인터넷 ON 상태의 VM B). 실험 중엔 인터넷 OFF 라
#            반드시 실험 '전' 빌드 단계에서 돌려 clean-baseline 스냅샷에 포함시킨다.
#
#   bash build-and-load.sh                 # 빌드 + tar 저장(수동 적재 안내 출력)
#   bash build-and-load.sh --vmb vm-b      # 빌드 + tar + scp + VM B 에서 k3s import 까지
#   bash build-and-load.sh --vmb user@192.168.16.128
set -euo pipefail

IMAGE="capstone/attacker-toolkit:1.0"
TAR="attacker-toolkit-1.0.tar"
HERE="$(cd "$(dirname "$0")" && pwd)"

VMB=""
while [ $# -gt 0 ]; do
  case "$1" in
    --vmb) VMB="${2:-}"; shift 2 ;;
    *) echo "알 수 없는 인자: $1" >&2; exit 2 ;;
  esac
done

echo "[1/3] 이미지 빌드 ($IMAGE) — 개발기(인터넷 ON). 도구는 전부 이미지에 구워진다."
docker build -t "$IMAGE" "$HERE"

echo "[2/3] tar 저장 ($HERE/$TAR)"
docker save "$IMAGE" -o "$HERE/$TAR"

if [ -z "$VMB" ]; then
  cat <<EOF
[3/3] 수동 적재 (VM B 에서 실행):
  scp "$HERE/$TAR" <사용자>@192.168.16.128:/tmp/$TAR
  # VM B:
  sudo k3s ctr images import /tmp/$TAR
  sudo k3s ctr images ls | grep attacker-toolkit     # 적재 확인
EOF
else
  echo "[3/3] VM B($VMB) 로 전송 + k3s import"
  scp "$HERE/$TAR" "$VMB:/tmp/$TAR"
  ssh "$VMB" "sudo k3s ctr images import /tmp/$TAR && sudo k3s ctr images ls | grep attacker-toolkit"
fi

cat <<'EOF'

[✓] 완료. 다음(VM B):
  1) 발판 재배포:   kubectl apply -f k8s/killchain/00-attacker-foothold.yaml
                    kubectl -n frontend rollout status deploy/attacker-foothold
  2) 동작 확인:     kubectl -n frontend exec deploy/attacker-foothold -- nuclei -version -disable-update-check
                    kubectl -n frontend exec deploy/attacker-foothold -- kubectl version --client
  3) clean-baseline 재스냅샷(발판 파드 뜬 상태로) — foothold/README.md 6단계
  4) VM A: attack-harness 재시작 전, git pull 로 attack-reinforce 최신 프롬프트 반영
EOF
