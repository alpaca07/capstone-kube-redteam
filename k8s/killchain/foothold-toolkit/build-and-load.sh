#!/usr/bin/env bash
# attacker-toolkit 이미지 빌드 → k3s(containerd)에 적재. VM B 에서 한 번 실행하면 끝.
#
# 실행 위치: VM B 위에서, '개발 단계(인터넷 ON)'에. 실험 단계엔 인터넷 OFF 라 반드시 실험 '전'
#            이 단계에서 구워 clean-baseline 스냅샷에 포함시킨다.
#
#   (VM B)  bash k8s/killchain/foothold-toolkit/build-and-load.sh
#
# 빌더 자동 선택: nerdctl(k3s containerd 에 직접) > docker(+k3s ctr import). 둘 다 없으면
# docker 를 자동 설치(get.docker.com)해 진행한다. 자동 설치를 막으려면 NO_AUTO_INSTALL=1.
set -euo pipefail

IMAGE="capstone/attacker-toolkit:1.0"
HERE="$(cd "$(dirname "$0")" && pwd)"

load_with_nerdctl() {
  echo "[빌드] nerdctl → k3s containerd(k8s.io). 빌드 즉시 파드에서 사용 가능(import 불필요)."
  sudo nerdctl --namespace k8s.io build -t "$IMAGE" "$HERE"
  sudo nerdctl --namespace k8s.io images | grep attacker-toolkit
}

load_with_docker() {
  echo "[빌드] docker build → docker save → k3s ctr import."
  sudo docker build -t "$IMAGE" "$HERE"
  sudo docker save "$IMAGE" | sudo k3s ctr images import -
  sudo k3s ctr images ls | grep attacker-toolkit
}

if command -v nerdctl >/dev/null 2>&1; then
  load_with_nerdctl
elif command -v docker >/dev/null 2>&1; then
  load_with_docker
elif [ "${NO_AUTO_INSTALL:-0}" != "1" ]; then
  echo "[설치] 빌더가 없어 docker 를 설치한다(인터넷 ON 전제). 막으려면 NO_AUTO_INSTALL=1."
  curl -fsSL https://get.docker.com | sudo sh
  sudo systemctl enable --now docker || true
  load_with_docker
else
  echo "[!] 빌더(nerdctl·docker) 없음 + 자동설치 off. 다른 장비서 빌드→tar→VM B import:" >&2
  echo "    docker build -t $IMAGE $HERE && docker save $IMAGE -o toolkit.tar" >&2
  echo "    # VM B: sudo k3s ctr images import toolkit.tar" >&2
  exit 1
fi

cat <<'EOF'

[✓] 적재 완료. 다음(전부 VM B):
  1) 발판 재배포:   kubectl apply -f k8s/killchain/00-attacker-foothold.yaml
                    kubectl -n frontend rollout restart deploy/attacker-foothold   # 같은 :1.0 태그라 restart 해야 새 이미지 반영
                    kubectl -n frontend rollout status deploy/attacker-foothold
  2) 동작 확인:     kubectl -n frontend exec deploy/attacker-foothold -- nuclei -version -disable-update-check
                    kubectl -n frontend exec deploy/attacker-foothold -- searchsploit apache | head
  3) clean-baseline 재스냅샷(발판 파드 뜬 상태로) — foothold/README.md 6단계
  4) VM A: git pull(attack-reinforce) 로 새 프롬프트 반영 후 attack-harness 재시작
EOF
