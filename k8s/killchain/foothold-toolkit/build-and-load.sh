#!/usr/bin/env bash
# attacker-toolkit 이미지 빌드 → k3s(containerd)에 적재.
#
# 실행 위치: VM B 위에서, '개발 단계(인터넷 ON)'에. VM B 가 k3s 노드라 빌드하면 containerd
#            에 바로 올라간다(별도 전송·import 불필요). 실험 단계엔 인터넷 OFF 라 반드시
#            실험 '전' 이 단계에서 구워 clean-baseline 스냅샷에 포함시킨다.
#
#   (VM B 에서)  bash k8s/killchain/foothold-toolkit/build-and-load.sh
#
# 빌더 자동 선택: nerdctl(k3s containerd 에 직접) > docker(+ k3s ctr import). 둘 다 없으면 안내.
set -euo pipefail

IMAGE="capstone/attacker-toolkit:1.0"
HERE="$(cd "$(dirname "$0")" && pwd)"

if command -v nerdctl >/dev/null 2>&1; then
  echo "[빌드] nerdctl → k3s containerd(k8s.io namespace). 빌드 즉시 파드에서 사용 가능(import 불필요)."
  sudo nerdctl --namespace k8s.io build -t "$IMAGE" "$HERE"
  sudo nerdctl --namespace k8s.io images | grep attacker-toolkit
elif command -v docker >/dev/null 2>&1; then
  echo "[빌드] docker build → docker save → k3s ctr import."
  docker build -t "$IMAGE" "$HERE"
  docker save "$IMAGE" | sudo k3s ctr images import -
  sudo k3s ctr images ls | grep attacker-toolkit
else
  cat >&2 <<'MSG'
[!] 이 VM 에 컨테이너 빌더(nerdctl·docker)가 없다. k3s 는 ctr/crictl 만 있어 Dockerfile 빌드가 안 된다.
  둘 중 하나로 진행:
  (가) VM B 에 nerdctl 설치 후 재실행:
       sudo nerdctl --namespace k8s.io build -t capstone/attacker-toolkit:1.0 \
         k8s/killchain/foothold-toolkit/
  (나) 도커가 있는 다른 장비에서 빌드 → tar 로 옮겨 VM B 에서 import:
       # (도커 있는 장비, 인터넷 ON)
       docker build -t capstone/attacker-toolkit:1.0 k8s/killchain/foothold-toolkit/
       docker save capstone/attacker-toolkit:1.0 -o attacker-toolkit-1.0.tar
       # attacker-toolkit-1.0.tar 를 VM B 로 옮긴 뒤 (VM B):
       sudo k3s ctr images import attacker-toolkit-1.0.tar
MSG
  exit 1
fi

cat <<'EOF'

[✓] 적재 완료. 다음(전부 VM B):
  1) 발판 재배포:   kubectl apply -f k8s/killchain/00-attacker-foothold.yaml
                    kubectl -n frontend rollout status deploy/attacker-foothold
  2) 동작 확인:     kubectl -n frontend exec deploy/attacker-foothold -- nuclei -version -disable-update-check
                    kubectl -n frontend exec deploy/attacker-foothold -- searchsploit apache | head
  3) clean-baseline 재스냅샷(발판 파드 뜬 상태로) — foothold/README.md 6단계
  4) VM A: git pull(attack-reinforce) 로 새 프롬프트 반영 후 attack-harness 재시작
EOF
