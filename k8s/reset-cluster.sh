#!/usr/bin/env bash
# B 리셋 — kubectl로 클러스터를 'clean 취약 베이스라인'으로 복원 (VMware 스냅샷 대체).
#
# VMware 라이브 스냅샷 리셋이 Workstation에서 취약(일시정지·락·stun·헤드리스 불가)해,
# VM 통째 복원 대신 클러스터 상태만 kubectl로 되돌린다. 공격면이 전부 k8s 오브젝트
# (RBAC·NetworkPolicy·Secret·ConfigMap·파드·DB데이터)라 이 범위로 충분.
#
# 하는 일: 공격 산물 + 방어 패치를 모두 걷어내고(네임스페이스 통째 삭제 + 클러스터 스코프
# 킬체인 RBAC 삭제) → ShopFlow + 킬체인 ①②③ 재적용 → 새 FLAG(④) 주입 → ready 대기.
#
# VM B에서 실행. 오케스트레이터(VM C)는 SSH로 이걸 호출한다(KubectlResetManager).
#   bash k8s/reset-cluster.sh
set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

command -v kubectl >/dev/null 2>&1 || { echo "[!] kubectl 없음."; exit 1; }
kubectl get nodes >/dev/null 2>&1 || { echo "[!] 클러스터 연결 실패."; exit 1; }

echo "[*] 1/4 기존 상태 제거 (네임스페이스 통째 — 공격 산물·방어 NetworkPolicy 포함)"
# --wait=true: 네임스페이스가 완전히 종료될 때까지 블로킹(재적용과 겹치지 않게).
kubectl delete namespace frontend backend database internal --ignore-not-found --wait=true
# 클러스터 스코프 킬체인 RBAC(ClusterRole/Binding)은 ns 삭제로 안 지워진다. 라벨로 정리:
# 방어자가 축소/삭제했을 수도 있으니 지우고, setup에서 취약 버전으로 다시 심는다.
kubectl delete clusterrole,clusterrolebinding \
  -l app.kubernetes.io/part-of=capstone-killchain --ignore-not-found

echo "[*] 2/4 취약 베이스라인 재적용 (ShopFlow + 킬체인 ①②③)"
bash "$DIR/services/setup-services.sh"

echo "[*] 3/4 새 FLAG 주입 (④ 에피소드 로테이션)"
bash "$DIR/flags/generate-flags.sh"

echo "[*] 4/4 핵심 파드 ready 대기 (이미지 미리 구워두면 빠름 / pip 설치면 수 분)"
# 킬체인 경로상 핵심 배포만 대기. 하나 느려도 전체를 막지 않게 경고로 처리.
_wait() {  # ns deploy timeout
  kubectl -n "$1" rollout status "deploy/$2" --timeout="${3}s" \
    || echo "    [경고] $1/$2 아직 안 떴음(타임아웃 ${3}s) — 수동 확인 필요"
}
_wait database postgres        300
_wait frontend web             240
_wait backend  catalog-api     300
_wait backend  order-api       300
_wait backend  auth-service    300
_wait internal admin-dashboard 180
_wait internal internal-wiki   180

echo "[✓] 리셋 완료 — clean 취약 베이스라인 복원됨."
echo "    확인: kubectl get pods -A | grep -vE 'Running|Completed'  (비정상만)"
