#!/usr/bin/env bash
# VM A 에서 공진화 run 시작 전 1회 실행하는 보조 스크립트.
#
# 공격자 기억 오염 방지:
#   - attack-harness 재시작 (프로세스 내 LLM 세션 context 리셋)
#   - 외부 저널·그래프 파일 정리 (/journal, /graph HTTP 엔드포인트에 push 됐던 흔적)
#
# baseline.py 가 자동 처리하는 범위와 역할 분담:
#   - orchestrator (VM C):  k8s 리소스 + Neo4j DB  → BaselineManager.reset_to_clean
#   - 이 스크립트 (VM A):   하네스 프로세스 + VM A 로컬 파일 흔적
#
# 사용: 각 run 시작 직전 VM A 에서 실행
#   bash ~/capstone/scripts/reset-attacker-memory.sh
#
set -u
cd "${CAPSTONE_ROOT:-$HOME/capstone}"

echo "[1/3] attack-harness 중지..."
sudo systemctl stop attack-harness 2>/dev/null || true

echo "[2/3] 공격자 로컬 저널·그래프 흔적 정리..."
# 라운드 간 외부 저장소 역할을 하는 파일들을 best-effort 삭제.
# 경로가 운영 환경에 따라 다를 수 있으니, 실제 떨어지는 경로 확인 후 조정 가능.
_removed=0
for pat in \
    "runs/*/attack_journal.jsonl" \
    "runs/*/off_kg.jsonl" \
    "runs/*/attack_graph.json" \
    "runs/*/graph_snapshot.json" \
    ".attacker-cache" \
    "logs/attack_journal.jsonl" \
    "logs/off_kg.jsonl"; do
    for f in $pat; do
        if [ -e "$f" ]; then
            rm -rf "$f" && _removed=$((_removed + 1))
        fi
    done
done
echo "      → ${_removed}개 정리"

echo "[3/3] attack-harness 재시작..."
sudo systemctl start attack-harness
sleep 2
sudo systemctl is-active attack-harness >/dev/null \
    && echo "      → attack-harness active" \
    || { echo "      → attack-harness 기동 실패 — journalctl 확인"; exit 1; }

echo "완료 — 공격자 기억 오염 리셋"
