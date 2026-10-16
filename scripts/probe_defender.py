"""방어자 단독 probe — 전체 공수 사이클(공격·스냅샷·리플레이, ~29분) 없이
/defense_turn_start 한 번만 때려, 방어자가 '지금 audit.log'로 무엇을 탐지하고 어떤 패치를
내는지(그리고 '왜 noop'인지)를 즉시 본다. noop 디버깅 전용.

    python3 -m scripts.probe_defender                 # 기본 time_limit=300
    python3 -m scripts.probe_defender --time-limit 600

핵심: DefenseTurnResult 는 이미 진단 필드를 담고 있다 — orchestrator 는 rounds.jsonl 에
reported_techniques·patch_applied 만 남기지만, 여기선 전체를 그대로 출력한다.
  - patch_attempts : 제안된 패치별 결과 "action → target [applied|skip] detail"
  - patch_note     : dry-run 실패 사유·"적용할 패치 없음" 등
  - detected       : 방어자가 추론한 위협(type·mitre·evidence)

주의: 방어자가 렌더 가능한 패치를 내면 apply_plan 이 '라이브 클러스터에 실제 적용'한다.
      반복 probe 전엔 재베이스라인/해당 패치 삭제로 상태를 되돌릴 것(--no-revert 라이브 가정).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.config import load_config          # noqa: E402
from common.messages import DefenseTurnStart   # noqa: E402
from orchestrator.http_clients import HttpDefenderClient  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="방어자 단독 probe(관측→추론→패치 1회)")
    ap.add_argument("--config", default=None, help="config.yaml 경로(기본: 탐색)")
    ap.add_argument("--time-limit", type=int, default=300, help="방어 턴 제한시간(초)")
    ap.add_argument("--episode", type=int, default=1)
    ap.add_argument("--round", type=int, default=1)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    cli = HttpDefenderClient(cfg.network.defender_url, token=cfg.network.shared_token)
    print(f"[*] 방어자 probe → {cfg.network.defender_url}")
    print(f"    audit_log={cfg.observability.audit_log_path}")
    print(f"    falco_log={cfg.observability.falco_log_path}")
    print("    (방어자는 공격 정보 없이 이 로그들로만 추론한다)\n")

    r = cli.defense_turn(DefenseTurnStart(time_limit_sec=args.time_limit),
                         episode=args.episode, round=args.round)
    d = r.model_dump(mode="json")
    print("=== DefenseTurnResult (전체) ===")
    print(json.dumps(d, ensure_ascii=False, indent=2))

    print("\n── 요약 ──")
    print(f"patch_applied     = {r.patch_applied}")
    print(f"end_reason        = {r.end_reason}")
    print(f"healthcheck_passed= {r.healthcheck_passed}")
    print(f"detected          = {len(r.detected)}개")
    for det in d.get("detected", []):
        print(f"    • {det}")
    print(f"patch_set         = {len(r.patch_set)}개")
    print("patch_attempts(제안된 패치별 적용 결과 — noop 원인):")
    for a in (r.patch_attempts or ["(없음)"]):
        print(f"    • {a}")
    print(f"patch_note        = {r.patch_note or '(없음)'}")
    if r.error:
        print(f"error             = {r.error}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
