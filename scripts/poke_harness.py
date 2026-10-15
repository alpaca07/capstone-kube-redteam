"""하네스 직접 찌르기(진단 전용) — 스냅샷 루프 없이 살아있는 VM A/B 서버에 턴 1회씩 보낸다.

오케스트레이터 전체 루프(스냅샷 revert·재개 등 수 분)를 돌리지 않고 **에러만 빠르게** 본다.
각 하네스의 except 블록이 이제 traceback 을 콘솔에 찍으므로, 이 스크립트로 턴을 쏘면:
  - VM A/B 서버 콘솔  → 전체 스택트레이스(정확한 파일·줄)
  - 이 스크립트 출력   → end_reason + 요약/에러 문자열 + 소요시간
베이스라인 재촬영 불필요(살아있는 서버를 직접 호출하므로). 서버 코드만 최신으로 재기동하면 됨.

    # VM C(또는 관리망 아무 곳)에서:
    python scripts/poke_harness.py                 # 공격·방어 둘 다
    python scripts/poke_harness.py --which attack   # 공격만
    python scripts/poke_harness.py --which defense  # 방어만(LLM 때문에 수백 초 걸릴 수 있음)
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.config import load_config                                    # noqa: E402
from common.messages import AttackTurnStart, DefenseTurnStart, Foothold  # noqa: E402
from orchestrator.http_clients import HttpAttackerClient, HttpDefenderClient  # noqa: E402


def _poke_attack(cfg, *, episode: int, round: int, time_limit=None) -> None:
    tl = time_limit if time_limit is not None else cfg.experiment.time_limit_sec
    print(f"\n[공격] POST {cfg.network.attacker_url}/attack_turn_start  "
          f"(ep={episode} r={round}, time_limit={tl}s)")
    client = HttpAttackerClient(cfg.network.attacker_url, token=cfg.network.shared_token)
    start = AttackTurnStart(
        time_limit_sec=tl,
        flag_format=cfg.flags.format,
        foothold=Foothold(attack_endpoint=cfg.target.attack_endpoint))
    t0 = time.time()
    try:
        res = client.attack_turn(start, episode=episode, round=round)
    except Exception as e:  # noqa: BLE001 — 전송 자체 실패(연결 거부·타임아웃 등)
        print(f"  \033[31m✗ 전송 실패\033[0m ({time.time() - t0:.1f}s): {type(e).__name__}: {e}")
        return
    tag = "\033[31m✗\033[0m" if res.end_reason.value == "error" else "\033[32m✓\033[0m"
    print(f"  {tag} end_reason={res.end_reason.value}  elapsed={time.time() - t0:.1f}s  "
          f"flags={[f.value for f in res.flags_obtained]}")
    print(f"    attack_summary: {res.attack_summary!r}")


def _poke_defense(cfg, *, episode: int, round: int, time_limit=None) -> None:
    tl = time_limit if time_limit is not None else cfg.experiment.time_limit_sec
    print(f"\n[방어] POST {cfg.network.defender_url}/defense_turn_start  "
          f"(ep={episode} r={round}, time_limit={tl}s)")
    print("    ※ 방어 LLM(triage) 호출이 있어 수백 초 걸릴 수 있음 — 기다리세요.")
    client = HttpDefenderClient(cfg.network.defender_url, token=cfg.network.shared_token)
    start = DefenseTurnStart(time_limit_sec=tl)
    t0 = time.time()
    try:
        res = client.defense_turn(start, episode=episode, round=round)
    except Exception as e:  # noqa: BLE001
        print(f"  \033[31m✗ 전송 실패\033[0m ({time.time() - t0:.1f}s): {type(e).__name__}: {e}")
        return
    tag = "\033[31m✗\033[0m" if res.end_reason.value == "error" else "\033[32m✓\033[0m"
    print(f"  {tag} end_reason={res.end_reason.value}  elapsed={time.time() - t0:.1f}s  "
          f"patch_applied={res.patch_applied}  detected={len(res.detected)}  "
          f"health={res.healthcheck_passed}")
    if res.error:
        print(f"    \033[31merror:\033[0m {res.error}")
    techs = [d.technique for d in res.detected if d.technique]
    if techs:
        print(f"    탐지 기법(MITRE): {techs}")
    attempts = getattr(res, "patch_attempts", None)
    if attempts:
        print(f"    패치 시도:")
        for pa in attempts:
            print(f"      - {pa}")
    elif res.end_reason.value == "noop":
        print(f"    패치 시도: (없음 — LLM이 patch_plan 을 비웠거나 제안이 전부 미지원)")
    note = getattr(res, "patch_note", "")
    if note:
        print(f"    패치 메모: {note}")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="하네스 직접 찌르기(진단) — 스냅샷 루프 없이")
    ap.add_argument("--config", default=None, help="config.yaml 경로(기본: 탐색)")
    ap.add_argument("--which", choices=["attack", "defense", "both"], default="both")
    ap.add_argument("--episode", type=int, default=0)
    ap.add_argument("--round", type=int, default=1)
    ap.add_argument("--time-limit", type=int, default=None,
                    help="턴 제한시간(초) — config 덮어씀. 측정용으로 짧게(예: 180)")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    print(f"[*] 진단 대상  공격자={cfg.network.attacker_url}  방어자={cfg.network.defender_url}")

    if args.which in ("attack", "both"):
        _poke_attack(cfg, episode=args.episode, round=args.round, time_limit=args.time_limit)
    if args.which in ("defense", "both"):
        _poke_defense(cfg, episode=args.episode, round=args.round, time_limit=args.time_limit)

    print("\n[i] end_reason=error 면 위의 attack_summary/error 와 "
          "해당 VM 서버 콘솔의 traceback 을 확인하세요.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
