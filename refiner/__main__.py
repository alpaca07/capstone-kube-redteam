"""시험실행 CLI — VM C 에서 실 어댑터로 시험실행 1회(되돌림→공격→god-view 채점).

실물 측정 고리를 한 번 돌려 숫자를 확인하는 용도. 편집자(제안)·합성 없이 probe 만.

실행(어디서: VM C — 심판, cfg.target.kubeconfig 로 clean 리셋·god-view 로그 조회):
  python3 -m refiner --config config.yaml
  python3 -m refiner --config config.yaml --prompt-file my_variant.txt   # 후보 프롬프트로
기본(--prompt-file 없음)은 기반 프롬프트 비움 → VM A 가 자기 라이브 프롬프트로 공격(기준선).
"""
from __future__ import annotations

import argparse
import json
import sys

from common.config import load_config
from refiner.builder import build_probe
from refiner.models import Harness


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="하네스² 시험실행 1회(probe)")
    ap.add_argument("--config", default=None, help="config.yaml 경로(기본 탐색 순서)")
    ap.add_argument("--basis", default="clean", choices=["clean", "patched"],
                    help="되돌림 기준 스냅샷(라이브 k8s 리셋은 clean 만 유효)")
    ap.add_argument("--prompt-file", default=None,
                    help="후보 시스템 프롬프트 파일. 없으면 VM A 라이브 프롬프트로(기준선)")
    ap.add_argument("--stage-weight", type=float, default=1.0)
    ap.add_argument("--crown-bonus", type=float, default=10.0)
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    probe = build_probe(cfg, stage_weight=args.stage_weight,
                        crown_bonus=args.crown_bonus, log=lambda m: print(f"[probe] {m}"))

    base = ""
    if args.prompt_file:
        with open(args.prompt_file, "r", encoding="utf-8") as f:
            base = f.read()
    harness = Harness(base_prompt=base)

    print(f"[probe] 시작 — basis={args.basis}, "
          f"프롬프트={'파일 '+args.prompt_file if args.prompt_file else 'VM A 라이브(기준선)'}")
    score = probe.probe(harness, basis=args.basis)
    print("[probe] 결과:")
    print(json.dumps({"score": score.score, "basis": score.basis, "detail": score.detail},
                     ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
