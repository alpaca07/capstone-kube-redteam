"""하네스² CLI — VM C 에서 실 어댑터로 실행.

서브커맨드:
  probe   : 시험실행 1회(되돌림→공격→god-view 채점). 편집자·합성 없이 측정만.
  refine  : 개량 1사이클(제안·시험실행·합성). 편집자(정렬)가 수정안을 내고, 상위 k를 탈옥으로
            실측해, 기준선+문턱을 넘는 최고안을 오버레이로 승급.

실행(어디서: VM C — 심판, cfg.target.kubeconfig 로 clean 리셋·god-view 로그 조회):
  python3 -m refiner probe  --config config.yaml
  python3 -m refiner refine --config config.yaml [--digest-file d.json]
서브커맨드 없이 `python3 -m refiner --config ...` 는 probe 로 동작(기존 호환).
refine 은 기반 프롬프트가 필요 → VM C 에서 먼저: git sparse-checkout add attacker/prompts
"""
from __future__ import annotations

import argparse
import json
import sys

from common.config import load_config
from refiner.builder import build_probe, run_refine
from refiner.models import Harness


def _cmd_probe(args) -> int:
    cfg = load_config(args.config)
    probe = build_probe(cfg, stage_weight=args.stage_weight,
                        crown_bonus=args.crown_bonus, log=lambda m: print(f"[probe] {m}"))
    base = ""
    if args.prompt_file:
        with open(args.prompt_file, "r", encoding="utf-8") as f:
            base = f.read()
    harness = Harness(base_prompt=base)
    print(f"[probe] 시작 — basis={args.basis}, "
          f"프롬프트={'파일 ' + args.prompt_file if args.prompt_file else 'VM A 라이브(기준선)'}")
    score = probe.probe(harness, basis=args.basis)
    print("[probe] 결과:")
    print(json.dumps({"score": score.score, "basis": score.basis, "detail": score.detail},
                     ensure_ascii=False, indent=2))
    return 0


def _cmd_refine(args) -> int:
    cfg = load_config(args.config)
    digest: dict = {}
    if args.digest_file:
        with open(args.digest_file, "r", encoding="utf-8") as f:
            digest = json.load(f)
    print(f"[refine] 시작 — n={args.n_candidates or cfg.refiner.n_candidates}, "
          f"top_k={args.probe_top_k or cfg.refiner.probe_top_k}, "
          f"basis={args.basis or cfg.refiner.probe_basis}")
    try:
        result = run_refine(cfg, digest, n_candidates=args.n_candidates,
                            probe_top_k=args.probe_top_k, basis=args.basis,
                            min_gain=args.min_gain, log=lambda m: print(f"[refine] {m}"))
    except RuntimeError as e:
        print(f"[refine] 중단: {e}")
        return 2
    print("[refine] 결과:")
    print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    print(f"[refine] {'승급함: ' + result.chosen.id if result.promoted else '승급 없음(하네스 보존)'}")
    return 0


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # 서브커맨드 없이 오면 기존 호환으로 probe 로.
    if not argv or (argv[0].startswith("-") and argv[0] not in ("-h", "--help")):
        argv = ["probe"] + argv

    ap = argparse.ArgumentParser(prog="refiner", description="하네스² 시험실행/개량 CLI")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("probe", help="시험실행 1회(측정만)")
    p.add_argument("--config", default=None)
    p.add_argument("--basis", default="clean", choices=["clean", "patched"])
    p.add_argument("--prompt-file", default=None, help="후보 프롬프트 파일(없으면 VM A 라이브=기준선)")
    p.add_argument("--stage-weight", type=float, default=1.0)
    p.add_argument("--crown-bonus", type=float, default=10.0)
    p.set_defaults(func=_cmd_probe)

    r = sub.add_parser("refine", help="개량 1사이클(제안·시험실행·합성)")
    r.add_argument("--config", default=None)
    r.add_argument("--digest-file", default=None, help="직전 교전 god-view 요약 JSON(없으면 빈 요약)")
    r.add_argument("--n-candidates", type=int, default=None, dest="n_candidates")
    r.add_argument("--probe-top-k", type=int, default=None, dest="probe_top_k")
    r.add_argument("--basis", default=None, choices=["clean", "patched"])
    r.add_argument("--min-gain", type=float, default=None, dest="min_gain")
    r.set_defaults(func=_cmd_refine)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
