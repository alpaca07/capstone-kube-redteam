"""VM C 진입점 — 실험 시작(= 경기 시작).

    python orchestrator/main.py --episodes N --max-rounds M --time-limit T
    python -m orchestrator.main --config config.yaml

관리자가 직접 실행하는 프로그램(자동 기동 아님). config.yaml을 읽어 실 어댑터
(HTTP 클라이언트·govc 스냅샷·로그 소스)를 조립하고, 턴 시퀀서로 에피소드를 돌린다.
라운드 기록은 JSON Lines로, 에피소드 요약은 별도 파일 + 콘솔로 떨군다.

build_sequencer / load_flag4 는 I/O 없이 조립만 하므로 테스트 가능(실제 연결은 run 때).
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import Optional

# python orchestrator/main.py 로도, -m orchestrator.main 으로도 돌게 저장소 루트를 경로에.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.config import Config, load_config  # noqa: E402
from orchestrator.flags import default_registry  # noqa: E402
from orchestrator.govc_snapshot import GovcSnapshotManager  # noqa: E402
from orchestrator.http_clients import HttpAttackerClient, HttpDefenderClient  # noqa: E402
from orchestrator.log_source import AuditFalcoLogSource, file_line_reader  # noqa: E402
from orchestrator.scorer import jsonl_file_sink  # noqa: E402
from orchestrator.sequencer import RunParams, TurnSequencer  # noqa: E402
from orchestrator.truth_log import TruthLog  # noqa: E402
from orchestrator.verifier import VerificationEngine  # noqa: E402


def load_flag4(path: str) -> Optional[str]:
    """generate-flags.sh가 심은 ④ 값을 읽음(gitignore된 secret). `FLAG_4=...` 또는 bare FLAG{...}."""
    try:
        with open(path, encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if line.startswith("FLAG_4="):
                    return line.split("=", 1)[1].strip().strip('"').strip("'")
                if line.startswith("FLAG{"):
                    return line
    except FileNotFoundError:
        return None
    return None


def _build_snapshots(cfg: Config):
    """config.vmware.method로 스냅샷 매니저 선택.

    - agent : 호스트 데스크톱 세션의 스냅샷 에이전트에 HTTP 위임(권장 — Workstation에서
              SSH는 revert 후 VM 재개를 못 함). HttpSnapshotManager.
    - vmrun : VM C→호스트 SSH로 vmrun 직접(스냅샷은 되나 재개 불가 — 사실상 비권장).
    - govc  : ESXi/vCenter.
    """
    if cfg.vmware.method.lower() == "agent":
        from orchestrator.http_snapshot import HttpSnapshotManager
        return HttpSnapshotManager(cfg.vmware.snapshot_agent_url,
                                   token=cfg.network.shared_token)
    if cfg.vmware.method.lower() == "vmrun":
        from orchestrator.vmrun_snapshot import (
            VmrunSnapshotManager, ssh_runner, local_runner)
        opts = cfg.vmware.ssh_opts.split() if cfg.vmware.ssh_opts else []
        runner = (ssh_runner(cfg.vmware.ssh_target, ssh_opts=opts)
                  if cfg.vmware.ssh_target else local_runner())
        return VmrunSnapshotManager(cfg.vmware.vmx_path, runner=runner,
                                    vmrun=cfg.vmware.vmrun_path)
    return GovcSnapshotManager(cfg.vmware.target_vm_name,
                               govc_env={"GOVC_URL": cfg.vmware.vcenter_or_esxi})


def build_sequencer(cfg: Config, *, flag4_value: Optional[str] = None,
                    sink=None, params: Optional[RunParams] = None) -> TurnSequencer:
    """config + 실 어댑터로 턴 시퀀서 조립(I/O 없음 — 실제 연결은 run_experiment에서)."""
    attacker = HttpAttackerClient(cfg.network.attacker_url, token=cfg.network.shared_token)
    defender = HttpDefenderClient(cfg.network.defender_url, token=cfg.network.shared_token)
    snapshots = _build_snapshots(cfg)
    registry = default_registry(flag4_value)
    verifier = VerificationEngine(attacker, defender, snapshots, registry)
    logs = AuditFalcoLogSource(file_line_reader(cfg.observability.audit_log_path),
                               file_line_reader(cfg.observability.falco_log_path))
    truth = TruthLog()
    if params is None:
        params = RunParams(
            episodes=cfg.experiment.episodes, max_rounds=cfg.experiment.max_rounds,
            n_consecutive_defense=cfg.experiment.n_consecutive_defense,
            time_limit_sec=cfg.experiment.time_limit_sec,
            baseline_snapshot=cfg.vmware.baseline_snapshot,
            attack_endpoint=cfg.target.attack_endpoint, flag_format=cfg.flags.format)
    return TurnSequencer(attacker=attacker, defender=defender, snapshots=snapshots,
                         verifier=verifier, logs=logs, registry=registry, truth=truth,
                         params=params, sink=sink)


def _params_from_args(cfg: Config, args: argparse.Namespace) -> RunParams:
    """CLI 인자가 있으면 config를 덮어씀(없으면 config 값)."""
    return RunParams(
        episodes=args.episodes if args.episodes is not None else cfg.experiment.episodes,
        max_rounds=args.max_rounds if args.max_rounds is not None else cfg.experiment.max_rounds,
        n_consecutive_defense=cfg.experiment.n_consecutive_defense,
        time_limit_sec=args.time_limit if args.time_limit is not None else cfg.experiment.time_limit_sec,
        baseline_snapshot=cfg.vmware.baseline_snapshot,
        attack_endpoint=cfg.target.attack_endpoint, flag_format=cfg.flags.format)


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="K8s 공수 공진화 오케스트레이터(VM C)")
    ap.add_argument("--config", default=None, help="config.yaml 경로(기본: 탐색)")
    ap.add_argument("--episodes", type=int, default=None, help="에피소드 수(config 덮어씀)")
    ap.add_argument("--max-rounds", type=int, default=None, help="에피소드당 최대 라운드")
    ap.add_argument("--time-limit", type=int, default=None, help="턴당 제한시간(초)")
    ap.add_argument("--flag-file", default=str(_ROOT / "k8s" / "flags" / "flag-values.secret"),
                    help="④ 값 secret 파일")
    ap.add_argument("--out-dir", default=str(_ROOT / "orchestrator" / "logs"),
                    help="로그 출력 디렉토리")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    flag4 = load_flag4(args.flag_file)
    params = _params_from_args(cfg, args)

    os.makedirs(args.out_dir, exist_ok=True)
    rounds_path = os.path.join(args.out_dir, "rounds.jsonl")
    episodes_path = os.path.join(args.out_dir, "episodes.jsonl")
    sink = jsonl_file_sink(rounds_path)

    seq = build_sequencer(cfg, flag4_value=flag4, sink=sink, params=params)

    print(f"[*] 실험 시작: episodes={params.episodes} max_rounds={params.max_rounds} "
          f"time_limit={params.time_limit_sec}s flag4={'로드됨' if flag4 else '없음(리플레이로만 ④판정)'}")
    print(f"    대상 VM={cfg.vmware.target_vm_name} baseline={params.baseline_snapshot}")
    print(f"    공격자={cfg.network.attacker_url}  방어자={cfg.network.defender_url}")

    summaries = seq.run_experiment()

    import json
    with open(episodes_path, "w", encoding="utf-8") as f:
        for s in summaries:
            f.write(json.dumps(s.to_dict(), ensure_ascii=False) + "\n")

    print("\n[✓] 완료. 에피소드 요약:")
    for s in summaries:
        d = s.detection
        print(f"  ep{s.episode}: {s.rounds}R 종료={s.end_reason} "
              f"플래그깊이={s.max_flag_depth} 탐지(TP/FP/FN)={d.tp}/{d.fp}/{d.fn} "
              f"MTTD={s.mttd.mean_rounds} 판정={s.verdict_counts}")
    print(f"\n    라운드 로그: {rounds_path}\n    에피소드 요약: {episodes_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
