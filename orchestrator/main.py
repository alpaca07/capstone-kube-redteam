"""VM C 진입점 — 실험 시작(= 경기 시작).

    python orchestrator/main.py --episodes N --max-rounds M --time-limit T
    python -m orchestrator.main --config config.yaml

관리자가 직접 실행하는 프로그램(자동 기동 아님). config.yaml을 읽어 실 어댑터
(HTTP 클라이언트·govc 스냅샷·로그 소스)를 조립하고, 턴 시퀀서로 회차를 돌린다.
라운드 기록은 JSON Lines로, 회차 요약은 별도 파일 + 콘솔로 떨군다.

build_sequencer 는 I/O 없이 조립만 하므로 테스트 가능(실제 연결은 run 때).
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Optional

# python orchestrator/main.py 로도, -m orchestrator.main 으로도 돌게 저장소 루트를 경로에.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.config import Config, load_config  # noqa: E402
from orchestrator.baseline import BaselineManager, kubectl_runner  # noqa: E402
from orchestrator.flags import default_registry  # noqa: E402
from orchestrator.objectives import resolve_objectives, resolve_goal  # noqa: E402
from orchestrator.govc_snapshot import GovcSnapshotManager  # noqa: E402
from orchestrator.http_clients import HttpAttackerClient, HttpDefenderClient  # noqa: E402
from orchestrator.log_source import AuditFalcoLogSource, file_line_reader  # noqa: E402
from orchestrator.app_log_source import AppLogSource, CompositeLogSource  # noqa: E402
from orchestrator.db_log_source import DbLogSource  # noqa: E402
from orchestrator.events import EventSink, jsonl_event_sink  # noqa: E402
from orchestrator.progress import ProgressSink  # noqa: E402
from orchestrator.scorer import jsonl_file_sink  # noqa: E402
from common.off_kg import jsonl_file_sink as off_kg_file_sink  # noqa: E402
from orchestrator.sequencer import RunParams, TurnSequencer  # noqa: E402
from orchestrator.truth_log import TruthLog  # noqa: E402
from orchestrator.verifier import VerificationEngine  # noqa: E402


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


def build_sequencer(cfg: Config, *, sink=None, progress=None, events=None,
                    detail_dir=None, off_kg_sink=None,
                    params: Optional[RunParams] = None) -> TurnSequencer:
    """config + 실 어댑터로 턴 시퀀서 조립(I/O 없음 — 실제 연결은 run_experiment에서)."""
    attacker = HttpAttackerClient(cfg.network.attacker_url, token=cfg.network.shared_token)
    defender = HttpDefenderClient(cfg.network.defender_url, token=cfg.network.shared_token)
    # A2: VM 스냅샷 대신 k8s 네이티브 베이스라인 리셋(심판이 cfg.target.kubeconfig 로 kubectl 직접).
    #   stun 유발 vmrun 스냅샷 제거(§8 #1). 매니페스트는 리포 루트 기준 절대경로(cwd 무관).
    #   전제: VM C 에 admin kubeconfig(cfg.target.kubeconfig) + k8s/killchain 체크아웃.
    baseline = BaselineManager(
        runner=kubectl_runner(cfg.target.kubeconfig or None),
        manifest_paths=(str(_ROOT / "k8s" / "killchain"),),
        # 발판 자동전환: baseline 회차간 재시작도 공격자 exec 와 같은 발판(cfg.attack, CLI override 반영됨)으로.
        foothold=(cfg.attack.exec_namespace, cfg.attack.exec_pod.split("/")[-1]),
        baseline_name=cfg.vmware.baseline_snapshot)
    registry = default_registry()               # 상태검증·탐지 채점용(①②③·web·esc·disc)
    objectives = resolve_objectives(            # free=빈(채점 끔) / asset=선택(비면 전체)
        cfg.experiment.objective_mode, cfg.experiment.target_assets)
    logs = CompositeLogSource(
        AuditFalcoLogSource(file_line_reader(cfg.observability.audit_log_path),
                            file_line_reader(cfg.observability.falco_log_path)),
        # [Phase A] 앱 레벨 웹 공격(SQLi·SSRF·cmdi·cred-leak) + 크라운 자백 — 서비스 JSON 감사 로그.
        AppLogSource(file_line_reader(cfg.observability.app_log_path)),
        # [B] 직접 DB 접속 크라운 — postgres statement 로그(앱 안 거치는 ④ 경로).
        #     attacker_db_roles 가 설정되면 그 role 접속만 크라운(앱·슈퍼유저 조회 제외).
        DbLogSource(file_line_reader(cfg.observability.db_log_path),
                    attacker_roles=cfg.observability.attacker_db_roles or None),
    )
    verifier = VerificationEngine(attacker, defender, baseline, registry,
                                  logs=logs, objectives=objectives)
    truth = TruthLog()
    if params is None:
        params = RunParams(
            episodes=cfg.experiment.episodes, max_rounds=cfg.experiment.max_rounds,
            n_consecutive_defense=cfg.experiment.n_consecutive_defense,
            time_limit_sec=cfg.experiment.time_limit_sec,
            max_tokens=cfg.dgx.max_tokens,
            baseline_snapshot=cfg.vmware.baseline_snapshot,
            goal=resolve_goal(cfg.experiment.objective_mode,       # free=사람 문구 / asset=선택 자산 생성
                              cfg.experiment.objective, cfg.experiment.target_assets),
            crown_sync_grace_sec=cfg.experiment.crown_sync_grace_sec,
            crown_skew_pad_sec=cfg.experiment.crown_skew_pad_sec,
            # exec_mode면 발판은 외부 URL 이 아니라 '클러스터 내부 파드'라 endpoint 를 비운다.
            attack_endpoint=(None if cfg.attack.exec_mode else cfg.target.attack_endpoint),
            exec_namespace=cfg.attack.exec_namespace, exec_pod=cfg.attack.exec_pod)
    return TurnSequencer(attacker=attacker, defender=defender, snapshots=baseline,
                         verifier=verifier, logs=logs, registry=registry,
                         objectives=objectives, truth=truth,
                         params=params, sink=sink, off_kg_sink=off_kg_sink,
                         progress=progress, events=events, detail_dir=detail_dir)


def _params_from_args(cfg: Config, args: argparse.Namespace) -> RunParams:
    """CLI 인자가 있으면 config를 덮어씀(없으면 config 값)."""
    return RunParams(
        episodes=args.episodes if args.episodes is not None else cfg.experiment.episodes,
        max_rounds=args.max_rounds if args.max_rounds is not None else cfg.experiment.max_rounds,
        n_consecutive_defense=cfg.experiment.n_consecutive_defense,
        time_limit_sec=args.time_limit if args.time_limit is not None else cfg.experiment.time_limit_sec,
        max_tokens=args.max_tokens if args.max_tokens is not None else cfg.dgx.max_tokens,
        baseline_snapshot=cfg.vmware.baseline_snapshot,
        run_id=time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()),
        attacker_model=cfg.dgx.attacker_model,
        goal=resolve_goal(cfg.experiment.objective_mode,           # 모드별 목표 문구(cfg는 CLI로 이미 덮임)
                          cfg.experiment.objective, cfg.experiment.target_assets),
        crown_sync_grace_sec=cfg.experiment.crown_sync_grace_sec,
        crown_skew_pad_sec=cfg.experiment.crown_skew_pad_sec,
        # exec_mode면 발판은 외부 URL 이 아니라 '클러스터 내부 파드'라 endpoint 를 비운다.
        attack_endpoint=(None if cfg.attack.exec_mode else cfg.target.attack_endpoint),
        exec_namespace=cfg.attack.exec_namespace,   # 발판 override 반영(공격자에 StartTurn 으로 전달)
        exec_pod=cfg.attack.exec_pod,
        skip_revert=args.no_revert,
        force_crown=args.force_crown)


# 새 런 시작 시 이관할 지난 런 산출물 — 대시보드 _ARCHIVE_* 와 동일 집합(라이브 디렉토리를 비워
# '지금 돌리는 실험'만 남긴다). runs.jsonl·progress.json·off_kg.jsonl 은 보존(런 레지스트리·현재
# 상태·off-KG 포획 누적).
_ARCHIVE_JSONL = ("rounds.jsonl", "episodes.jsonl", "events.jsonl", "attack_journal.jsonl")
_ARCHIVE_DIRS = ("round_detail", "defense_topology", "attack_graph")


def _archive_prior_logs(out_dir: str) -> Optional[str]:
    """새 런 시작 전, 지난 런의 회차 로그·라운드 상세·공격 그래프를 runs_archive/<ts>/ 로 옮긴다.
    삭제가 아니라 보관 — 대시보드가 이전 런 그래프를 계속 들고 있지 않게 라이브 디렉토리를 비운다."""
    dest = os.path.join(out_dir, "runs_archive", time.strftime("%Y%m%d-%H%M%S"))
    moved = False
    try:
        for name in _ARCHIVE_JSONL:
            src = os.path.join(out_dir, name)
            if os.path.isfile(src) and os.path.getsize(src) > 0:
                os.makedirs(dest, exist_ok=True)
                shutil.move(src, os.path.join(dest, name))
                moved = True
        for name in _ARCHIVE_DIRS:
            src = os.path.join(out_dir, name)
            if os.path.isdir(src) and os.listdir(src):
                os.makedirs(dest, exist_ok=True)
                shutil.move(src, os.path.join(dest, name))
                moved = True
    except OSError:
        return None
    return dest if moved else None


def _append_run_manifest(path: str, params: RunParams, cfg: Config) -> None:
    """실행 시작 시 회차 설정을 runs.jsonl 에 한 줄 남긴다 — 대시보드가 로그를 회차별로 나누고
    각 회차의 초기 설정값(에피소드·라운드·제한시간·토큰·대상)을 보여주는 소스. 대시보드 /api/run 이
    쓰는 줄과 같은 모양({id,started,params}) + 출처·대상 보강. 쓰기 실패는 실험을 멈추지 않는다."""
    rec = {
        "id": params.run_id,
        "started": time.time(),
        "source": "cli",
        "params": {
            "episodes": params.episodes,
            "max_rounds": params.max_rounds,
            "time_limit": params.time_limit_sec,
            "max_tokens": params.max_tokens,
        },
        "objective_mode": getattr(cfg.experiment, "objective_mode", ""),
        "target_assets": list(getattr(cfg.experiment, "target_assets", []) or []),
        "target_vm": getattr(cfg.vmware, "target_vm_name", ""),
    }
    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass


def main(argv: Optional[list[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="K8s 공수 공진화 오케스트레이터(VM C)")
    ap.add_argument("--config", default=None, help="config.yaml 경로(기본: 탐색)")
    ap.add_argument("--episodes", type=int, default=None, help="회차 수(config 덮어씀)")
    ap.add_argument("--max-rounds", type=int, default=None, help="회차당 최대 라운드")
    ap.add_argument("--time-limit", type=int, default=None, help="턴당 제한시간(초)")
    ap.add_argument("--max-tokens", type=int, default=None,
                    help="공격 생성 토큰 상한(실험 파라미터; 생략 시 config.dgx.max_tokens)")
    ap.add_argument("--out-dir", default=str(_ROOT / "orchestrator" / "logs"),
                    help="로그 출력 디렉토리")
    ap.add_argument("--force-crown", action="store_true",
                    help="(스모크 전용) 크라운 미검출이어도 방어+검증 게이트 강제 — 루프 배관 점검용")
    ap.add_argument("--no-revert", action="store_true",
                    help="회차 init 의 baseline revert 생략 — 라이브(이미 취약 상태) 클러스터를 "
                         "그대로 공격. vmrun revert 가 k3s exec 을 느리게 만드는 인프라 이슈 회피용 "
                         "단발 포획·디버그. 다중 회차 리셋 불가.")
    ap.add_argument("--objective-mode", default=None, choices=["free", "asset"],
                    help="목표 모드(config 덮어씀): free=자유 목표 문구(크라운 채점 없음) / "
                         "asset=크라운 자산 선택(자산별 채점)")
    ap.add_argument("--objective", default=None,
                    help="free 모드 목표 문구 — 공격자에게 줄 '무엇을'(어디서·어떻게는 안 줌)")
    ap.add_argument("--target-assets", default=None,
                    help="asset 모드 크라운 자산 id 쉼표구분(예: crown-pii,crown-secrets). 비우면 전체")
    ap.add_argument("--exec-namespace", default=None,
                    help="in-cluster exec 발판 네임스페이스 override(대시보드 타깃→발판 자동전환; config.attack 덮음)")
    ap.add_argument("--exec-pod", default=None,
                    help="kubectl exec 대상 override(deploy/… 또는 파드명; config.attack 덮음)")
    ap.add_argument("--attacker-db-roles", default=None,
                    help="DB 크라운 역할 스코핑 override(쉼표구분; 빈문자열=스코핑 없음). 대시보드 타깃→자동. config.observability 덮음")
    ap.add_argument("--db-log-corp", action="store_true",
                    help="corp 크라운 DB 로그(corp-crown) 파일(-corp)을 읽음 — db_log_path 를 -corp 변형으로. 대시보드 corp 타깃→자동")
    ap.add_argument("--keep-logs", action="store_true",
                    help="지난 런 로그를 아카이브하지 않고 유지(기본: 새 런 시작 시 지난 로그를 "
                         "runs_archive/ 로 이관해 대시보드에 이전 그래프가 남지 않게 함)")
    args = ap.parse_args(argv)

    cfg = load_config(args.config)
    # CLI 가 config 의 목표 설정을 덮어씀(지정된 것만) — _params_from_args·build_sequencer 가 이 cfg 를 읽는다.
    if args.objective_mode is not None:
        cfg.experiment.objective_mode = args.objective_mode
    if args.objective is not None:
        cfg.experiment.objective = args.objective
    if args.target_assets is not None:
        cfg.experiment.target_assets = [s.strip() for s in args.target_assets.split(",") if s.strip()]
    # 발판 override(대시보드 타깃→자동전환) — cfg.attack 에 반영: 공격자엔 StartTurn 으로, baseline 엔 build_sequencer 가 이 값으로 전달.
    if args.exec_namespace is not None:
        cfg.attack.exec_namespace = args.exec_namespace
    if args.exec_pod is not None:
        cfg.attack.exec_pod = args.exec_pod
    # DB 크라운 채점 override(대시보드 타깃→자동): 역할 스코핑 + 읽을 로그 파일(ShopFlow=base / corp=-corp).
    if args.attacker_db_roles is not None:
        cfg.observability.attacker_db_roles = [s.strip() for s in args.attacker_db_roles.split(",") if s.strip()]
    if args.db_log_corp:
        _p = cfg.observability.db_log_path
        cfg.observability.db_log_path = (_p[:-4] + "-corp.log") if _p.endswith(".log") else (_p + "-corp")
    params = _params_from_args(cfg, args)

    os.makedirs(args.out_dir, exist_ok=True)
    if not args.keep_logs:                       # 새 런 = 깨끗한 시작(이전 그래프·회차 기록 이관)
        _arch = _archive_prior_logs(args.out_dir)
        if _arch:
            print(f"[*] 지난 런 로그 보관 → {_arch}")
    rounds_path = os.path.join(args.out_dir, "rounds.jsonl")
    episodes_path = os.path.join(args.out_dir, "episodes.jsonl")
    progress_path = os.path.join(args.out_dir, "progress.json")
    events_path = os.path.join(args.out_dir, "events.jsonl")
    off_kg_path = os.path.join(args.out_dir, "off_kg.jsonl")
    sink = jsonl_file_sink(rounds_path)
    off_kg_sink = off_kg_file_sink(off_kg_path)   # off-KG 포획 저널(승격은 개발기 knowledge/promote.py)
    progress = ProgressSink(progress_path)       # 실시간 진행 상태(/api/status 소스)
    events = EventSink(jsonl_event_sink(events_path), run_id=params.run_id)  # 행위 이벤트(이벤트 로그·타임라인 소스)
    detail_dir = args.out_dir                    # round_detail/ · defense_topology/ 를 여기 아래 떨굼
    _append_run_manifest(os.path.join(args.out_dir, "runs.jsonl"), params, cfg)  # 회차 설정 기록(대시보드 분리용)

    seq = build_sequencer(cfg, sink=sink, progress=progress,
                          events=events, detail_dir=detail_dir,
                          off_kg_sink=off_kg_sink, params=params)

    print(f"[*] 실험 시작: episodes={params.episodes} max_rounds={params.max_rounds} "
          f"time_limit={params.time_limit_sec}s "
          f"max_tokens={params.max_tokens if params.max_tokens is not None else '무제한(config 기본)'}")
    print(f"    대상 VM={cfg.vmware.target_vm_name} baseline={params.baseline_snapshot}")
    print(f"    공격자={cfg.network.attacker_url}  방어자={cfg.network.defender_url}")
    foothold_desc = (f"in-cluster exec({cfg.attack.exec_namespace}/{cfg.attack.exec_pod})"
                     if cfg.attack.exec_mode else f"외부 endpoint({cfg.target.attack_endpoint})")
    print(f"    발판={foothold_desc}")
    if cfg.experiment.objective_mode == "asset":
        _sel = ",".join(cfg.experiment.target_assets) if cfg.experiment.target_assets else "(전체)"
        print(f"    목표 모드=asset  채점 자산={_sel}")
    else:
        print(f"    목표 모드=free  (크라운 채점 없음 — 탐색·데모)")
    _g = params.goal
    print(f"    공격자 목표={_g[:70] + ('…' if len(_g) > 70 else '')}")

    summaries = seq.run_experiment()

    import json
    with open(episodes_path, "w", encoding="utf-8") as f:
        for s in summaries:
            f.write(json.dumps(s.to_dict(), ensure_ascii=False) + "\n")

    print("\n[✓] 완료. 회차 요약:")
    for s in summaries:
        d = s.detection
        print(f"  ep{s.episode}: {s.rounds}R 종료={s.end_reason} "
              f"플래그깊이={s.max_flag_depth} 탐지(TP/FP/FN)={d.tp}/{d.fp}/{d.fn} "
              f"MTTD={s.mttd.mean_rounds} 판정={s.verdict_counts}")
    print(f"\n    라운드 로그: {rounds_path}\n    회차 요약: {episodes_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
