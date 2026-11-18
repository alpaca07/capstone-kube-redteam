"""실 조립 — config 로 HarnessProbe(시험실행)를 라이브와 동일한 실 어댑터로 구성.

오케스트레이터 build_sequencer 와 '같은' 어댑터를 쓴다(스냅샷·공격 클라이언트·로그 소스
composite·채점 레지스트리) → 시험실행 점수가 라이브 채점과 일치. 조립만 하고 I/O 는 안 한다
(모든 어댑터는 지연 — 실제 연결은 probe() 호출 때).

되돌림은 BaselineManager(k8s 네이티브 clean 리셋) — 라이브와 동일. 이 모델에선 '패치후
스냅샷'이 없어(save/revert 무동작) basis="patched" 는 사실상 clean 리셋이 된다. patched
기준이 꼭 필요하면 VM 스냅샷 모드(govc/vmrun)가 필요 — 현 라이브 경로는 clean 기준만 유효.
"""
from __future__ import annotations

from pathlib import Path
from typing import Callable, Optional

from common.config import Config
from common.messages import Foothold
from refiner.probe import HarnessProbe
from refiner.score import GodviewScorer

_ROOT = Path(__file__).resolve().parent.parent


def build_probe(
    cfg: Config,
    *,
    score_turn=None,
    stage_weight: float = 1.0,
    flag_weight: float = 1.0,
    crown_bonus: float = 10.0,
    clean_snapshot: Optional[str] = None,
    patched_snapshot=None,
    settle_sec: Optional[float] = None,
    goal: Optional[str] = None,
    log: Optional[Callable[[str], None]] = None,
) -> HarnessProbe:
    """config + 실 어댑터로 HarnessProbe 조립(I/O 없음).

    score_turn 을 안 주면 GodviewScorer(라이브와 같은 로그 소스·레지스트리)로 자동 구성.
    """
    # 지연 import — refiner 를 오케스트레이터에 강결합하지 않도록 함수 안에서.
    from orchestrator.http_clients import HttpAttackerClient
    from orchestrator.baseline import BaselineManager, kubectl_runner
    from orchestrator.log_source import AuditFalcoLogSource, file_line_reader
    from orchestrator.app_log_source import AppLogSource, CompositeLogSource
    from orchestrator.db_log_source import DbLogSource
    from orchestrator.flags import default_registry
    from orchestrator.objectives import resolve_objectives

    attacker = HttpAttackerClient(cfg.network.attacker_url, token=cfg.network.shared_token)

    # 되돌림: 라이브와 동일한 k8s 네이티브 clean 리셋(killchain 매니페스트 재적용).
    baseline = BaselineManager(
        runner=kubectl_runner(cfg.target.kubeconfig or None),
        manifest_paths=(str(_ROOT / "k8s" / "killchain"),),
        foothold=(cfg.attack.exec_namespace, cfg.attack.exec_pod.split("/")[-1]),
        baseline_name=cfg.vmware.baseline_snapshot,
    )

    registry = default_registry()
    objectives = resolve_objectives(cfg.experiment.objective_mode,
                                    cfg.experiment.target_assets)

    # god-view 로그 소스 composite — 라이브 build_sequencer 와 동일 구성.
    logs = CompositeLogSource(
        AuditFalcoLogSource(file_line_reader(cfg.observability.audit_log_path),
                            file_line_reader(cfg.observability.falco_log_path)),
        AppLogSource(file_line_reader(cfg.observability.app_log_path)),
        DbLogSource(file_line_reader(cfg.observability.db_log_path),
                    attacker_roles=cfg.observability.attacker_db_roles or None),
    )

    st = score_turn or GodviewScorer(
        logs, objectives, registry,
        stage_weight=stage_weight, flag_weight=flag_weight, crown_bonus=crown_bonus,
        skew_pad=cfg.experiment.crown_skew_pad_sec,
        grace_sec=cfg.experiment.crown_sync_grace_sec,
    )

    # 발판: exec 모드면 클러스터 내부 파드(endpoint 비움, VM A가 자기 config.attack 발판 사용).
    #        아니면 외부 공격 엔드포인트를 첫 라운드 발판으로.
    foothold = None
    if not cfg.attack.exec_mode and cfg.target.attack_endpoint:
        foothold = Foothold(attack_endpoint=cfg.target.attack_endpoint)

    return HarnessProbe(
        snapshot=baseline,
        attacker=attacker,
        score_turn=st,
        clean_snapshot=clean_snapshot or cfg.vmware.baseline_snapshot,
        patched_snapshot=patched_snapshot,
        time_limit_sec=cfg.experiment.time_limit_sec,
        max_tokens=cfg.dgx.max_tokens,
        foothold=foothold,
        goal=goal,
        settle_sec=(cfg.experiment.crown_sync_grace_sec if settle_sec is None else settle_sec),
        log=log,
    )


def build_store(cfg: Config, *, log: Optional[Callable[[str], None]] = None):
    """config 로 FileHarnessStore 조립 — 오버레이는 VM C 로컬(refiner_state/), 기반은 레포 공격 프롬프트.

    기반 프롬프트 파일(attacker/prompts/attacker_system.txt)은 VM C sparse 에 없으면 못 읽음
    → 이 경우 기반이 빈 채로 와서 refine 이 거부한다(아래 run_refine 가드). VM C 에서 refine 을
    돌리려면 `git sparse-checkout add attacker/prompts` 선행 필요.
    """
    from refiner.store import FileHarnessStore
    state_path = _ROOT / "refiner_state" / "overlays.json"
    base_path = _ROOT / "attacker" / "prompts" / "attacker_system.txt"
    return FileHarnessStore(str(state_path), base_prompt_path=str(base_path), log=log)


def build_editor(cfg: Config, *, log: Optional[Callable[[str], None]] = None):
    """config 로 RefinerEditor 조립 — 정렬 모델(편집 엔드포인트)에 붙인다(I/O 없음).

    편집 엔드포인트 = refiner.editor_host(비면 dgx.defender_host), 모델 = refiner.editor_model
    (비면 dgx.defender_model). 서빙 여유 있는 '두 번째 엔드포인트'에 태워 라이브 공격 디코드와
    경합 안 함. 추론(thinking) 모델이라 JSON 잘림 방지로 max_tokens 비움(무제한).
    """
    from common.llm_client import OllamaClient
    from refiner.editor import RefinerEditor

    host = cfg.refiner.editor_host or cfg.dgx.defender_host
    model = cfg.refiner.editor_model or cfg.dgx.defender_model
    base_url = f"http://{host}:{cfg.dgx.port}/v1"
    req_timeout = cfg.dgx.request_timeout_sec or float(cfg.experiment.time_limit_sec)
    llm = OllamaClient(base_url, model, temperature=cfg.dgx.temperature,
                       timeout=req_timeout, max_tokens=None)
    return RefinerEditor(llm, log=log)


def run_refine(cfg: Config, digest: dict, *,
               n_candidates: Optional[int] = None, probe_top_k: Optional[int] = None,
               basis: Optional[str] = None, min_gain: Optional[float] = None,
               log: Optional[Callable[[str], None]] = None):
    """개량 한 사이클 실 조립·실행 — 편집자·시험실행·저장소를 config 로 엮어 refine() 호출.

    기반 프롬프트가 비어 있으면(VM C sparse 에 attacker/prompts 없음) override 가 기반 없이
    오버레이만 교체해 공격을 깨뜨리므로, 오버레이가 쌓일 상태에서는 거부한다.
    """
    from refiner.refiner import refine

    editor = build_editor(cfg, log=log)
    probe = build_probe(cfg, log=log)
    store = build_store(cfg, log=log)

    if not store.read().base_prompt.strip():
        raise RuntimeError(
            "기반 프롬프트를 읽지 못했습니다(attacker/prompts/attacker_system.txt). "
            "VM C 에서 refine 하려면 먼저: git sparse-checkout add attacker/prompts")

    return refine(
        digest, store=store, editor=editor, probe=probe,
        n_candidates=n_candidates if n_candidates is not None else cfg.refiner.n_candidates,
        probe_top_k=probe_top_k if probe_top_k is not None else cfg.refiner.probe_top_k,
        basis=basis or cfg.refiner.probe_basis,
        min_gain=min_gain if min_gain is not None else cfg.refiner.min_gain,
    )


__all__ = ["build_probe", "build_editor", "build_store", "run_refine"]
