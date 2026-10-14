"""VM B 방어 하네스 — 턴 로직 배선(DefenseHarness). HTTP(FastAPI) 바인딩은 배포 층에서.

관측→필터→triage→패치 파이프라인을 묶어 VM C의 4개 메시지에 응답:
  defense_turn_start → defense_turn_result (관측·추론·패치, 공격정보 0으로 자력 추론)
  state_query        → state_query_result  (사실만)
  health_check       → health_result       (서비스 가용성)
  status             → agent_status        (하트비트)

컴포넌트(observer/triager/patcher/state_handler/cluster)를 주입받는다 → fake로 전체 테스트.
실제 LLM·kubectl 배선과 FastAPI 라우트(create_app)는 다음 단계(실 어댑터)에서.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Iterable, Optional

from common.messages import (
    AgentRole, AgentState, AgentStatus,
    DefenseEndReason, DefenseTurnResult, DefenseTurnStart, Detection,
    HealthCheck, HealthResult, MsgType, PatchItem, StateQuery,
    parse_envelope, wrap,
)

from .filter import filter_observations
from .observer import Observer
from .patcher import Patcher
from .state_query import StateQueryHandler
from .triage import Triager


def _patch_kind(action: str) -> str:
    a = action.lower()
    if "network" in a or "netpol" in a:
        return "networkpolicy"
    if "rbac" in a or "role" in a:
        return "rbac"
    if "pod" in a:
        return "pod"
    if "secret" in a:
        return "secret"
    return action or "patch"


class DefenseHarness:
    """방어 턴 로직. 상태는 증분 로그 커서만 보유(에이전트는 stateless 지향)."""

    def __init__(self, *, observer: Observer, triager: Triager, patcher: Patcher,
                 state_handler: StateQueryHandler, cluster, service: str = "all") -> None:
        self.observer = observer
        self.triager = triager
        self.patcher = patcher
        self.state_handler = state_handler
        self.cluster = cluster              # health_check용(healthcheck())
        self.service = service
        self._cursor: float = 0.0           # 마지막으로 본 로그 시각(증분 관측)

    # ── defense_turn_start → defense_turn_result ──
    def defense_turn(self, start: DefenseTurnStart, *, episode: int, round: int) -> DefenseTurnResult:
        t0 = time.time()
        try:
            obs = self.observer.collect(since_ts=self._cursor)
            self._cursor = max(self._cursor, obs.until_ts)          # 커서 전진(다음 라운드 증분)
            report = filter_observations(obs)
            triage = self.triager.triage(report)                   # LLM(공격정보 없이 자력 추론)
            outcome = self.patcher.apply_plan(triage.patch_plan)

            detected = [Detection(technique=d.mitre, evidence=d.evidence) for d in triage.detected]
            patch_set = [PatchItem(kind=_patch_kind(a.action), target=a.target, summary=a.detail)
                         for a in outcome.applied if a.ok]
            end = DefenseEndReason.PATCHED if outcome.patch_applied else DefenseEndReason.NOOP
            return DefenseTurnResult(
                patch_applied=outcome.patch_applied, end_reason=end,
                detected=detected, patch_set=patch_set,
                healthcheck_passed=outcome.healthcheck_passed,
                elapsed_sec=time.time() - t0)
        except Exception as e:              # noqa: BLE001 — 하네스 오류는 ERROR로 보고(루프 보호)
            return DefenseTurnResult(
                patch_applied=False, end_reason=DefenseEndReason.ERROR,
                detected=[], patch_set=[], healthcheck_passed=True,
                elapsed_sec=time.time() - t0)

    # ── state_query → state_query_result ──
    def state_query(self, query: StateQuery, *, episode: int, round: int) -> StateQueryResult:
        return self.state_handler.handle(query)

    # ── health_check → health_result ──
    def health_check(self, hc: HealthCheck, *, episode: int, round: int) -> HealthResult:
        t0 = time.time()
        try:
            r = self.cluster.healthcheck()
            healthy = bool(getattr(r, "ok", False))
        except Exception:                   # noqa: BLE001
            healthy = False
        return HealthResult(service=hc.service, healthy=healthy,
                            response_time_ms=(time.time() - t0) * 1000.0)

    def status(self) -> AgentStatus:
        return AgentStatus(agent=AgentRole.DEFENDER, state=AgentState.IDLE)


# ───────────── 메시지 디스패치 (FastAPI 없이 테스트 가능) ─────────────
def handle_message(harness: DefenseHarness, raw) -> dict:
    """수신 봉투(dict/str/bytes) → harness 디스패치 → 응답 봉투 dict."""
    env = parse_envelope(raw)
    t = env.type
    if t == MsgType.DEFENSE_TURN_START:
        resp = harness.defense_turn(env.payload_as(DefenseTurnStart),
                                    episode=env.episode, round=env.round)
    elif t == MsgType.STATE_QUERY:
        resp = harness.state_query(env.payload_as(StateQuery),
                                   episode=env.episode, round=env.round)
    elif t == MsgType.HEALTH_CHECK:
        resp = harness.health_check(env.payload_as(HealthCheck),
                                    episode=env.episode, round=env.round)
    elif t == MsgType.AGENT_STATUS:
        resp = harness.status()
    else:
        raise ValueError(f"방어 하네스가 처리 못 하는 메시지: {t.value}")
    return wrap(resp, episode=env.episode, round=env.round, status="ok").model_dump(mode="json")


# ───────────── 실 배선 ─────────────
def _file_line_reader(path: str) -> Callable[[], Iterable[str]]:
    def _r() -> Iterable[str]:
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    yield line
        except FileNotFoundError:
            return
    return _r


def _load_prompt() -> str:
    return (Path(__file__).resolve().parent / "prompts" / "defender_system.txt").read_text(encoding="utf-8")


def create_harness(cfg, *, prompt: Optional[str] = None, cluster=None, llm=None) -> DefenseHarness:
    """config + 실 어댑터로 DefenseHarness 조립(I/O 없음 — 실제 연결은 턴 때)."""
    from common.llm_client import OllamaClient
    from .kubectl_cluster import KubectlCluster
    cluster = cluster or KubectlCluster(kubeconfig=(cfg.target.kubeconfig or None))
    if llm is None:
        llm = OllamaClient(cfg.dgx.defender_base_url, cfg.dgx.defender_model, temperature=cfg.dgx.temperature)
    observer = Observer(_file_line_reader(cfg.observability.audit_log_path),
                        _file_line_reader(cfg.observability.falco_log_path))
    return DefenseHarness(observer=observer, triager=Triager(llm, prompt or _load_prompt()),
                          patcher=Patcher(cluster), state_handler=StateQueryHandler(cluster),
                          cluster=cluster)


def create_app(harness: DefenseHarness):
    """FastAPI 앱 — VM C가 POST하는 요청타입 경로를 harness로 디스패치. (fastapi lazy import)

    주의: harness 메서드는 LLM·kubectl로 블로킹하지만 VM C가 턴을 순차 호출하므로 OK.
    """
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse
    app = FastAPI(title="VM B 방어 하네스")

    @app.post("/status")
    async def _status():                       # noqa: ANN202
        return wrap(harness.status()).model_dump(mode="json")

    @app.post("/{msg_type}")
    async def _handle(msg_type: str, request: Request):   # noqa: ANN202
        body = await request.json()
        try:
            return handle_message(harness, body)
        except Exception as e:                 # noqa: BLE001
            return JSONResponse(status_code=400, content={"error": str(e)})

    return app


def main(argv: Optional[list] = None) -> int:
    """VM B 서버 실행. `python -m defender.server --config config.yaml`."""
    import argparse
    from common.config import load_config
    ap = argparse.ArgumentParser(description="VM B 방어 하네스 서버")
    ap.add_argument("--config", default=None, help="config.yaml 경로(기본: 탐색)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    app = create_app(create_harness(cfg))
    import uvicorn
    print(f"[*] 방어 하네스 서버 {args.host}:{args.port}  defender_model={cfg.dgx.defender_model}")
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


__all__ = ["DefenseHarness", "handle_message", "create_harness", "create_app", "main"]


if __name__ == "__main__":
    import sys
    sys.exit(main())
