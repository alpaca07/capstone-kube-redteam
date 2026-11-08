"""VM A 공격 하네스 — 2모드 배선(AttackHarness). HTTP(FastAPI) 바인딩은 배포 층에서.

VM C가 보내는 메시지에 응답한다:
  attack_turn_start → attack_turn_result  (공격 모드: 탈옥 LLM ReAct 루프로 새 수 생성)
  replay_request    → replay_result       (리플레이 모드: LLM 없이 대본 결정론 재생)
  status            → agent_status         (하트비트)

두 모드는 같은 하네스에서 '머리(LLM)'를 켜고/끈다. 공격 모드는 ReActLoop(execute_action으로
실행+대본기록), 리플레이 모드는 ReplayEngine(같은 CommandRunner·resolve_args, LLM만 제거).
컴포넌트(llm/runner/scope)를 주입받는다 → fake로 전 파이프라인 테스트.

상태: 라운드 간 요약(prior_summary)만 보유(에피소드 바뀌면 리셋). 대본은 VM C가 보관했다가
replay_request로 되돌려주므로 하네스는 저장하지 않는다(stateless 지향).
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Callable, Optional

from common.messages import (
    AgentRole, AgentState, AgentStatus, AttackEndReason, AttackTurnResult,
    AttackTurnStart, MsgType, ReplayRequest, ReplayResult,
    parse_envelope, wrap,
)

from .execute_action import ActionExecutor, CommandRunner
from .history import AttackHistory
from .react_loop import ReActLoop
from .replay_engine import ReplayEngine
from .scope import ScopePolicy, default_policy

# FastAPI가 `request: Request` 힌트를 모듈 전역에서 해석하려면 여기(함수 밖)에 있어야 한다.
# (from __future__ import annotations로 힌트가 문자열이라, create_app 안에서만 import하면
#  FastAPI가 "Request"를 못 풀고 쿼리 파라미터로 오해 → 422.) fastapi 미설치 테스트 땐 None.
try:
    from fastapi import Request
except ImportError:                    # pragma: no cover
    Request = None  # type: ignore

_MAX_PRIOR_ROUNDS = 4        # 라운드 간 기억으로 넘길 최근 라운드 수(프롬프트 비대 방지)


def _harness_log(msg: str) -> None:
    """병렬 경로 로그 → stdout(=journalctl). 라운드 엔진·워커·ReAct 스텝 로그가 이리로 흐른다.
    (단일 경로는 ReActLoop 기본 로거가 이미 stdout으로 찍음 → 병렬도 같은 가시성을 갖게 함.)"""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


class AttackHarness:
    """공격 턴(새 수 생성) + 리플레이 턴(결정론 재생) 로직."""

    def __init__(self, *, llm, runner: CommandRunner, scope_policy: ScopePolicy,
                 system_prompt: str, flag_value_id: str = "4", session_id: str = "vmA",
                 max_steps: int = 40, step_timeout: float = 60.0,
                 mode: str = "single", planner_llm=None, round_cfg=None,
                 graph_backend: str = "memory", neo4j_driver=None,
                 neo4j_database=None,
                 log: Optional[Callable[[str], None]] = None) -> None:
        self.llm = llm
        self.runner = runner
        self.scope = scope_policy
        self.system_prompt = system_prompt
        self.log = log or _harness_log      # 병렬 경로 가시성(주입 가능 → 테스트에서 캡처)
        self.flag_value_id = flag_value_id
        self.session_id = session_id
        self.max_steps = max_steps
        self.step_timeout = step_timeout
        self._episode: Optional[int] = None
        self._prior_summary = ""             # 라운드 간 기억(에피소드 내에서만 누적)
        self._round_digests: list[str] = []  # 라운드별 요약 누적(최근 N라운드)
        # ── 병렬 워커 모드 ──
        self.mode = mode                     # single | parallel
        self.planner_llm = planner_llm       # 정렬 모델(플래너 전용). parallel에서만 필요
        self.round_cfg = round_cfg           # RoundConfig(system_prompt 포함). parallel에서만
        self._graph = None                   # 에피소드 스코프 탐색 그래프(라운드 넘어 지속)
        self._asset_graph = None             # 에피소드 스코프 자산 그래프(짝)
        self._graph_episode: Optional[int] = None
        self._graph_backend = graph_backend  # memory | neo4j
        self._neo4j_driver = neo4j_driver    # neo4j 백엔드일 때 공유 드라이버
        self._neo4j_database = neo4j_database

    # ── attack_turn_start → attack_turn_result (공격 모드) ──
    def attack_turn(self, start: AttackTurnStart, *, episode: int, round: int) -> AttackTurnResult:
        if self.mode == "parallel" and self.planner_llm is not None:
            return self._attack_turn_parallel(start, episode=episode, round=round)
        return self._attack_turn_single(start, episode=episode, round=round)

    # ── 병렬 워커 턴(ARTEX식: 플래너+워커 N) ──
    def _new_episode_graph(self, episode: int):
        """에피소드 스코프 탐색 그래프 생성(백엔드별). neo4j는 공유 드라이버로 episode별
        Neo4jGraph를 만들고 그 episode만 reset(새 에피소드 시작=깨끗한 상태)."""
        if self._graph_backend == "neo4j":
            from .graph_neo4j import Neo4jGraph
            g = Neo4jGraph(self._neo4j_driver, episode=episode,
                           database=self._neo4j_database)
            g.reset_episode()                # 이 episode 번호의 묵은 노드 제거(KG는 보존)
            return g
        from .graph_fake import InMemoryGraph
        return InMemoryGraph(episode=episode)

    def _new_episode_asset_graph(self, episode: int):
        """에피소드 스코프 자산 그래프(탐색 그래프와 짝). 백엔드 동일."""
        if self._graph_backend == "neo4j":
            from .assets_neo4j import Neo4jAssetGraph
            ag = Neo4jAssetGraph(self._neo4j_driver, episode=episode,
                                 database=self._neo4j_database)
            ag.ensure_schema()
            ag.reset_episode()
            return ag
        from .assets_fake import InMemoryAssetGraph
        return InMemoryAssetGraph(episode=episode)

    def _attack_turn_parallel(self, start: AttackTurnStart, *, episode: int,
                              round: int) -> AttackTurnResult:
        from .round_engine import AttackRound
        # 그래프는 에피소드 스코프: 새 에피소드이거나 에피소드 첫 라운드(R1)면 새로.
        # (단일 경로의 리셋 조건과 동일 사상 — 상주 하네스의 런 간 기억 유출 방지)
        if episode != self._graph_episode or round <= 1 or self._graph is None:
            self._graph = self._new_episode_graph(episode)
            self._asset_graph = self._new_episode_asset_graph(episode)
            self._graph_episode = episode
        try:
            rnd = AttackRound(
                attacker_llm=self.llm, planner_llm=self.planner_llm,
                runner=self.runner, scope_policy=self.scope, cfg=self.round_cfg,
                log=self.log)                # 웨이브·의도·겹침·진전없음·스텝 로그를 저널로
            return rnd.run(start, episode=episode, round=round, graph=self._graph,
                           asset_graph=self._asset_graph)
        except Exception as e:                   # noqa: BLE001 — 하네스 오류는 ERROR로
            import traceback
            traceback.print_exc()
            return AttackTurnResult(end_reason=AttackEndReason.ERROR,
                                    attack_summary=f"하네스 오류(parallel): {type(e).__name__}: {e}")

    # ── 단일 ReAct 턴(기존 경로) ──
    def _attack_turn_single(self, start: AttackTurnStart, *, episode: int, round: int) -> AttackTurnResult:
        # 라운드 간 기억 리셋: 새 에피소드이거나 '에피소드 첫 라운드(R1)'면 초기화.
        # 하네스는 systemd로 상주 → 매 런이 episode=1 로 들어오므로 'episode 바뀜'만
        # 보면 이전 런의 요약("이미 FLAG 획득")이 새어 즉시 give_up 됨. R1=에피소드
        # 시작엔 이월할 과거가 없으므로 여기서 비워 매 런이 깨끗한 정찰로 출발하게 한다.
        if episode != self._episode or round <= 1:
            self._episode = episode
            self._prior_summary = ""
            self._round_digests = []
        try:
            executor = ActionExecutor(
                self.runner, scope_policy=self.scope, session_id=self.session_id,
                episode=episode, round=round, base_snapshot=None,
                flag_value_id=self.flag_value_id, step_timeout=self.step_timeout)
            history = AttackHistory(prior_summary=self._prior_summary)
            loop = ReActLoop(
                self.llm, executor, history, system_prompt=self.system_prompt,
                goal=start.goal, flag_format=start.flag_format,
                time_limit_sec=float(start.time_limit_sec), max_steps=self.max_steps,
                max_tokens=start.max_tokens)      # None이면 ReActLoop→client config 기본값으로 폴백
            foothold = ({"attack_endpoint": start.foothold.attack_endpoint}
                        if start.foothold is not None else None)
            result = loop.run(foothold=foothold)
            # 라운드 간 기억: 이번 라운드 요약을 누적(최근 N라운드만 유지 → 프롬프트 비대 방지).
            self._round_digests.append(f"[R{round}] {result.attack_summary}")
            self._round_digests = self._round_digests[-_MAX_PRIOR_ROUNDS:]
            self._prior_summary = "\n\n".join(self._round_digests)
            return result
        except Exception as e:               # noqa: BLE001 — 하네스 오류는 ERROR로 보고(루프 보호)
            import traceback
            traceback.print_exc()            # VM A 콘솔에 전체 스택트레이스(디버깅용)
            return AttackTurnResult(end_reason=AttackEndReason.ERROR,
                                    attack_summary=f"하네스 오류: {type(e).__name__}: {e}")

    # ── replay_request → replay_result (리플레이 모드) ──
    def replay(self, req: ReplayRequest, *, episode: int, round: int) -> ReplayResult:
        try:
            engine = ReplayEngine(self.runner, scope_policy=self.scope,
                                  step_timeout=self.step_timeout)
            foothold = {"attack_endpoint": req.target} if req.target else None
            return engine.run(req, foothold=foothold)
        except Exception:                    # noqa: BLE001 — 재생 실패는 '재현 안 됨'으로(VC가 상태검증行)
            return ReplayResult(phase=req.phase, overall_success=False)

    def status(self) -> AgentStatus:
        return AgentStatus(agent=AgentRole.ATTACKER, state=AgentState.IDLE)


# ───────────── 메시지 디스패치 (FastAPI 없이 테스트 가능) ─────────────
def handle_message(harness: AttackHarness, raw) -> dict:
    """수신 봉투(dict/str/bytes) → harness 디스패치 → 응답 봉투 dict."""
    env = parse_envelope(raw)
    t = env.type
    if t == MsgType.ATTACK_TURN_START:
        resp = harness.attack_turn(env.payload_as(AttackTurnStart),
                                   episode=env.episode, round=env.round)
    elif t == MsgType.REPLAY_REQUEST:
        resp = harness.replay(env.payload_as(ReplayRequest),
                              episode=env.episode, round=env.round)
    elif t == MsgType.AGENT_STATUS:
        resp = harness.status()
    else:
        raise ValueError(f"공격 하네스가 처리 못 하는 메시지: {t.value}")
    return wrap(resp, episode=env.episode, round=env.round, status="ok").model_dump(mode="json")


# ───────────── 실 배선 ─────────────
def _load_prompt() -> str:
    return (Path(__file__).resolve().parent / "prompts" / "attacker_system.txt").read_text(encoding="utf-8")


def create_harness(cfg, *, prompt: Optional[str] = None, runner=None, llm=None) -> AttackHarness:
    """config + 실 어댑터로 AttackHarness 조립(I/O 없음 — 실제 연결은 턴 때)."""
    from common.llm_client import OllamaClient
    from .subprocess_runner import KubectlExecRunner, SubprocessRunner
    if llm is None:
        req_timeout = cfg.dgx.request_timeout_sec or float(cfg.experiment.time_limit_sec)
        llm = OllamaClient(cfg.dgx.attacker_base_url, cfg.dgx.attacker_model,
                           temperature=cfg.dgx.temperature,
                           timeout=req_timeout,            # 콜드스타트/느린 모델이 120초 넘겨도 안 끊김
                           max_tokens=cfg.dgx.max_tokens)
    # 개별 exec 타임아웃: 정상 명령은 <1s. 방어로 차단된 뒤 nc/psql/wget 가 매달리는데(NetworkPolicy
    # 가 SYN 을 DROP → 커넥트 대기) 이게 크면 한 스텝이 턴 예산·오케스트레이터 read timeout(=예산+30)을
    # 넘겨 에피소드를 ABORT 시킨다(2026-10-17 다중에피소드: nc 5432 가 120s 매달려 E2·E3 중단). → 15s 캡.
    step_to = float(min(cfg.experiment.time_limit_sec, 15))
    if runner is None:
        if cfg.attack.exec_mode:
            # ★ 발판 = frontend 파드 '안'(웹 계층 침해). 모든 명령을 kubectl exec 로 투명 래핑 →
            #   공격자가 internal-wiki·postgres 등 .svc.cluster.local 내부 서비스에 도달(①③④).
            runner = KubectlExecRunner(
                kubeconfig=cfg.attack.exec_kubeconfig, namespace=cfg.attack.exec_namespace,
                pod_ref=cfg.attack.exec_pod, default_timeout=step_to)
        else:
            # 로컬 실행(개발·테스트·외부 flat). cwd 를 빈 디렉토리로 격리 — 하네스 소스의
            # FLAG{...} 플레이스홀더를 긁어 가짜 플래그를 줍는 reward-hacking 방지.
            import os
            work_dir = "/tmp/attack-workspace"
            os.makedirs(work_dir, exist_ok=True)
            runner = SubprocessRunner(default_timeout=step_to, cwd=work_dir)
    # ★ 자기 하네스 경로(소스·설정)를 스코프로 보호 — 절대경로로 접근해도 차단(가짜 플래그 원천 차단).
    repo_root = str(Path(__file__).resolve().parent.parent)
    sys_prompt = prompt or _load_prompt()
    session_id = cfg.vmware.target_vm_name or "vmA"

    # ── 병렬 워커 모드: 플래너(정렬 모델) LLM + RoundConfig 조립 ──
    mode = getattr(cfg.attack, "mode", "single")
    planner_llm = None
    round_cfg = None
    graph_backend = "memory"
    neo4j_driver = None
    neo4j_database = None
    if mode == "parallel":
        from .round_engine import RoundConfig
        req_timeout = cfg.dgx.request_timeout_sec or float(cfg.experiment.time_limit_sec)
        # 플래너=정렬 모델(방어용과 같은 서빙, defender_base_url). 추론 모델이라 토큰 넉넉히.
        planner_llm = OllamaClient(cfg.dgx.defender_base_url, cfg.dgx.defender_model,
                                   temperature=cfg.dgx.temperature, timeout=req_timeout,
                                   max_tokens=None)
        round_cfg = RoundConfig(
            system_prompt=sys_prompt, session_id=session_id, flag_value_id="4",
            step_timeout=step_to, n_workers=cfg.attack.n_workers,
            intent_budget_sec=cfg.attack.intent_budget_sec,
            intent_max_steps=cfg.attack.intent_max_steps,
            react_max_tokens=cfg.dgx.max_tokens, planner_max_tokens=3000,
            max_waves=cfg.attack.max_waves)
        # 탐색 그래프 백엔드: memory(기본) | neo4j(영속·에피소드 넘어 지속)
        graph_backend = getattr(cfg.attack, "graph_backend", "memory")
        if graph_backend == "neo4j":
            from .graph_neo4j import Neo4jGraph, connect_driver
            neo4j_driver = connect_driver(cfg.neo4j.uri, cfg.neo4j.user, cfg.neo4j.password)
            neo4j_database = cfg.neo4j.database
            Neo4jGraph(neo4j_driver, episode=0, database=neo4j_database).ensure_schema()

    return AttackHarness(
        llm=llm, runner=runner,
        scope_policy=default_policy(protected_paths=[repo_root]),
        system_prompt=sys_prompt,
        flag_value_id="4", session_id=session_id,
        step_timeout=step_to,
        mode=mode, planner_llm=planner_llm, round_cfg=round_cfg,
        graph_backend=graph_backend, neo4j_driver=neo4j_driver,
        neo4j_database=neo4j_database)


def create_app(harness: AttackHarness):
    """FastAPI 앱 — VM C가 POST하는 요청타입 경로를 harness로 디스패치. (fastapi lazy import)"""
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    app = FastAPI(title="VM A 공격 하네스")

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
    """VM A 서버 실행. `python -m attacker.server --config config.yaml`."""
    import argparse
    from common.config import load_config
    ap = argparse.ArgumentParser(description="VM A 공격 하네스 서버")
    ap.add_argument("--config", default=None, help="config.yaml 경로(기본: 탐색)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    app = create_app(create_harness(cfg))
    import uvicorn
    mode = getattr(cfg.attack, "mode", "single")
    extra = (f"  mode=parallel workers={cfg.attack.n_workers} "
             f"planner={cfg.dgx.defender_model}") if mode == "parallel" else "  mode=single"
    print(f"[*] 공격 하네스 서버 {args.host}:{args.port}  attacker_model={cfg.dgx.attacker_model}{extra}")
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


__all__ = ["AttackHarness", "handle_message", "create_harness", "create_app", "main"]


if __name__ == "__main__":
    import sys
    sys.exit(main())
