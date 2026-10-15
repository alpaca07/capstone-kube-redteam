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

from pathlib import Path
from typing import Optional

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


class AttackHarness:
    """공격 턴(새 수 생성) + 리플레이 턴(결정론 재생) 로직."""

    def __init__(self, *, llm, runner: CommandRunner, scope_policy: ScopePolicy,
                 system_prompt: str, flag_value_id: str = "4", session_id: str = "vmA",
                 max_steps: int = 40, step_timeout: float = 60.0) -> None:
        self.llm = llm
        self.runner = runner
        self.scope = scope_policy
        self.system_prompt = system_prompt
        self.flag_value_id = flag_value_id
        self.session_id = session_id
        self.max_steps = max_steps
        self.step_timeout = step_timeout
        self._episode: Optional[int] = None
        self._prior_summary = ""             # 라운드 간 기억(에피소드 내에서만 누적)
        self._round_digests: list[str] = []  # 라운드별 요약 누적(최근 N라운드)

    # ── attack_turn_start → attack_turn_result (공격 모드) ──
    def attack_turn(self, start: AttackTurnStart, *, episode: int, round: int) -> AttackTurnResult:
        if episode != self._episode:         # 새 에피소드 → 라운드 간 기억 리셋
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
    from .subprocess_runner import SubprocessRunner
    if llm is None:
        req_timeout = cfg.dgx.request_timeout_sec or float(cfg.experiment.time_limit_sec)
        llm = OllamaClient(cfg.dgx.attacker_base_url, cfg.dgx.attacker_model,
                           temperature=cfg.dgx.temperature,
                           timeout=req_timeout,            # 콜드스타트/느린 모델이 120초 넘겨도 안 끊김
                           max_tokens=cfg.dgx.max_tokens)
    runner = runner or SubprocessRunner(default_timeout=min(cfg.experiment.time_limit_sec, 120))
    return AttackHarness(
        llm=llm, runner=runner, scope_policy=default_policy(),
        system_prompt=prompt or _load_prompt(),
        flag_value_id="4", session_id=cfg.vmware.target_vm_name or "vmA",
        step_timeout=float(min(cfg.experiment.time_limit_sec, 120)))


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
    print(f"[*] 공격 하네스 서버 {args.host}:{args.port}  attacker_model={cfg.dgx.attacker_model}")
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


__all__ = ["AttackHarness", "handle_message", "create_harness", "create_app", "main"]


if __name__ == "__main__":
    import sys
    sys.exit(main())
