"""ReAct 루프 — 관측→추론→행동→관측 (공격 모드).

탈옥 LLM이 다음 행동을 JSON으로 내면 execute_action(단일 통로)으로 실행하고, 결과를
히스토리에 쌓아 다음 추론에 넣는다. 종료 3조건: 플래그 획득 / 시간 T 소진 / 막다른 길(give_up).
LLM·실행은 주입(execute_action이 실행 손발) → fake로 전 루프 테스트.
"""
from __future__ import annotations

import time
from typing import Optional, Protocol

from common.llm_client import LLMTimeout
from common.messages import AttackEndReason, AttackTurnResult, FlagObtained

from .actions import AttackAction, ParseError, parse_action
from .execute_action import ActionExecutor
from .history import AttackHistory

_TIME_FLOOR = 2.0        # 남은 예산이 이보다 적으면 새 LLM 호출 안 시작(정상 타임아웃)


class _LLM(Protocol):
    def chat_text(self, system: str, user: str, **kw) -> str:
        ...


def build_user_prompt(*, goal: str, flag_format: str, history: AttackHistory,
                      foothold: Optional[dict] = None, first: bool = False) -> str:
    parts = [f"[목표] {goal}", f"[플래그 형식] {flag_format}"]
    if first and foothold:
        parts.append(f"[발판(이번 라운드 시작점)] {foothold}")
    parts.append("[지금까지의 관측]\n" + history.render())
    parts.append("위를 보고 다음 행동 하나를 지정된 JSON 형식으로만 응답하라. "
                 "더 시도할 것이 없으면 tool 을 give_up 으로.")
    return "\n\n".join(parts)


class ReActLoop:
    def __init__(self, llm: _LLM, executor: ActionExecutor, history: AttackHistory, *,
                 system_prompt: str, goal: str, flag_format: str = "FLAG{...}",
                 time_limit_sec: float = 300.0, max_steps: int = 40,
                 parse_retries: int = 2) -> None:
        self.llm = llm
        self.executor = executor
        self.history = history
        self.system_prompt = system_prompt
        self.goal = goal
        self.flag_format = flag_format
        self.time_limit_sec = time_limit_sec
        self.max_steps = max_steps
        self.parse_retries = parse_retries

    def run(self, *, foothold: Optional[dict] = None) -> AttackTurnResult:
        t0 = time.time()
        deadline = t0 + self.time_limit_sec      # 턴 예산 마감 시각(호출을 이 안으로 묶음)
        end = AttackEndReason.DEADEND            # max_steps 소진도 막다른 길로 취급
        flags: list[FlagObtained] = []

        for i in range(self.max_steps):
            if deadline - time.time() <= _TIME_FLOOR:   # 남은 예산 없음 → 정상 타임아웃
                end = AttackEndReason.TIMEOUT
                break
            user = build_user_prompt(goal=self.goal, flag_format=self.flag_format,
                                     history=self.history, foothold=foothold, first=(i == 0))
            try:
                action = self._get_action(user, deadline=deadline)
            except LLMTimeout:                   # 호출이 남은 예산 초과 → 대본 보존하고 정상 타임아웃
                end = AttackEndReason.TIMEOUT
                break
            if action is None:                   # 파싱 끝내 실패 → 하네스 오류
                end = AttackEndReason.ERROR
                break
            if action.is_give_up():
                end = AttackEndReason.DEADEND
                break
            obs = self.executor.execute(action, foothold=foothold)
            self.history.record(action, obs)
            if obs.flag_found:
                flags.append(FlagObtained(flag_id="4", value=obs.flag_found, step=obs.step))
                end = AttackEndReason.FLAG
                break

        return AttackTurnResult(
            end_reason=end, flags_obtained=flags,
            replay_script=self.executor.script,
            attack_summary=self.history.summarize(),
            elapsed_sec=time.time() - t0)

    def _get_action(self, user: str, *, deadline: float) -> Optional[AttackAction]:
        """LLM 호출 + 파싱. 각 호출은 '남은 예산'만큼만 대기 → 초과 시 LLMTimeout 전파
        (run이 정상 타임아웃으로 처리, 대본 보존). 파싱 실패는 재프롬프트 재시도, 끝내 실패면 None."""
        prompt = user
        for _ in range(self.parse_retries + 1):
            remaining = deadline - time.time()
            if remaining <= _TIME_FLOOR:
                raise LLMTimeout("남은 예산 없음(파싱 재시도 중)")
            text = self.llm.chat_text(self.system_prompt, prompt, timeout=remaining)
            try:
                return parse_action(text)
            except ParseError:
                prompt = user + "\n\n(이전 응답이 올바른 JSON이 아니었습니다. 지정된 형식으로만 응답하라.)"
        return None


__all__ = ["build_user_prompt", "ReActLoop"]
