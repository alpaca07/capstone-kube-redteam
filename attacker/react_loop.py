"""ReAct 루프 — 관측→추론→행동→관측 (공격 모드).

탈옥 LLM이 다음 행동을 JSON으로 내면 execute_action(단일 통로)으로 실행하고, 결과를
히스토리에 쌓아 다음 추론에 넣는다. 종료 3조건: 플래그 획득 / 시간 T 소진 / 막다른 길(give_up).
LLM·실행은 주입(execute_action이 실행 손발) → fake로 전 루프 테스트.
"""
from __future__ import annotations

import time
from typing import Optional, Protocol

from common.messages import AttackEndReason, AttackTurnResult, FlagObtained

from .actions import AttackAction, ParseError, parse_action
from .execute_action import ActionExecutor
from .history import AttackHistory


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
        end = AttackEndReason.DEADEND            # max_steps 소진도 막다른 길로 취급
        flags: list[FlagObtained] = []

        for i in range(self.max_steps):
            if time.time() - t0 >= self.time_limit_sec:
                end = AttackEndReason.TIMEOUT
                break
            user = build_user_prompt(goal=self.goal, flag_format=self.flag_format,
                                     history=self.history, foothold=foothold, first=(i == 0))
            action = self._get_action(user)
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

    def _get_action(self, user: str) -> Optional[AttackAction]:
        """LLM 호출 + 파싱. 실패 시 재프롬프트 재시도, 끝내 실패면 None."""
        prompt = user
        for _ in range(self.parse_retries + 1):
            text = self.llm.chat_text(self.system_prompt, prompt)
            try:
                return parse_action(text)
            except ParseError:
                prompt = user + "\n\n(이전 응답이 올바른 JSON이 아니었습니다. 지정된 형식으로만 응답하라.)"
        return None


__all__ = ["build_user_prompt", "ReActLoop"]
