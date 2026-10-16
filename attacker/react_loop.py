"""ReAct 루프 — 관측→추론→행동→관측 (공격 모드).

탈옥 LLM이 다음 행동을 JSON으로 내면 execute_action(단일 통로)으로 실행하고, 결과를
히스토리에 쌓아 다음 추론에 넣는다. 종료 3조건: 플래그 획득 / 시간 T 소진 / 막다른 길(give_up).
LLM·실행은 주입(execute_action이 실행 손발) → fake로 전 루프 테스트.
"""
from __future__ import annotations

import time
from typing import Callable, Optional, Protocol

from common.llm_client import LLMTimeout
from common.messages import AttackEndReason, AttackTurnResult, FlagObtained

from .actions import AttackAction, ParseError, parse_action
from .execute_action import ActionExecutor
from .history import AttackHistory

_TIME_FLOOR = 2.0        # 남은 예산이 이보다 적으면 새 LLM 호출 안 시작(정상 타임아웃)
_MAX_PARSE_FAILS = 3     # 연속 파싱 실패가 이 횟수면 막다른 길로 종료(모델이 깨진 JSON만 뱉는 상황 방지)


def _default_log(msg: str) -> None:
    """스텝별 타이밍 기본 출력 — VM A 공격 하네스 stdout(=journalctl)으로 흘러감."""
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def _action_hint(action: AttackAction) -> str:
    """로그용 짧은 행동 요약 — tool + 인자(길면 자름). 어떤 명령이 느린지 식별용."""
    joined = " ".join(action.args)
    if len(joined) > 48:
        joined = joined[:48] + "…"
    return f"{action.tool} {joined}".rstrip()


class _LLM(Protocol):
    def chat_text_meta(self, system: str, user: str, **kw) -> tuple[Optional[str], Optional[str]]:
        """(응답텍스트, finish_reason) 반환. finish_reason=='length' 면 잘림(토큰 상한)."""
        ...


def build_user_prompt(*, goal: str, flag_format: str, history: AttackHistory,
                      foothold: Optional[dict] = None, first: bool = False) -> str:
    parts = [f"[목표] {goal}", f"[플래그 형식] {flag_format}"]
    if first and foothold:
        parts.append(f"[발판(이번 라운드 시작점)] {foothold}")
    parts.append("[지금까지의 관측]\n" + history.render())
    parts.append("위를 보고 다음 행동 하나를 지정된 JSON 형식으로만 응답하라. "
                 "더 시도할 것이 없으면 tool 을 give_up 으로.")
    # Qwen3 계열 '사고(thinking) 모드' OFF 소프트 스위치. 켜져 있으면 모델이 <think> 안에서
    # 토큰 상한까지 추론만 하다 본문(content)을 빈 채로 잘려(finish=length, len=0) 스텝을 통째로
    # 날린다 — 밤샘 런 파싱실패의 실제 원인. 우리 JSON 의 thought 필드가 추론 채널을 대신하므로
    # 별도 <think> 는 불필요. (사고 모드 아닌 모델에선 그냥 무시되는 평범한 토큰 → 무해.)
    parts.append("/no_think")
    return "\n\n".join(parts)


class ReActLoop:
    def __init__(self, llm: _LLM, executor: ActionExecutor, history: AttackHistory, *,
                 system_prompt: str, goal: str, flag_format: str = "FLAG{...}",
                 time_limit_sec: float = 300.0, max_steps: int = 40,
                 parse_retries: int = 2, max_tokens: Optional[int] = None,
                 log: Optional[Callable[[str], None]] = None) -> None:
        self.llm = llm
        self.executor = executor
        self.history = history
        self.system_prompt = system_prompt
        self.goal = goal
        self.flag_format = flag_format
        self.time_limit_sec = time_limit_sec
        self.max_steps = max_steps
        self.parse_retries = parse_retries
        self.max_tokens = max_tokens            # 생성 토큰 상한(턴마다 VC 지정, None이면 LLM client 기본값)
        self.log = log or _default_log          # 스텝별 타이밍 계측 출력(주입 가능 → 테스트에선 no-op)

    def run(self, *, foothold: Optional[dict] = None) -> AttackTurnResult:
        t0 = time.time()
        deadline = t0 + self.time_limit_sec      # 턴 예산 마감 시각(호출을 이 안으로 묶음)
        end = AttackEndReason.DEADEND            # max_steps 소진도 막다른 길로 취급
        flags: list[FlagObtained] = []
        consec_fail = 0                          # 연속 파싱 실패 횟수(가드용)

        for i in range(self.max_steps):
            if deadline - time.time() <= _TIME_FLOOR:   # 남은 예산 없음 → 정상 타임아웃
                end = AttackEndReason.TIMEOUT
                break
            user = build_user_prompt(goal=self.goal, flag_format=self.flag_format,
                                     history=self.history, foothold=foothold, first=(i == 0))
            t_llm = time.time()                  # ── LLM 호출+파싱 구간 계측 시작 ──
            try:
                action, n_calls, fail_detail = self._get_action(user, deadline=deadline)
            except LLMTimeout:                   # 호출이 남은 예산 초과 → 대본 보존하고 정상 타임아웃
                self.log(f"[공격 step {i+1}] llm={time.time()-t_llm:.1f}s → 예산 소진(타임아웃)")
                end = AttackEndReason.TIMEOUT
                break
            llm_sec = time.time() - t_llm
            if action is None:                   # 이 스텝 파싱 실패 → 턴을 죽이지 않고 스킵, 연속만 가드
                consec_fail += 1
                self.log(f"[공격 step {i+1}] llm={llm_sec:.1f}s(calls={n_calls}) "
                         f"→ 파싱 실패, 스킵({consec_fail}/{_MAX_PARSE_FAILS}) | {fail_detail}")
                if consec_fail >= _MAX_PARSE_FAILS:   # 계속 깨진 JSON만 → 막다른 길(예산 낭비 방지)
                    end = AttackEndReason.DEADEND
                    self.log(f"[공격] 연속 파싱 실패 {consec_fail}회 → 턴 종료(DEADEND)")
                    break
                continue
            consec_fail = 0                      # 유효 액션 파싱 성공 → 연속 실패 카운터 리셋
            if action.is_give_up():
                self.log(f"[공격 step {i+1}] llm={llm_sec:.1f}s(calls={n_calls}) → give_up(막다른 길)")
                end = AttackEndReason.DEADEND
                break
            t_exec = time.time()                 # ── 실제 명령 실행 구간 계측 시작 ──
            obs = self.executor.execute(action, foothold=foothold)
            exec_sec = time.time() - t_exec
            self.history.record(action, obs)
            remain = max(0.0, deadline - time.time())
            blocked = " [BLOCKED]" if obs.blocked else ""
            # 스텝당 한 줄: llm(생성+파싱, 실제 호출수) / exec(명령) / step합 / 남은예산 / 무슨 명령이었는지
            self.log(f"[공격 step {i+1}] llm={llm_sec:.1f}s(calls={n_calls}) exec={exec_sec:.1f}s "
                     f"step={llm_sec+exec_sec:.1f}s 남은={remain:.0f}s | {_action_hint(action)}{blocked}")
            if obs.flag_found:
                flags.append(FlagObtained(flag_id="4", value=obs.flag_found, step=obs.step))
                end = AttackEndReason.FLAG
                break

        return AttackTurnResult(
            end_reason=end, flags_obtained=flags,
            replay_script=self.executor.script,
            attack_summary=self.history.summarize(),
            elapsed_sec=time.time() - t0)

    def _get_action(self, user: str, *, deadline: float
                    ) -> tuple[Optional[AttackAction], int, str]:
        """LLM 호출 + 파싱. 각 호출은 '남은 예산'만큼만 대기 → 초과 시 LLMTimeout 전파
        (run이 정상 타임아웃으로 처리, 대본 보존). 파싱 실패는 재시도, 끝내 실패면 None.
        반환: (액션|None, 실제 LLM 호출 횟수, 실패진단문).

        재시도 전략을 '실패 원인'으로 나눈다:
          - 잘림(finish_reason=='length'): 토큰이 모자란 게 아니라 모델이 thought 를 장황하게
            써서 상한에 걸린 것이다. cap 을 키우면 더 길게 생성해 역효과(과거 2배 bump 이 3072→
            6144 로 560s 괴물 호출을 만들었다) → cap 은 고정하고 '설명 빼고 JSON 하나만, thought
            한 문장' 나그로 장황함 자체를 친다.
          - 형식 위반(그 외): '형식으로만 응답하라' 나그로 재프롬프트.
        실패진단문엔 finish_reason·에러·출력 길이·앞뒤 발췌를 담아(로그로) 다음 튜닝 근거를 남긴다."""
        prompt = user
        n_calls = 0
        cap = self.max_tokens                    # 호출마다 고정 — 잘렸다고 키우지 않는다(장황함만 조장).
        detail = ""
        for _ in range(self.parse_retries + 1):
            remaining = deadline - time.time()
            if remaining <= _TIME_FLOOR:
                raise LLMTimeout("남은 예산 없음(파싱 재시도 중)")
            n_calls += 1
            text, finish = self.llm.chat_text_meta(self.system_prompt, prompt,
                                                   timeout=remaining, max_tokens=cap)
            try:
                return parse_action(text or ""), n_calls, ""
            except ParseError as e:
                t = text or ""
                detail = (f"finish={finish} err={e} len={len(t)} "
                          f"head={t[:80]!r} tail={t[-80:]!r}")
                if finish == "length":           # 잘림 = 장황함 → 창 키우지 말고 '짧게' 요구
                    prompt = user + ("\n\n(직전 응답이 너무 길어 잘렸다. 설명 문장을 쓰지 말고 "
                                     "JSON 객체 하나만 출력하라. thought 는 한 문장으로.)")
                else:                            # 형식 위반 → 형식 재지시 나그
                    prompt = user + "\n\n(이전 응답이 올바른 JSON이 아니었습니다. 지정된 형식으로만 응답하라.)"
        return None, n_calls, detail


__all__ = ["build_user_prompt", "ReActLoop"]
