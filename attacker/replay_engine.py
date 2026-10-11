"""리플레이 엔진 — LLM을 끈 결정론적 재생 (공격 하네스 2모드 중 '리플레이 모드').

VM C(검증 엔진)가 replay_request(phase=pre|post)를 보내면, 저장된 ReplayScript를
'지능 없이' 그대로 재실행한다. 공격 모드와 같은 CommandRunner·resolve_args를 쓰되
머리(LLM)가 없다 — 리플레이에 LLM을 쓰면 재현이 비결정적으로 깨지므로.

핵심 메커니즘(3중 그물 ① '검증 불능' 예방):
- 녹음된 만료값(SA 토큰 등)을 그대로 쓰지 않는다. 대본의 inputs(STEP_OUTPUT)를 따라
  선행 스텝을 재실행해 '이번 재생에서 새로 얻은 값'을 주입한다 → 토큰이 만료돼도 재현 가능.
- 그래서 execute_action은 args를 '템플릿'(원본 {name})으로 기록한다. 여기서 fresh 값으로 재치환.

판정 기여(최종 판정은 VM C verifier):
- 플래그 스텝 success = '재생에서 FLAG{}를 실제로 다시 봤나'(녹음된 success 아님).
  패치 후(post) 경로가 막혀 플래그가 안 나오면 success=False → VM C가 BLOCKED 판정.
- matched_baseline = 정규화 stdout 해시가 기록본과 같나 → success의 보조 지표(해시 노이즈 대응).
- 킬스위치 범위검사는 재생에도 적용(scope_policy 주입 시) — 대본이 범위를 벗어나면 실행 안 함.
"""
from __future__ import annotations

from typing import Optional

from common.messages import ReplayPhase, ReplayRequest, ReplayResult, StepReplayRec
from common.replay_schema import ReplayScript, hash_normalized

from .execute_action import (
    CommandRunner, extract_value, find_flag, resolve_args,
)
from .scope import ScopePolicy, check_scope


class ReplayEngine:
    """저장된 대본을 재실행해 ReplayResult를 만든다. 요청(pre/post)당 하나 생성 권장."""

    def __init__(self, runner: CommandRunner, *, scope_policy: Optional[ScopePolicy] = None,
                 step_timeout: Optional[float] = None) -> None:
        self.runner = runner
        self.scope = scope_policy
        self.step_timeout = step_timeout

    # ───────────── 메시지 진입점 ─────────────
    def run(self, request: ReplayRequest, *, foothold: Optional[dict] = None) -> ReplayResult:
        """replay_request 처리 → replay_result (서버가 봉투로 감싸 VM C에 응답)."""
        return self.replay(request.replay_script, request.phase,
                           foothold=foothold, target=request.target)

    # ───────────── 재생 본체 ─────────────
    def replay(self, script: ReplayScript, phase: ReplayPhase, *,
               foothold: Optional[dict] = None, target: Optional[str] = None) -> ReplayResult:
        values: dict[str, str] = {}        # produces 이름 → '이번 재생'에서 새로 얻은 값(fresh)
        recs: list[StepReplayRec] = []
        flags_reached: list[str] = []
        expected = [s.flag_check.flag_id for s in script.steps if s.flag_check is not None]

        for step in script.steps:
            resolved = resolve_args(step.command.args, step.inputs, values,
                                    foothold, target=target)

            # 범위검사(킬스위치) — 재생에도 적용. 벗어나면 실행 안 하고 차단 기록
            if self.scope is not None:
                sc = check_scope(step.command.tool + " " + " ".join(resolved), self.scope)
                if not sc.allowed:
                    recs.append(StepReplayRec(
                        step=step.step, exit_code=-1, success=False,
                        matched_baseline=None, note=f"BLOCKED:{sc.reason}"))
                    continue

            res = self.runner.run(step.command.tool, resolved, timeout=self.step_timeout)

            # produces 재추출 — 반드시 '이번 재생'의 fresh 값이어야(다음 스텝 의존성 주입)
            for name, pref in step.produces.items():
                v = extract_value(res.stdout, pref.extract)
                if v is not None:
                    values[name] = v

            replay_hash = hash_normalized(res.stdout)
            baseline = step.result.stdout_hash
            matched = (replay_hash == baseline) if baseline else None

            if step.flag_check is not None:
                flag = find_flag(res.stdout)
                success = flag is not None                  # ★ 플래그는 '다시 봤나'로 판정
                if success:
                    flags_reached.append(step.flag_check.flag_id)
                note = "flag:found" if success else "flag:absent"
            else:
                success = res.exit_code == 0
                note = ""

            recs.append(StepReplayRec(
                step=step.step, exit_code=res.exit_code, success=success,
                stdout_hash=replay_hash, matched_baseline=matched, note=note))

        if expected:
            overall = all(fid in flags_reached for fid in expected)
        else:
            overall = bool(recs) and all(r.success for r in recs)

        return ReplayResult(phase=phase, steps_result=recs,
                            overall_success=overall, flags_reached=flags_reached)


__all__ = ["ReplayEngine"]
