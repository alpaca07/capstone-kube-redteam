"""병렬 워커용 실행 분리 — 공유 실행 레인 + 워커별 값 맥락.

추론은 병렬(워커 N), 실행은 직렬(단일 레인). 기존 ActionExecutor(N=1 경로)를 둘로 가른 것:
  - ExecutionLane: 라운드당 하나. 전역 step seq·범위검사·실제 실행·replay_script 기록·
    플래그 수집을 쥔다. 모든 워커의 행동이 여기로 모여 '한 번에 하나씩' 직렬 실행
    → 전역 step_id 순서 = 레인 도착 순서 = 결정론 재생의 선형 순서.
    실행은 락 안(직렬)이지만 LLM 추론은 워커 쪽에서 레인 호출 '전에' 끝나므로 병렬 유지.
    exec≈0(병목은 LLM decode)이라 직렬 실행의 벽시계 비용은 ~0.
  - WorkerContext: 워커당 하나. 자기 _values(produces)만 쥐고 inputs를 자기 값으로 푼다.
    워커 간 값 공유 없음(지식은 fact 그래프로만, 이번 세션 확정).

결정론 재생 함정과 대응(네임스페이스):
  재생 엔진(replay_engine)은 병합 대본을 '이름 키 단일 values 사전'으로 재생한다. 두
  워커가 같은 produce 이름(tok 등)을 쓰고 전역 순서상 끼어들면 재생 때 값이 덮여 틀어진다.
  → 기록 경계에서 STEP_OUTPUT produces/inputs 이름을 'wid:name'으로 네임스페이스해 병합
    대본의 단일 사전에서도 워커끼리 키가 안 겹치게 한다. STATIC/FOOTHOLD는 공유 사전을
    안 거치므로 건드리지 않는다(특히 FOOTHOLD는 foothold 사전 키라 네임스페이스하면 깨짐).
"""
from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Optional

from common.replay_schema import (
    Command, FlagCheck, Step, StepResultRec, ReplayScript,
    classify_determinism, hash_normalized, make_step_id,
)

from .actions import AttackAction
from .execute_action import (
    _EXCERPT, _OBS_STDOUT, CommandRunner, Observation,
    extract_value, find_flag, resolve_args,
)
from .scope import ScopePolicy, check_scope
from common.replay_schema import InputSource


# ───────────── 네임스페이스 (재생 충돌 방지의 핵심) ─────────────
def _ns(wid: str, name: str) -> str:
    return f"{wid}:{name}"


def namespace_action(action: AttackAction, wid: str):
    """STEP_OUTPUT produces/inputs 이름과 args 플레이스홀더를 wid로 네임스페이스.

    반환: (template_args, inputs, produces) — 네임스페이스 적용본.
    · produces: 전부 네임스페이스(이들은 뒤 스텝이 STEP_OUTPUT으로 참조).
    · inputs: STEP_OUTPUT만 네임스페이스, STATIC/FOOTHOLD는 그대로(공유 values 사전 미경유).
    · args: 네임스페이스된 STEP_OUTPUT 입력의 {name} 플레이스홀더만 {wid:name}으로 치환.
    wid를 빈 문자열로 주면 아무것도 안 바꾼다(N=1 호환 경로).
    """
    if not wid:
        return list(action.args), dict(action.inputs), dict(action.produces)

    produces = {_ns(wid, k): v for k, v in action.produces.items()}

    inputs = {}
    rename: dict[str, str] = {}
    for k, ref in action.inputs.items():
        if ref.source == InputSource.STEP_OUTPUT:
            nk = _ns(wid, k)
            inputs[nk] = ref
            rename[k] = nk
        else:
            inputs[k] = ref

    args = []
    for a in action.args:
        for old, new in rename.items():
            a = a.replace("{" + old + "}", "{" + new + "}")
        args.append(a)
    return args, inputs, produces


# ───────────── 공유 실행 레인 ─────────────
@dataclass
class LaneResult:
    """레인이 워커에 돌려주는 1스텝 결과. stdout은 '원본'(워커가 produces 추출용)."""
    step: int
    step_id: str
    exit_code: int
    success: bool
    stdout: str = ""
    stderr: str = ""
    blocked: bool = False
    block_reason: str = ""
    flag_found: Optional[str] = None


class ExecutionLane:
    """라운드당 하나. 모든 워커의 행동을 직렬화해 실행·기록(결정론 재생 보존)."""

    def __init__(self, runner: CommandRunner, *, scope_policy: ScopePolicy,
                 session_id: str, episode: int, round: int,
                 base_snapshot: Optional[str] = None,
                 flag_value_id: str = "4", step_timeout: Optional[float] = None) -> None:
        self.runner = runner
        self.scope = scope_policy
        self.script = ReplayScript(session_id=session_id, episode=episode, round=round,
                                   base_snapshot=base_snapshot, steps=[])
        self.flag_value_id = flag_value_id
        self.step_timeout = step_timeout
        self.flags_found: list[str] = []
        self._step = 0
        self._lock = threading.Lock()

    def run_step(self, *, tool: str, template_args: list, resolved_args: list,
                 inputs: dict, produces: dict, worker: str = "") -> LaneResult:
        """한 행동을 직렬로 실행·기록. 전역 seq·step_id 부여는 락 안에서 원자적으로.

        LLM 추론은 호출 전에 끝나 있으므로 락이 추론 병렬성을 막지 않는다.
        args 치환(inputs 해소)도 워커 쪽에서 이미 끝났고, 레인엔 template(기록용)과
        resolved(실행·범위검사용)가 함께 들어온다.
        """
        with self._lock:
            self._step += 1
            n = self._step
            sid = make_step_id(self.script.round, n)
            command = Command(tool=tool, args=list(template_args))
            cmd_str = tool + " " + " ".join(resolved_args)

            sc = check_scope(cmd_str, self.scope)
            if not sc.allowed:
                self.script.steps.append(Step(
                    step=n, step_id=sid, command=command, inputs=inputs, produces=produces,
                    result=StepResultRec(exit_code=-1, success=False,
                                         stdout_excerpt=f"[BLOCKED] {sc.reason}")))
                return LaneResult(step=n, step_id=sid, exit_code=-1, success=False,
                                  blocked=True, block_reason=sc.reason, stderr=sc.reason)

            res = self.runner.run(tool, resolved_args, timeout=self.step_timeout)

            flag_found = find_flag(res.stdout)
            if flag_found:
                self.flags_found.append(flag_found)

            success = res.exit_code == 0
            rec = StepResultRec(
                exit_code=res.exit_code, success=success,
                stdout_hash=hash_normalized(res.stdout),
                stdout_excerpt=res.stdout[:_EXCERPT],
                stdout_full=(res.stdout if flag_found else None))
            flag_check = FlagCheck(flag_id=self.flag_value_id, obtained=True) if flag_found else None
            det = classify_determinism(command, inputs)
            self.script.steps.append(Step(
                step=n, step_id=sid, command=command, inputs=inputs, produces=produces,
                result=rec, flag_check=flag_check, determinism=det))

            return LaneResult(step=n, step_id=sid, exit_code=res.exit_code, success=success,
                              stdout=res.stdout, stderr=res.stderr, flag_found=flag_found)


# ───────────── 워커별 값 맥락 ─────────────
class WorkerContext:
    """워커당 하나. 자기 produces 값만 쥐고 공유 레인으로 행동을 흘려보낸다.

    execute(action)->Observation 시그니처가 ActionExecutor와 호환이라 ReAct 루프가
    둘 중 무엇을 받아도 동작한다.
    """

    def __init__(self, lane: ExecutionLane, worker_id: str, *,
                 foothold: Optional[dict] = None, target: Optional[str] = None) -> None:
        self.lane = lane
        self.wid = worker_id
        self.foothold = foothold
        self.target = target
        self._values: dict[str, str] = {}   # 네임스페이스된 produce 이름 → 값(이 워커 전용)

    def execute(self, action: AttackAction, *, foothold: Optional[dict] = None) -> Observation:
        t_args, inputs, produces = namespace_action(action, self.wid)
        fh = foothold if foothold is not None else self.foothold
        # inputs 해소는 '워커 쪽'에서 자기 _values로(격리). 레인엔 치환 완료본을 넘긴다.
        resolved = resolve_args(t_args, inputs, self._values, fh, target=self.target)

        res = self.lane.run_step(
            tool=action.tool, template_args=t_args, resolved_args=resolved,
            inputs=inputs, produces=produces, worker=self.wid)

        if not res.blocked:
            for name, pref in produces.items():
                val = extract_value(res.stdout, pref.extract)
                if val is not None:
                    self._values[name] = val

        return Observation(
            step=res.step, step_id=res.step_id, tool=action.tool,
            exit_code=res.exit_code, success=res.success,
            stdout=res.stdout[:_OBS_STDOUT], stderr=res.stderr[:_EXCERPT],
            blocked=res.blocked, block_reason=res.block_reason,
            flag_found=res.flag_found)


__all__ = ["ExecutionLane", "WorkerContext", "LaneResult", "namespace_action"]
