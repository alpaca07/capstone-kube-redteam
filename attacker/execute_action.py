"""★ execute_action — 모든 실행의 단일 통로 (공격 하네스의 심장).

LLM이 고른 행동은 전부 이 함수 하나를 거친다 → 실행 + 리플레이 대본 기록 + determinism
판정 + 플래그 탐지가 한 몸. LLM은 이 함수만 호출하므로 기록 누락이 원천 불가 →
VM C가 나중에 재현·검증할 근거(ReplayScript)가 자동으로 쌓인다.

흐름: 입력 치환(선행 produces 값 주입) → 범위검사(킬스위치 예방, 실패 시 실행 안 함) →
실행(CommandRunner 주입) → produces 추출·저장 → 플래그 탐지 → determinism 판정 →
Step 기록. 실행 I/O만 주입 → fake로 테스트.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable

from common.replay_schema import (
    Command, Extract, ExtractMethod, FlagCheck, InputSource, ReplayScript, Step,
    StepResultRec, classify_determinism, hash_normalized,
)

from .actions import AttackAction
from .scope import ScopePolicy, check_scope


@dataclass
class CommandResult:
    exit_code: int
    stdout: str = ""
    stderr: str = ""


@runtime_checkable
class CommandRunner(Protocol):
    """도구 실행 이음새. 실 구현=subprocess, 테스트=fake."""
    def run(self, tool: str, args: list, *, stdin: Optional[str] = None,
            timeout: Optional[float] = None) -> CommandResult:
        ...


@dataclass
class Observation:
    """행동 후 ReAct 루프(LLM)가 보는 결과."""
    step: int
    tool: str
    exit_code: int
    success: bool
    stdout: str = ""
    stderr: str = ""
    blocked: bool = False
    block_reason: str = ""
    flag_found: Optional[str] = None


# ───────────── produces/inputs 값 추출 ─────────────
def _json_path_get(data, path: str):
    """미니 jsonpath: $.a.b[0].c 형태만. 실패 시 예외."""
    cur = data
    for tok in _tokenize_path(path):
        cur = cur[tok]
    return cur


def _tokenize_path(path: str) -> list:
    p = path.strip()
    if p.startswith("$"):
        p = p[1:]
    if p.startswith("."):
        p = p[1:]
    toks: list = []
    for part in p.split("."):
        if not part:
            continue
        # a[0][1] 같은 인덱스 처리
        m = re.match(r"^([^\[\]]*)((?:\[\d+\])*)$", part)
        name, idxs = (m.group(1), m.group(2)) if m else (part, "")
        if name:
            toks.append(name)
        for i in re.findall(r"\[(\d+)\]", idxs):
            toks.append(int(i))
    return toks


def extract_value(stdout: str, extract: Optional[Extract]) -> Optional[str]:
    """extract 방법대로 stdout에서 값 하나. 실패 시 None."""
    if extract is None or extract.method == ExtractMethod.FULL:
        return stdout.strip() or None
    if extract.method == ExtractMethod.REGEX:
        if not extract.path:
            return None
        m = re.search(extract.path, stdout)
        if not m:
            return None
        return m.group(1) if m.groups() else m.group(0)
    if extract.method == ExtractMethod.JSONPATH:
        if not extract.path:
            return None
        try:
            data = json.loads(stdout)
            return str(_json_path_get(data, extract.path))
        except (json.JSONDecodeError, KeyError, IndexError, TypeError, ValueError):
            return None
    return None


# ───────────── 단일 통로 ─────────────
_FLAG_RE = re.compile(r"FLAG\{[^}]*\}")
_EXCERPT = 600          # 대본 발췌 길이
_OBS_STDOUT = 2000      # LLM에 돌려줄 stdout 길이(컨텍스트 절약)


class ActionExecutor:
    """한 라운드의 모든 행동을 받아 실행·기록. 라운드당 하나 생성."""

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
        self._values: dict[str, str] = {}      # produces 이름 → 값(후속 input 주입용)
        self._step = 0
        self.flags_found: list[str] = []

    def _resolve_args(self, action: AttackAction, foothold: Optional[dict]) -> list:
        """inputs를 값으로 풀어 args의 {name} 플레이스홀더 치환."""
        subs: dict[str, str] = {}
        for name, ref in action.inputs.items():
            if ref.source == InputSource.STATIC:
                subs[name] = ref.value or ""
            elif ref.source == InputSource.FOOTHOLD:
                subs[name] = str((foothold or {}).get(name, ref.value or ""))
            else:  # STEP_OUTPUT — 선행 produces가 저장한 값
                subs[name] = self._values.get(name, "")
        out = []
        for a in action.args:
            for name, val in subs.items():
                a = a.replace("{" + name + "}", val)
            out.append(a)
        return out

    def execute(self, action: AttackAction, *, foothold: Optional[dict] = None) -> Observation:
        self._step += 1
        n = self._step
        args = self._resolve_args(action, foothold)
        command = Command(tool=action.tool, args=args)
        cmd_str = action.tool + " " + " ".join(args)

        # 범위검사(킬스위치 예방) — 실패면 실행 안 하고 차단 기록
        sc = check_scope(cmd_str, self.scope)
        if not sc.allowed:
            self.script.steps.append(Step(
                step=n, command=command, inputs=action.inputs, produces=action.produces,
                result=StepResultRec(exit_code=-1, success=False,
                                     stdout_excerpt=f"[BLOCKED] {sc.reason}")))
            return Observation(step=n, tool=action.tool, exit_code=-1, success=False,
                               blocked=True, block_reason=sc.reason, stderr=sc.reason)

        # 실행
        res = self.runner.run(action.tool, args, timeout=self.step_timeout)

        # produces 추출·저장(후속 스텝 의존)
        for name, pref in action.produces.items():
            val = extract_value(res.stdout, pref.extract)
            if val is not None:
                self._values[name] = val

        # 플래그 탐지
        flag_found = None
        m = _FLAG_RE.search(res.stdout)
        if m:
            flag_found = m.group(0)
            self.flags_found.append(flag_found)

        success = res.exit_code == 0
        rec = StepResultRec(
            exit_code=res.exit_code, success=success,
            stdout_hash=hash_normalized(res.stdout),
            stdout_excerpt=res.stdout[:_EXCERPT],
            stdout_full=(res.stdout if flag_found else None))
        flag_check = FlagCheck(flag_id=self.flag_value_id, obtained=True) if flag_found else None
        det = classify_determinism(command, action.inputs)
        self.script.steps.append(Step(
            step=n, command=command, inputs=action.inputs, produces=action.produces,
            result=rec, flag_check=flag_check, determinism=det))

        return Observation(step=n, tool=action.tool, exit_code=res.exit_code, success=success,
                           stdout=res.stdout[:_OBS_STDOUT], stderr=res.stderr[:_EXCERPT],
                           flag_found=flag_found)


__all__ = ["CommandResult", "CommandRunner", "Observation",
           "extract_value", "ActionExecutor"]
