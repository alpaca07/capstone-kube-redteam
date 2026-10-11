"""공격 액션 스키마 + LLM 출력 파서.

LLM은 {thought, action:{tool, args, inputs, produces}} JSON을 뱉는다. 로컬 모델은
출력이 지저분하므로(코드펜스·앞뒤 잡설·트레일링 콤마·홑따옴표) 견고하게 뽑아낸다.
파싱 실패는 ParseError로 올려 ReAct 루프가 재시도하게 한다(설계: 파서·검증·재시도 필수).

inputs/produces는 common.replay_schema의 InputRef/ProducesRef로 매핑 — execute_action이
그대로 대본 기록·의존성 재실행에 쓴다. source는 키로 추론(from_step→STEP_OUTPUT,
value→STATIC, foothold→FOOTHOLD)해서 프롬프트를 간단히 유지.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from common.replay_schema import Extract, ExtractMethod, InputRef, InputSource, ProducesRef

GIVE_UP = "give_up"


class ParseError(ValueError):
    """LLM 출력에서 유효한 액션을 못 뽑음 → 재시도 트리거."""


@dataclass
class AttackAction:
    thought: str
    tool: str
    args: list[str] = field(default_factory=list)
    inputs: dict[str, InputRef] = field(default_factory=dict)
    produces: dict[str, ProducesRef] = field(default_factory=dict)
    raw: str = ""                      # 원본 LLM 출력(디버그/대본 보관)

    def is_give_up(self) -> bool:
        return self.tool.strip().lower() == GIVE_UP


# ───────────── JSON 추출 ─────────────
_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)


def extract_json_object(text: str) -> str:
    """잡설·코드펜스에 섞인 첫 번째 균형 잡힌 {...} JSON 객체를 뽑아낸다."""
    if not text or not text.strip():
        raise ParseError("빈 출력")
    # 코드펜스 안이 있으면 우선 사용
    m = _FENCE.search(text)
    candidate = m.group(1) if m else text
    # 첫 '{' 부터 중괄호 균형으로 끝 '}' 찾기(문자열 리터럴 내 중괄호 무시)
    start = candidate.find("{")
    if start == -1:
        raise ParseError("JSON 객체 없음({ 못 찾음)")
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(candidate)):
        c = candidate[i]
        if in_str:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                in_str = False
            continue
        if c == '"':
            in_str = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return candidate[start:i + 1]
    raise ParseError("JSON 객체가 닫히지 않음(} 불균형)")


_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _loads_lenient(blob: str) -> dict:
    """json.loads, 실패하면 트레일링 콤마 제거 후 1회 재시도."""
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        repaired = _TRAILING_COMMA.sub(r"\1", blob)
        try:
            return json.loads(repaired)
        except json.JSONDecodeError as e:
            raise ParseError(f"JSON 디코드 실패: {e}") from e


# ───────────── inputs/produces 매핑 ─────────────
def _parse_extract(d: object) -> Extract:
    if not isinstance(d, dict):
        raise ParseError(f"extract 형식 오류: {d!r}")
    method = str(d.get("method", "jsonpath")).lower()
    try:
        m = ExtractMethod(method)
    except ValueError:
        raise ParseError(f"알 수 없는 extract.method: {method}")
    return Extract(method=m, path=d.get("path"))


def _parse_input(name: str, d: object) -> InputRef:
    if not isinstance(d, dict):
        raise ParseError(f"inputs[{name}] 형식 오류: {d!r}")
    # source 키로 추론(명시돼 있으면 존중)
    src = d.get("source")
    if src is None:
        if "from_step" in d:
            src = InputSource.STEP_OUTPUT
        elif "value" in d:
            src = InputSource.STATIC
        elif "foothold" in d:
            src = InputSource.FOOTHOLD
        else:
            raise ParseError(f"inputs[{name}] source 추론 불가(from_step/value/foothold 없음)")
    else:
        try:
            src = InputSource(str(src).lower())
        except ValueError:
            raise ParseError(f"inputs[{name}] 알 수 없는 source: {src}")
    extract = _parse_extract(d["extract"]) if "extract" in d else None
    return InputRef(source=src, from_step=d.get("from_step"),
                    extract=extract, value=d.get("value"))


def _parse_produces(name: str, d: object) -> ProducesRef:
    if not isinstance(d, dict) or "extract" not in d:
        raise ParseError(f"produces[{name}] 엔 extract 필요: {d!r}")
    return ProducesRef(extract=_parse_extract(d["extract"]))


# ───────────── 최상위 파서 ─────────────
def parse_action(text: str) -> AttackAction:
    """LLM 출력 텍스트 → AttackAction. 실패 시 ParseError(재시도용)."""
    blob = extract_json_object(text)
    obj = _loads_lenient(blob)
    if not isinstance(obj, dict):
        raise ParseError("최상위가 객체가 아님")

    action = obj.get("action")
    if not isinstance(action, dict):
        raise ParseError("action 객체 없음")
    tool = action.get("tool")
    if not isinstance(tool, str) or not tool.strip():
        raise ParseError("action.tool 없음/빈 값")

    thought = obj.get("thought", "")
    thought = thought if isinstance(thought, str) else str(thought)

    # give_up이면 args/inputs/produces 불필요
    if tool.strip().lower() == GIVE_UP:
        return AttackAction(thought=thought, tool=GIVE_UP, raw=text)

    raw_args = action.get("args", [])
    if raw_args is None:
        raw_args = []
    if not isinstance(raw_args, list):
        raise ParseError(f"action.args는 리스트여야 함: {raw_args!r}")
    args = [str(a) for a in raw_args]

    inputs: dict[str, InputRef] = {}
    for k, v in (action.get("inputs") or {}).items():
        inputs[str(k)] = _parse_input(str(k), v)
    produces: dict[str, ProducesRef] = {}
    for k, v in (action.get("produces") or {}).items():
        produces[str(k)] = _parse_produces(str(k), v)

    return AttackAction(thought=thought, tool=tool.strip(), args=args,
                        inputs=inputs, produces=produces, raw=text)


__all__ = ["GIVE_UP", "ParseError", "AttackAction", "extract_json_object", "parse_action"]
