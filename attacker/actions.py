"""공격 액션 스키마 + LLM 출력 파서.

LLM은 {thought, action:{tool, args, inputs, produces}} JSON을 뱉는다. 지저분한 출력의
JSON 추출은 common.llm_json(공격·방어 공유)에 맡기고, 여기선 액션 구조로 매핑한다.
파싱 실패는 ParseError(=LLMJsonError)로 올려 ReAct 루프가 재시도하게 한다.

inputs/produces는 common.replay_schema의 InputRef/ProducesRef로 매핑 — execute_action이
그대로 대본 기록·의존성 재실행에 쓴다. source는 키로 추론(from_step→STEP_OUTPUT,
value→STATIC, foothold→FOOTHOLD)해서 프롬프트를 간단히 유지.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from common.llm_json import LLMJsonError, extract_json_object, loads_lenient
from common.replay_schema import Extract, ExtractMethod, InputRef, InputSource, ProducesRef

GIVE_UP = "give_up"

# 파싱 실패 타입 — 공유 에러를 공격 하네스 이름으로 노출(재시도 트리거).
ParseError = LLMJsonError


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
    obj = loads_lenient(extract_json_object(text))
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
