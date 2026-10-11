"""LLM 출력에서 JSON 뽑아내기 — 공격/방어 하네스가 공유.

로컬 모델은 JSON을 코드펜스(```json)·앞뒤 잡설·트레일링 콤마와 섞어 뱉는다.
그걸 견고하게 추출: 펜스 벗기고, 중괄호 균형으로 첫 객체만 자르고(문자열 내 중괄호 무시),
디코드 실패 시 트레일링 콤마 1회 repair. 실패는 LLMJsonError로 올려 재시도하게 한다.
"""
from __future__ import annotations

import json
import re
from typing import Any

_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


class LLMJsonError(ValueError):
    """LLM 출력에서 유효한 JSON을 못 뽑음 → 재시도 트리거."""


def extract_json_object(text: str) -> str:
    """잡설·코드펜스에 섞인 첫 번째 균형 잡힌 {...} JSON 객체 문자열을 뽑아낸다."""
    if not text or not text.strip():
        raise LLMJsonError("빈 출력")
    m = _FENCE.search(text)
    candidate = m.group(1) if m else text
    start = candidate.find("{")
    if start == -1:
        raise LLMJsonError("JSON 객체 없음({ 못 찾음)")
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
    raise LLMJsonError("JSON 객체가 닫히지 않음(} 불균형)")


def loads_lenient(blob: str) -> Any:
    """json.loads, 실패하면 트레일링 콤마 제거 후 1회 재시도."""
    try:
        return json.loads(blob)
    except json.JSONDecodeError:
        repaired = _TRAILING_COMMA.sub(r"\1", blob)
        try:
            return json.loads(repaired)
        except json.JSONDecodeError as e:
            raise LLMJsonError(f"JSON 디코드 실패: {e}") from e


def extract_and_load(text: str) -> Any:
    """편의: 추출 후 로드. 반환이 dict가 아닐 수도 있으니 상위에서 검사."""
    return loads_lenient(extract_json_object(text))


__all__ = ["LLMJsonError", "extract_json_object", "loads_lenient", "extract_and_load"]
