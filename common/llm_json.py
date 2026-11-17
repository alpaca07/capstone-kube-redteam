"""LLM 출력에서 JSON 뽑아내기 — 공격/방어 하네스가 공유.

로컬 모델은 JSON을 코드펜스(```json)·앞뒤 잡설·트레일링 콤마와 섞어 뱉는다.
그걸 견고하게 추출: 펜스 벗기고, 중괄호 균형으로 첫 객체만 자르고(문자열 내 중괄호 무시),
디코드 실패 시 트레일링 콤마 1회 repair. 실패는 LLMJsonError로 올려 재시도하게 한다.
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

_FENCE = re.compile(r"```(?:json)?\s*(.*?)\s*```", re.DOTALL)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


class LLMJsonError(ValueError):
    """LLM 출력에서 유효한 JSON을 못 뽑음 → 재시도 트리거."""


def _repair_truncated(candidate: str, start: int) -> Optional[str]:
    """토큰 상한에 걸려 '중간에 끊긴' JSON을, 마지막으로 닫힌 컨테이너까지 되감아 닫아 복구 시도.

    예: 플래너가 의도 배열을 뱉다 토큰이 떨어져 마지막 원소가 미완성이면, 완결된 원소들까지만
    살려 유효 JSON으로 만든다(잘린 꼬리 원소는 버림). 문자열 안에서 끊긴 경우 등 완결 컨테이너가
    하나도 없으면 None(살릴 것 없음 → 상위에서 에러). 끊김이 아닌 형식 오류엔 개입 안 함
    (정상 균형 스캔이 먼저 성공하므로 이 경로는 '끝까지 불균형'일 때만 탄다)."""
    stack: list[str] = []
    in_str = esc = False
    cut = -1                      # 마지막으로 닫힌 컨테이너의 '}'/']' 인덱스(안전 절단점)
    cut_stack: Optional[list[str]] = None
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
        elif c in "{[":
            stack.append(c)
        elif c in "}]":
            if not stack:
                break             # 짝 안 맞는 닫기 → 형식 깨짐, 복구 포기
            stack.pop()
            cut = i
            cut_stack = list(stack)
    if cut < 0 or not cut_stack:
        return None               # 완결된 컨테이너가 없음 → 살릴 것 없음
    closers = "".join("}" if ch == "{" else "]" for ch in reversed(cut_stack))
    return candidate[start:cut + 1] + closers


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
    # 끝까지 균형이 안 맞음 = 토큰 상한에 걸려 잘림 → 완결된 부분까지 복구 시도(라운드 생존).
    repaired = _repair_truncated(candidate, start)
    if repaired is not None:
        return repaired
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
