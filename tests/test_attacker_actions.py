"""공격 액션 파서 테스트 — 지저분한 LLM 출력까지 견고하게 파싱.

    python3 tests/test_attacker_actions.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.actions import GIVE_UP, ParseError, extract_json_object, parse_action  # noqa: E402
from common.replay_schema import ExtractMethod, InputSource  # noqa: E402


def test_clean_json():
    a = parse_action('{"thought":"t","action":{"tool":"kubectl","args":["get","pods"]}}')
    assert a.thought == "t" and a.tool == "kubectl" and a.args == ["get", "pods"]
    assert not a.is_give_up()


def test_code_fence_wrapped():
    txt = '```json\n{"thought":"x","action":{"tool":"nmap","args":["-sV"]}}\n```'
    a = parse_action(txt)
    assert a.tool == "nmap" and a.args == ["-sV"]


def test_prose_around_object():
    txt = 'Sure! Here is my move:\n{"thought":"go","action":{"tool":"curl","args":["http://x"]}}\nHope that helps.'
    a = parse_action(txt)
    assert a.tool == "curl"


def test_trailing_comma_repaired():
    txt = '{"thought":"t","action":{"tool":"ls","args":["-la",],},}'
    a = parse_action(txt)
    assert a.tool == "ls" and a.args == ["-la"]


def test_give_up_needs_no_args():
    a = parse_action('{"thought":"막힘","action":{"tool":"give_up"}}')
    assert a.is_give_up() and a.tool == GIVE_UP


def test_inputs_from_step_infers_step_output():
    txt = ('{"thought":"t","action":{"tool":"psql","args":["-c","SELECT 1"],'
           '"inputs":{"pw":{"from_step":1,"extract":{"method":"jsonpath","path":"$.data.password"}}}}}')
    a = parse_action(txt)
    ref = a.inputs["pw"]
    assert ref.source == InputSource.STEP_OUTPUT and ref.from_step == 1
    assert ref.extract.method == ExtractMethod.JSONPATH and ref.extract.path == "$.data.password"


def test_inputs_value_infers_static():
    a = parse_action('{"thought":"t","action":{"tool":"sh","args":["-c","echo"],'
                     '"inputs":{"ns":{"value":"database"}}}}')
    assert a.inputs["ns"].source == InputSource.STATIC and a.inputs["ns"].value == "database"


def test_produces_parsed():
    a = parse_action('{"thought":"t","action":{"tool":"curl","args":["http://x"],'
                     '"produces":{"tok":{"extract":{"method":"regex","path":"token=(\\\\w+)"}}}}}')
    assert a.produces["tok"].extract.method == ExtractMethod.REGEX


def test_braces_inside_string_dont_break_extraction():
    # thought에 FLAG{...} 같은 중괄호가 있어도 문자열 내부라 균형 추출이 안 깨져야 함
    txt = 'noise {"thought":"found FLAG{abc} maybe","action":{"tool":"give_up"}} trailing'
    obj = extract_json_object(txt)
    assert obj.endswith("}}")
    a = parse_action(txt)
    assert a.is_give_up() and "FLAG{abc}" in a.thought


def test_missing_action_raises():
    _expect_parse_error('{"thought":"t"}')


def test_missing_tool_raises():
    _expect_parse_error('{"thought":"t","action":{"args":["x"]}}')


def test_args_not_list_raises():
    _expect_parse_error('{"thought":"t","action":{"tool":"ls","args":"oops"}}')


def test_garbage_raises():
    _expect_parse_error("완전 쓰레기 출력, JSON 없음")
    _expect_parse_error("")


def _expect_parse_error(txt: str) -> None:
    try:
        parse_action(txt)
    except ParseError:
        return
    raise AssertionError(f"ParseError 기대했는데 통과: {txt!r}")


def _run() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  \033[32m✓\033[0m {t.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  \033[31m✗\033[0m {t.__name__}: {type(e).__name__}: {e}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed  (총 {len(tests)})")
    return 1 if failed else 0


if __name__ == "__main__":
    print("── 공격 액션 파서 테스트 ──")
    sys.exit(_run())
