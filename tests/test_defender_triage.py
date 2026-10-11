"""방어 트리아지 파서 테스트 — 방어 LLM 진단 출력을 구조화.

    python3 tests/test_defender_triage.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from defender.triage import ParseError, Severity, parse_triage  # noqa: E402

_FULL = ('{"assessment":"admin-sa가 DB secret 조회","detected":['
         '{"type":"over_permissioned_sa","mitre":"T1078","evidence":"audit: admin-sa get secret"}],'
         '"severity":"high","patch_plan":['
         '{"action":"restrict_rbac","target":"sa/admin-sa","detail":"secret get 제거"}]}')


def test_full_parse():
    r = parse_triage(_FULL)
    assert r.assessment.startswith("admin-sa")
    assert r.has_threat() and len(r.detected) == 1
    d = r.detected[0]
    assert d.type == "over_permissioned_sa" and d.mitre == "T1078"
    assert r.severity == Severity.HIGH
    assert r.patch_plan[0].action == "restrict_rbac" and r.patch_plan[0].target == "sa/admin-sa"


def test_no_threat_empty_detected():
    r = parse_triage('{"assessment":"정상","detected":[],"severity":"low","patch_plan":[]}')
    assert not r.has_threat() and r.techniques() == []


def test_fence_and_prose():
    txt = '분석 결과입니다:\n```json\n' + _FULL + '\n```\n이상입니다.'
    r = parse_triage(txt)
    assert r.detected[0].mitre == "T1078"


def test_severity_synonyms():
    assert parse_triage('{"assessment":"a","severity":"critical"}').severity == Severity.HIGH
    assert parse_triage('{"assessment":"a","severity":"informational"}').severity == Severity.LOW
    assert parse_triage('{"assessment":"a","severity":"weird"}').severity == Severity.MEDIUM  # 알수없음→중간


def test_techniques_dedup():
    txt = ('{"assessment":"a","detected":['
           '{"type":"x","mitre":"T1078"},{"type":"y","mitre":"T1078"},{"type":"z","mitre":"T1210"}]}')
    assert parse_triage(txt).techniques() == ["T1078", "T1210"]


def test_lenient_missing_fields():
    r = parse_triage('{"assessment":"대충"}')          # severity/detected/patch_plan 없음
    assert r.severity == Severity.LOW and r.detected == [] and r.patch_plan == []


def test_malformed_detected_raises():
    _expect_error('{"assessment":"a","detected":["문자열은 안됨"]}')


def test_malformed_patch_plan_raises():
    _expect_error('{"assessment":"a","patch_plan":[123]}')


def test_garbage_raises():
    _expect_error("JSON 없는 쓰레기")
    _expect_error("")


def _expect_error(txt: str) -> None:
    try:
        parse_triage(txt)
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
    print("── 방어 트리아지 파서 테스트 ──")
    sys.exit(_run())
