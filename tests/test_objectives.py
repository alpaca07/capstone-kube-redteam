"""목표 조건표(objectives) 스모크 — 플래그리스 크라운 판정.

핵심: 조건표 평가기는 통로 관측집합에 조건을 대보는 멍청한 함수. 크라운 자백 집합에서
목표·goal 달성이 올바로 떨어지는가 + '그리고/또는' 묶기 규칙.
"""
from __future__ import annotations

import sys
from pathlib import Path

# 어떻게 실행하든 저장소 루트를 import 경로에 둔다.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.app_signals import CROWN_CUSTOMERS_PII, CROWN_INTERNAL_SECRETS
from orchestrator.objectives import (
    Condition, ObjectiveRegistry, ObjectiveSpec, default_objectives)


def _obs(*crowns) -> dict:
    """app_access 통로의 crown 관측집합 꾸미기."""
    return {"app_access": {"crown": set(crowns)}}


def test_internal_secrets_reached():
    reg = default_objectives()
    assert reg.is_reached("crown-secrets", _obs(CROWN_INTERNAL_SECRETS))


def test_pii_reached():
    reg = default_objectives()
    assert reg.is_reached("crown-pii", _obs(CROWN_CUSTOMERS_PII))


def test_empty_obs_none_reached():
    reg = default_objectives()
    assert reg.reached_objectives(_obs()) == set()
    assert reg.reached_goals(_obs()) == set()


def test_goal_or_one_path_enough():
    # 두 경로(secrets·pii) 중 하나만 달성돼도 goal(db_exfil) 성공('또는')
    reg = default_objectives()
    assert reg.reached_goals(_obs(CROWN_CUSTOMERS_PII)) == {"db_exfil"}
    assert reg.reached_objectives(_obs(CROWN_CUSTOMERS_PII)) == {"crown-pii"}


def test_both_paths_reached():
    reg = default_objectives()
    obs = _obs(CROWN_INTERNAL_SECRETS, CROWN_CUSTOMERS_PII)
    assert reg.reached_objectives(obs) == {"crown-secrets", "crown-pii"}
    assert reg.reached_goals(obs) == {"db_exfil"}


def test_and_all_conditions_required():
    # 조건줄 둘을 '그리고'로 묶으면 하나만 맞을 땐 미달성
    reg = ObjectiveRegistry([
        ObjectiveSpec("two", "T1213", "g", "두 조건 AND", (
            Condition("app_access", "crown", "eq", CROWN_INTERNAL_SECRETS),
            Condition("app_access", "crown", "eq", CROWN_CUSTOMERS_PII),
        )),
    ])
    assert not reg.is_reached("two", _obs(CROWN_INTERNAL_SECRETS))          # 하나만 → 미달성
    assert reg.is_reached("two", _obs(CROWN_INTERNAL_SECRETS, CROWN_CUSTOMERS_PII))  # 둘 다 → 달성


def test_operator_in():
    reg = ObjectiveRegistry([
        ObjectiveSpec("any", "T1213", "g", "둘 중 하나", (
            Condition("app_access", "crown", "in",
                      [CROWN_INTERNAL_SECRETS, CROWN_CUSTOMERS_PII]),
        )),
    ])
    assert reg.is_reached("any", _obs(CROWN_CUSTOMERS_PII))
    assert not reg.is_reached("any", _obs("something_else"))


def test_operator_exists():
    reg = ObjectiveRegistry([
        ObjectiveSpec("any", "T1213", "g", "크라운 아무거나", (
            Condition("app_access", "crown", "exists"),
        )),
    ])
    assert reg.is_reached("any", _obs(CROWN_INTERNAL_SECRETS))
    assert not reg.is_reached("any", _obs())


def test_unknown_channel_or_field_is_false():
    # 관측에 없는 통로/항목이면 보수적으로 미달성(심판은 추측 안 함)
    reg = default_objectives()
    assert not reg.is_reached("crown-secrets", {"falco": {"rule": {"x"}}})
    assert not reg.is_reached("crown-secrets", {})


def test_empty_conditions_rejected():
    try:
        ObjectiveSpec("bad", "T1213", "g", "빈 조건", ())
    except ValueError:
        return
    raise AssertionError("빈 conditions 인데 에러 안 남")


def test_duplicate_id_rejected():
    s = ObjectiveSpec("dup", "T1213", "g", "d", (Condition("app_access", "crown", "exists"),))
    try:
        ObjectiveRegistry([s, s])
    except ValueError:
        return
    raise AssertionError("중복 objective_id 인데 에러 안 남")


# ───────────────────── 자체 러너 ─────────────────────
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
            print(f"  \033[31m✗\033[0m {t.__name__}: {type(e).__name__}: {e}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed  (총 {len(tests)})")
    return 1 if failed else 0


if __name__ == "__main__":
    print("── objectives 조건표 스모크 ──")
    sys.exit(_run())
