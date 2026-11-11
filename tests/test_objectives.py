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
    Condition, ObjectiveRegistry, ObjectiveSpec, default_objectives,
    DEFAULT_ASSET_GOAL, objectives_for, resolve_objectives, resolve_goal)


def _obs(*crowns) -> dict:
    """crown 관측축의 자백 집합 꾸미기."""
    return {"crown": {"asset": set(crowns)}}


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
            Condition("crown", "asset", "eq", CROWN_INTERNAL_SECRETS),
            Condition("crown", "asset", "eq", CROWN_CUSTOMERS_PII),
        )),
    ])
    assert not reg.is_reached("two", _obs(CROWN_INTERNAL_SECRETS))          # 하나만 → 미달성
    assert reg.is_reached("two", _obs(CROWN_INTERNAL_SECRETS, CROWN_CUSTOMERS_PII))  # 둘 다 → 달성


def test_operator_in():
    reg = ObjectiveRegistry([
        ObjectiveSpec("any", "T1213", "g", "둘 중 하나", (
            Condition("crown", "asset", "in",
                      [CROWN_INTERNAL_SECRETS, CROWN_CUSTOMERS_PII]),
        )),
    ])
    assert reg.is_reached("any", _obs(CROWN_CUSTOMERS_PII))
    assert not reg.is_reached("any", _obs("something_else"))


def test_operator_exists():
    reg = ObjectiveRegistry([
        ObjectiveSpec("any", "T1213", "g", "크라운 아무거나", (
            Condition("crown", "asset", "exists"),
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
    s = ObjectiveSpec("dup", "T1213", "g", "d", (Condition("crown", "asset", "exists"),))
    try:
        ObjectiveRegistry([s, s])
    except ValueError:
        return
    raise AssertionError("중복 objective_id 인데 에러 안 남")


# ───────────────────── 목표 2모드 해석(free | asset) ─────────────────────
def test_resolve_objectives_free_is_empty():
    """free 모드 = 빈 레지스트리 → 크라운 반출돼도 채점 off(탐색·데모)."""
    reg = resolve_objectives("free", [])
    assert reg.all_ids() == []
    assert reg.reached_goals(_obs(CROWN_INTERNAL_SECRETS)) == set()


def test_resolve_objectives_asset_all_when_empty():
    """asset 모드 + 빈 목록 = 전체 크라운(기존 동작 보존)."""
    assert set(resolve_objectives("asset", []).all_ids()) == set(default_objectives().all_ids())


def test_resolve_objectives_asset_subset():
    """asset 모드 + 명시 선택 = 그 자산만 활성(자산별 채점)."""
    reg = resolve_objectives("asset", ["crown-pii"])
    assert reg.all_ids() == ["crown-pii"]
    assert reg.is_reached("crown-pii", _obs(CROWN_CUSTOMERS_PII))
    assert reg.get("crown-secrets") is None            # 안 고른 자산은 채점 대상 아님


def test_resolve_objectives_bad_mode_raises():
    try:
        resolve_objectives("bogus", [])
    except ValueError:
        return
    raise AssertionError("알 수 없는 모드인데 에러 안 남")


def test_objectives_for_unknown_id_raises():
    """시작 가드: 정의 안 된 자산 id → 실험 시작 전에 바로 터짐."""
    try:
        objectives_for(["crown-nope"])
    except ValueError:
        return
    raise AssertionError("알 수 없는 자산 id 인데 에러 안 남")


def test_resolve_goal_free_uses_text():
    assert resolve_goal("free", "고객 PII 를 반출하라", []) == "고객 PII 를 반출하라"


def test_resolve_goal_free_empty_raises():
    """시작 가드: free 인데 목표 문구 비어 있으면 중단."""
    try:
        resolve_goal("free", "   ", [])
    except ValueError:
        return
    raise AssertionError("free 빈 문구인데 에러 안 남")


def test_resolve_goal_asset_all_is_default():
    assert resolve_goal("asset", "", []) == DEFAULT_ASSET_GOAL


def test_resolve_goal_asset_subset_is_derived():
    """명시 선택 시 goal 은 선택 자산 설명에서 생성(기본 문구와 다름)."""
    g = resolve_goal("asset", "", ["crown-pii"])
    assert g != DEFAULT_ASSET_GOAL
    assert "고객 PII" in g                             # crown-pii 설명이 녹아듦


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
