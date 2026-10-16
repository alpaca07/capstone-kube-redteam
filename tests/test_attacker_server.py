"""AttackHarness 라운드 간 기억(carry-forward) 리셋 회귀.

상주(systemd) 하네스는 매 런이 episode=1·round=1 로 들어온다. 리셋을 'episode 변화'로만
하면 이전 런의 요약("이미 FLAG 획득")이 새어 공격자가 즉시 give_up 한다. 리셋 조건을
'새 에피소드 OR 에피소드 첫 라운드(R1)'로 바꿨는지, 그러면서도 같은 에피소드의 R2+
이월은 유지되는지 검증한다(프롬프트에 이전 요약 센티넬이 실리는지로 관측).

    python3 tests/test_attacker_server.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.messages import AttackTurnStart          # noqa: E402
from attacker.execute_action import CommandResult    # noqa: E402
from attacker.scope import default_policy            # noqa: E402
from attacker.server import AttackHarness            # noqa: E402

_ACTION = '{"thought":"정찰","action":{"tool":"kubectl","args":["get","pods"]}}'
_STALE = "STALE_MEM_이미_FLAG_획득"      # 이전 런에서 남은 '기억' 센티넬


class _Runner:
    """CommandRunner — 스코프 통과 시 호출됨. 항상 benign stdout."""

    def run(self, tool, args, *, stdin=None, timeout=None):
        return CommandResult(exit_code=0, stdout="ok")


class _LLM:
    """매 호출 benign 액션 반환 + 받은 user 프롬프트 기록(센티넬 유출 관측용)."""

    def __init__(self):
        self.users_seen: list[str] = []

    def chat_text_meta(self, system, user, *, timeout=None, max_tokens=None, **kw):
        self.users_seen.append(user)
        return _ACTION, "stop"

    def chat_text(self, system, user, **kw):
        return self.chat_text_meta(system, user, **kw)[0]


def _harness(llm):
    return AttackHarness(llm=llm, runner=_Runner(), scope_policy=default_policy(),
                         system_prompt="s", max_steps=1)


def _seed_prior_run(h):
    """이전 런이 남긴 상주 상태 재현: episode=1 로 끝났고 기억에 센티넬이 쌓여 있음."""
    h._episode = 1
    h._prior_summary = _STALE


def test_round1_resets_stale_carryforward():
    # 핵심 버그 수정: 새 런도 episode=1·R1 → 리셋되어 첫 프롬프트에 이전 런 기억이 없어야.
    llm = _LLM()
    h = _harness(llm)
    _seed_prior_run(h)
    h.attack_turn(AttackTurnStart(time_limit_sec=300), episode=1, round=1)
    assert llm.users_seen, "LLM 호출이 없음"
    assert _STALE not in llm.users_seen[0], \
        f"R1 인데 이전 런 기억이 새어나옴(리셋 실패): {llm.users_seen[0][:200]}"


def test_round2_keeps_carryforward():
    # 기능 회귀 방지: 같은 에피소드의 R2 는 이월 유지 → 첫 프롬프트에 센티넬이 있어야.
    llm = _LLM()
    h = _harness(llm)
    _seed_prior_run(h)
    h.attack_turn(AttackTurnStart(time_limit_sec=300), episode=1, round=2)
    assert llm.users_seen and _STALE in llm.users_seen[0], \
        "R2 인데 라운드 간 이월이 사라짐(기능 손상)"


def test_new_episode_resets():
    # 기존 동작 유지: 에피소드 번호가 바뀌면 리셋.
    llm = _LLM()
    h = _harness(llm)
    _seed_prior_run(h)
    h.attack_turn(AttackTurnStart(time_limit_sec=300), episode=2, round=5)
    assert llm.users_seen and _STALE not in llm.users_seen[0], \
        "새 에피소드인데 리셋 안 됨"


# ───────────── 자체 러너 ─────────────
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
    print("── AttackHarness carry-forward 리셋 회귀 ──")
    sys.exit(_run())
