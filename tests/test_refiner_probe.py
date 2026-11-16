"""시험실행 어댑터(HarnessProbe) 테스트 — 되돌림→공격→채점 수직 슬라이스(fake 이음새).

자체 러너: python3 tests/test_refiner_probe.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.messages import AttackEndReason, AttackTurnResult, Foothold
from refiner.models import Component, Harness, HarnessEdit
from refiner.probe import HarnessProbe


# ───────────── 로컬 fake 이음새 ─────────────
class FakeSnapshot:
    def __init__(self):
        self.reverts: list[str] = []
    def save(self, name): pass
    def revert_to(self, name): self.reverts.append(name)
    def delete(self, name): pass
    def list(self): return []


class FakeAttacker:
    """공격 턴 요청(start)을 기록하고 미리 심은 결과를 돌려준다."""
    def __init__(self, result: AttackTurnResult):
        self._result = result
        self.starts: list = []          # 받은 AttackTurnStart
        self.rounds: list = []          # (episode, round)
    def attack_turn(self, start, *, episode, round):
        self.starts.append(start)
        self.rounds.append((episode, round))
        return self._result
    def replay(self, req, *, episode, round): ...
    def status(self): ...


def _ok_result(summary="정찰함") -> AttackTurnResult:
    return AttackTurnResult(end_reason=AttackEndReason.DEADEND, attack_summary=summary)


def _harness(overlay_text: str | None = None) -> Harness:
    h = Harness(base_prompt="BASE_PROMPT")
    if overlay_text:
        h = h.with_overlay(HarnessEdit(id="e1", component=Component.SYSTEM_PROMPT,
                                       kind="domain", rationale="r", overlay_text=overlay_text))
    return h


# ───────────── 되돌림→공격→채점 ─────────────
def test_probe_reverts_clean_attacks_scores():
    snap = FakeSnapshot()
    atk = FakeAttacker(_ok_result())
    probe = HarnessProbe(snapshot=snap, attacker=atk,
                         score_turn=lambda r, t0, t1: (0.42, {"end": r.end_reason.value}),
                         clean_snapshot="clean-baseline",
                         foothold=Foothold(attack_endpoint="10.0.0.5"))

    s = probe.probe(_harness(), basis="clean")

    assert snap.reverts == ["clean-baseline"]        # 1) 고정 스냅샷 되돌림
    assert atk.rounds == [(9000, 1)]                 # round=1 → 공격자 기억 리셋(독립 시험)
    assert s.score == 0.42 and s.basis == "clean"
    assert s.edit_id is None
    assert s.detail["end"] == "deadend"


def test_probe_injects_candidate_prompt():
    """후보 하네스의 오버레이가 system_prompt_override 로 공격 턴에 실린다."""
    atk = FakeAttacker(_ok_result())
    probe = HarnessProbe(snapshot=FakeSnapshot(), attacker=atk,
                         score_turn=lambda r, t0, t1: (1.0, {}))

    probe.probe(_harness(overlay_text="추가지침 XYZ"), basis="clean")

    sent = atk.starts[0].system_prompt_override
    assert "BASE_PROMPT" in sent and "추가지침 XYZ" in sent   # 기반+오버레이 합본


def test_probe_patched_basis_uses_patched_snapshot():
    snap = FakeSnapshot()
    probe = HarnessProbe(snapshot=snap, attacker=FakeAttacker(_ok_result()),
                         score_turn=lambda r, t0, t1: (0.1, {}),
                         clean_snapshot="clean-baseline",
                         patched_snapshot="patched-r3")

    probe.probe(_harness(), basis="patched")
    assert snap.reverts == ["patched-r3"]


def test_probe_patched_callable_snapshot():
    """patched 스냅샷을 호출가능(최신 패치 스냅샷 getter)으로 줄 수 있다."""
    snap = FakeSnapshot()
    probe = HarnessProbe(snapshot=snap, attacker=FakeAttacker(_ok_result()),
                         score_turn=lambda r, t0, t1: (0.1, {}),
                         patched_snapshot=lambda: "patched-latest")
    probe.probe(_harness(), basis="patched")
    assert snap.reverts == ["patched-latest"]


def test_probe_patched_without_snapshot_falls_back_to_clean():
    snap = FakeSnapshot()
    probe = HarnessProbe(snapshot=snap, attacker=FakeAttacker(_ok_result()),
                         score_turn=lambda r, t0, t1: (0.1, {}),
                         clean_snapshot="clean-baseline", patched_snapshot=None)
    probe.probe(_harness(), basis="patched")
    assert snap.reverts == ["clean-baseline"]        # 폴백


def test_probe_rejects_unknown_basis():
    probe = HarnessProbe(snapshot=FakeSnapshot(), attacker=FakeAttacker(_ok_result()),
                         score_turn=lambda r, t0, t1: (0.1, {}))
    try:
        probe.probe(_harness(), basis="weird")
        assert False, "알 수 없는 basis 는 ValueError 여야"
    except ValueError:
        pass


def test_probe_passes_time_limit_and_max_tokens():
    atk = FakeAttacker(_ok_result())
    probe = HarnessProbe(snapshot=FakeSnapshot(), attacker=atk,
                         score_turn=lambda r, t0, t1: (0.1, {}),
                         time_limit_sec=123, max_tokens=2048)
    probe.probe(_harness(), basis="clean")
    assert atk.starts[0].time_limit_sec == 123
    assert atk.starts[0].max_tokens == 2048


def test_probe_end_to_end_with_godview_scorer():
    """되돌림→공격→god-view 채점 전체 고리를 실제 GodviewScorer 로 엮어 스칼라가 나오나."""
    from common.app_signals import CROWN_INTERNAL_SECRETS
    from orchestrator.objectives import default_objectives
    from orchestrator.flags import default_registry
    from refiner.score import GodviewScorer

    class _Logs:
        def techniques_in_window(self, *, since_ts, until_ts):
            return {"T1552.001", "T1078"}        # 단계 2
        def crowns_in_window(self, *, since_ts, until_ts):
            return {CROWN_INTERNAL_SECRETS}      # 크라운 1

    scorer = GodviewScorer(_Logs(), default_objectives(), default_registry())
    probe = HarnessProbe(snapshot=FakeSnapshot(), attacker=FakeAttacker(_ok_result()),
                         score_turn=scorer)
    s = probe.probe(_harness(), basis="clean")
    assert s.score == 2 * 1.0 + 1 * 10.0         # 단계깊이2 + 크라운1*10 = 12.0
    assert "crown-secrets" in s.detail["crowns"]


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
    print("── 시험실행 어댑터(HarnessProbe) 테스트 ──")
    sys.exit(_run())
