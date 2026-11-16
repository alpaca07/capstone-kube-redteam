"""실 조립(build_probe) 테스트 — config 로 HarnessProbe 가 I/O 없이 조립되나.

실 어댑터는 전부 지연(연결은 probe() 때)이라 조립만으론 네트워크·파일을 안 건드린다.
자체 러너: python3 tests/test_refiner_builder.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.config import Config
from refiner.builder import build_probe
from refiner.probe import HarnessProbe
from refiner.score import GodviewScorer


def _cfg(**over) -> Config:
    base = {
        "dgx": {"attacker_host": "10.0.0.9", "defender_host": "10.0.0.10",
                "attacker_model": "jb", "defender_model": "al", "max_tokens": 2048},
        "network": {"attacker_url": "http://10.0.0.1:8000",
                    "defender_url": "http://10.0.0.2:8000", "shared_token": "t"},
        "target": {"attack_endpoint": "10.0.0.5", "kubeconfig": "/tmp/kube.yaml"},
        "experiment": {"time_limit_sec": 222, "crown_sync_grace_sec": 5.0,
                       "crown_skew_pad_sec": 3.0},
    }
    base.update(over)
    return Config.model_validate(base)


def test_build_probe_returns_harnessprobe_with_godview_scorer():
    p = build_probe(_cfg())
    assert isinstance(p, HarnessProbe)
    assert isinstance(p.score_turn, GodviewScorer)          # 기본 채점기 자동 구성
    assert p.clean_snapshot == "clean-baseline"             # cfg.vmware.baseline_snapshot 기본값
    assert p.time_limit_sec == 222                          # experiment 에서
    assert p.max_tokens == 2048                             # dgx 에서
    assert p.settle_sec == 5.0                              # crown_sync_grace_sec 기본 사용


def test_build_probe_foothold_from_attack_endpoint():
    p = build_probe(_cfg())
    assert p.foothold is not None and p.foothold.attack_endpoint == "10.0.0.5"


def test_build_probe_exec_mode_omits_foothold():
    # exec 모드면 클러스터 내부 발판 → 외부 endpoint 안 실음(VM A가 자기 config 발판 사용).
    p = build_probe(_cfg(attack={"exec_mode": True, "exec_namespace": "frontend",
                                 "exec_pod": "deploy/attacker-foothold"}))
    assert p.foothold is None


def test_build_probe_scorer_weights_and_window():
    p = build_probe(_cfg(), stage_weight=2.0, crown_bonus=7.0)
    sc = p.score_turn
    assert sc.stage_weight == 2.0 and sc.crown_bonus == 7.0
    assert sc.skew_pad == 3.0 and sc.grace_sec == 5.0       # experiment 패드에서


def test_build_probe_custom_score_turn_overrides_default():
    custom = lambda r, t0, t1: (1.0, {})
    p = build_probe(_cfg(), score_turn=custom)
    assert p.score_turn is custom                           # 주입하면 GodviewScorer 안 만듦


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
    print("── 실 조립(build_probe) 테스트 ──")
    sys.exit(_run())
