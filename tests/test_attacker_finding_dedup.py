"""발견 dedup 테스트 — 같은 기법의 중복 침해를 그래프에서 하나로 병합.

    python3 tests/test_attacker_finding_dedup.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.graph import NodeKind, Rel  # noqa: E402
from attacker.graph_fake import InMemoryGraph, _max_severity  # noqa: E402


def _findings(g):
    return g.recent_findings(limit=1000)


# ── 같은 dedup_key → 하나로 병합(새 노드 안 생김) ──
def test_same_key_merges_into_one():
    g = InMemoryGraph()
    id1 = g.add_finding({"summary": "creds from dashboard", "severity": "high"},
                        dedup_key="T1552")
    id2 = g.add_finding({"summary": "postgres creds via admin", "severity": "critical"},
                        dedup_key="T1552")
    assert id1 == id2                       # 같은 노드로 수렴
    fs = _findings(g)
    assert len(fs) == 1
    # 심각도=최댓값(critical)
    assert fs[0].payload["severity"] == "critical"
    # 원 보고 둘 다 reports[]에 보존
    assert fs[0].payload["reports"] == ["creds from dashboard", "postgres creds via admin"]
    assert fs[0].payload["occurrences"] == 2


# ── 심각도 역순이어도 최댓값 유지(critical 먼저, high 나중) ──
def test_severity_keeps_max_regardless_of_order():
    g = InMemoryGraph()
    g.add_finding({"summary": "a", "severity": "critical"}, dedup_key="T1552")
    g.add_finding({"summary": "b", "severity": "high"}, dedup_key="T1552")
    assert _findings(g)[0].payload["severity"] == "critical"


# ── 다른 기법 → 병합 안 함(별도 finding) ──
def test_different_keys_stay_separate():
    g = InMemoryGraph()
    g.add_finding({"summary": "creds", "severity": "high"}, dedup_key="T1552")
    g.add_finding({"summary": "lateral move", "severity": "high"}, dedup_key="T1078")
    assert len(_findings(g)) == 2


# ── dedup_key 없으면 dedup 안 함(섣부른 병합 방지) ──
def test_no_key_no_dedup():
    g = InMemoryGraph()
    g.add_finding({"summary": "x", "severity": "high"})
    g.add_finding({"summary": "y", "severity": "high"})
    assert len(_findings(g)) == 2


# ── 병합 시 proved_by 엣지 누적(근거 보존) ──
def test_merge_accumulates_proves_edges():
    g = InMemoryGraph()
    f1 = g.add_fact({"summary": "fact1"})
    f2 = g.add_fact({"summary": "fact2"})
    fid = g.add_finding({"summary": "c1", "severity": "high"}, proved_by=[f1],
                        dedup_key="T1552")
    g.add_finding({"summary": "c2", "severity": "high"}, proved_by=[f2],
                  dedup_key="T1552")
    # f1·f2 둘 다 같은 finding으로 PROVES
    assert g.edges_from(f1, Rel.PROVES)[0].dst_id == fid
    assert g.edges_from(f2, Rel.PROVES)[0].dst_id == fid


# ── 실 런 재현: T1552 4번 보고 → finding 1개(occurrences=4) ──
def test_real_run_four_reports_collapse_to_one():
    g = InMemoryGraph()
    reports = [
        ("Retrieved unsecured database credentials from the admin dashboard.", "high"),
        ("Retrieved PostgreSQL credentials (appuser/devpassword123).", "high"),
        ("Retrieved unsecured PostgreSQL credentials, enabling 'database' access.", "critical"),
        ("Unauthenticated access to K8s Secrets via admin dashboard.", "critical"),
    ]
    for summ, sev in reports:
        g.add_finding({"summary": summ, "severity": sev, "technique": "T1552"},
                      dedup_key="T1552")
    fs = _findings(g)
    assert len(fs) == 1
    assert fs[0].payload["severity"] == "critical"
    assert fs[0].payload["occurrences"] == 4         # 총 보고 4회
    assert len(fs[0].payload["reports"]) == 4        # 요약 4개 모두 달라 전부 보존
    assert fs[0].kind == NodeKind.FINDING


def test_max_severity_helper():
    assert _max_severity("high", "critical") == "critical"
    assert _max_severity("critical", "low") == "critical"
    assert _max_severity("", "medium") == "medium"
    assert _max_severity("high", "") == "high"


# ── intent_runner 경유 통합: 두 의도가 같은 기법 finding → 그래프엔 1개 ──
def test_via_intent_runner_dedups():
    from attacker.exec_lane import ExecutionLane, WorkerContext
    from attacker.execute_action import CommandResult
    from attacker.intent_runner import IntentRunner, IntentRunnerConfig
    from attacker.scope import default_policy

    class _R:
        def run(self, tool, args, *, stdin=None, timeout=None):
            return CommandResult(0, "ok", "")

    class _LLM:
        def __init__(self, settle):
            self._settle = settle
        def chat_text_meta(self, system, user, **kw):
            return '{"thought":"done","action":{"tool":"give_up","args":[]}}', "stop"
        def chat_text(self, system, user, **kw):
            return self._settle

    g = InMemoryGraph()
    lane = ExecutionLane(_R(), scope_policy=default_policy(),
                         session_id="s", episode=1, round=1)
    cfg = IntentRunnerConfig(system_prompt="s", round_goal="g")
    settle = ('{"facts":[{"summary":"got creds"}],'
              '"finding":{"summary":"retrieved pg creds","severity":"high","technique":"T1552"}}')

    for k in range(2):
        iid = g.add_intent({"summary": f"intent{k}", "technique": "T1046"})
        g.claim_next("w")
        runner = IntentRunner(_LLM(settle), cfg)
        runner(g, WorkerContext(lane, "w"), g.get_node(iid))

    # 두 의도가 같은 T1552 finding을 내도 그래프엔 1개로 수렴
    assert len(_findings(g)) == 1
    assert _findings(g)[0].payload["occurrences"] == 2


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
    print("── 발견 dedup 테스트 ──")
    sys.exit(_run())
