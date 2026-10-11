"""방어 state_query + DefenseHarness 테스트 — fake 이음새로 전 파이프라인 end-to-end.

    python3 tests/test_defender_server.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.messages import (  # noqa: E402
    DefenseEndReason, DefenseTurnStart, HealthCheck, StateCheck, StateQuery, wrap,
)
from defender.observer import Observer  # noqa: E402
from defender.patcher import OpResult, Patcher  # noqa: E402
from defender.server import DefenseHarness, handle_message  # noqa: E402
from defender.state_query import ADMIN_SA, StateQueryHandler  # noqa: E402
from defender.triage import Triager  # noqa: E402

_TRIAGE_DETECT = ('{"assessment":"②","detected":[{"type":"over_perm","mitre":"T1078",'
                  '"evidence":"audit"}],"severity":"high","patch_plan":['
                  '{"action":"restrict_rbac","target":"clusterrolebinding/admin-tools-binding"}]}')
_TRIAGE_NONE = '{"assessment":"정상","detected":[],"severity":"low","patch_plan":[]}'


def _audit(user=ADMIN_SA, ts="2026-10-11T14:56:03.100000Z"):
    return json.dumps({"verb": "get", "user": {"username": user},
                       "objectRef": {"resource": "secrets", "namespace": "database"},
                       "annotations": {"authorization.k8s.io/reason": "admin-tools-binding"},
                       "requestReceivedTimestamp": ts})


def _reader(lines):
    return lambda: iter(lines)


class _FakeLLM:
    def __init__(self, text):
        self.text = text

    def chat_text(self, system, user, **kw):
        return self.text


class _BoomLLM:
    def chat_text(self, system, user, **kw):
        raise RuntimeError("llm down")


class _FakeCluster:
    """ClusterClient(apply/delete/healthcheck) + ClusterReader(can_i/get/find_text) 겸용."""
    def __init__(self, *, healthy=True, can_i=True, netpols=0, leak=True,
                 apply_ok=True, delete_ok=True):
        self._healthy, self._can_i, self._netpols, self._leak = healthy, can_i, netpols, leak
        self._apply_ok, self._delete_ok = apply_ok, delete_ok

    def apply(self, manifest, *, dry_run=False):
        return OpResult(self._apply_ok, "")

    def delete(self, kind, name, namespace="", *, dry_run=False):
        return OpResult(self._delete_ok, "")

    def healthcheck(self):
        return OpResult(self._healthy, "")

    def can_i(self, verb, resource, *, as_user="", all_namespaces=False, namespace=""):
        return self._can_i

    def get(self, kind, *, namespace="", name=""):
        return [{} for _ in range(self._netpols)]

    def find_text(self, needle, *, kinds, namespaces):
        return self._leak


def _harness(*, triage_json=_TRIAGE_DETECT, cluster=None, audit_lines=None, llm=None):
    cluster = cluster or _FakeCluster()
    observer = Observer(_reader(audit_lines if audit_lines is not None else [_audit()]), _reader([]))
    triager = Triager(llm or _FakeLLM(triage_json), "sys")
    return DefenseHarness(observer=observer, triager=triager, patcher=Patcher(cluster),
                          state_handler=StateQueryHandler(cluster), cluster=cluster)


def _start():
    return DefenseTurnStart(time_limit_sec=300)


# ───────────── defense_turn end-to-end ─────────────
def test_defense_turn_detect_and_patch():
    h = _harness()
    r = h.defense_turn(_start(), episode=1, round=1)
    assert r.patch_applied and r.end_reason == DefenseEndReason.PATCHED
    assert any(d.technique == "T1078" for d in r.detected)
    assert r.healthcheck_passed and r.elapsed_sec >= 0
    assert r.patch_set and r.patch_set[0].kind == "rbac"


def test_defense_turn_noop_when_no_threat():
    h = _harness(triage_json=_TRIAGE_NONE)
    r = h.defense_turn(_start(), episode=1, round=1)
    assert not r.patch_applied and r.end_reason == DefenseEndReason.NOOP
    assert r.detected == []


def test_defense_turn_overblock_flags_health():
    h = _harness(cluster=_FakeCluster(healthy=False))      # 패치 후 서비스 죽음
    r = h.defense_turn(_start(), episode=1, round=1)
    assert r.patch_applied and not r.healthcheck_passed    # 과잉차단 신호


def test_cursor_advances():
    h = _harness()
    assert h._cursor == 0.0
    h.defense_turn(_start(), episode=1, round=1)
    assert h._cursor > 0.0                                 # 로그 ts만큼 전진(다음 라운드 증분)


def test_defense_turn_error_on_llm_crash():
    h = _harness(llm=_BoomLLM())
    r = h.defense_turn(_start(), episode=1, round=1)
    assert r.end_reason == DefenseEndReason.ERROR and not r.patch_applied


def test_health_check():
    h = _harness(cluster=_FakeCluster(healthy=False))
    hr = h.health_check(HealthCheck(service="all"), episode=1, round=1)
    assert hr.healthy is False and hr.service == "all" and hr.response_time_ms >= 0


# ───────────── state_query ─────────────
def test_state_query_facts():
    h = _harness(cluster=_FakeCluster(can_i=True, netpols=0, leak=True))
    res = h.state_query(StateQuery(checks=[
        StateCheck(check_id="1", query="q"), StateCheck(check_id="2", query="q"),
        StateCheck(check_id="3", query="q")]), episode=1, round=1)
    by = {r.check_id: r.vulnerable for r in res.results}
    assert by == {"1": True, "2": True, "3": True}         # 전부 취약 상태


def test_state_query_netpol_present_not_vulnerable():
    sh = StateQueryHandler(_FakeCluster(netpols=1))
    res = sh.handle(StateQuery(checks=[StateCheck(check_id="3", query="q")]))
    assert res.results[0].vulnerable is False               # NP 있으면 ③ 안전


def test_state_query_unsupported_omitted():
    sh = StateQueryHandler(_FakeCluster())
    res = sh.handle(StateQuery(checks=[StateCheck(check_id="99", query="?")]))
    assert res.results == []                                # 생략 → VM C가 INCONCLUSIVE


# ───────────── handle_message 디스패치 (봉투 왕복) ─────────────
def test_handle_defense_turn_envelope():
    h = _harness()
    raw = wrap(DefenseTurnStart(time_limit_sec=300), episode=2, round=1).model_dump(mode="json")
    resp = handle_message(h, raw)
    assert resp["type"] == "defense_turn_result" and resp["status"] == "ok"
    assert resp["episode"] == 2 and resp["payload"]["patch_applied"] is True


def test_handle_state_query_envelope():
    h = _harness(cluster=_FakeCluster(can_i=True, netpols=0))
    raw = wrap(StateQuery(checks=[StateCheck(check_id="2", query="q")]),
               episode=1, round=1).model_dump(mode="json")
    resp = handle_message(h, raw)
    assert resp["type"] == "state_query_result"
    assert resp["payload"]["results"][0]["vulnerable"] is True


def test_handle_health_envelope():
    h = _harness(cluster=_FakeCluster(healthy=True))
    raw = wrap(HealthCheck(service="all"), episode=1, round=1).model_dump(mode="json")
    resp = handle_message(h, raw)
    assert resp["type"] == "health_check" and resp["payload"]["healthy"] is True


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
    print("── 방어 state_query + 하네스 테스트 ──")
    sys.exit(_run())
