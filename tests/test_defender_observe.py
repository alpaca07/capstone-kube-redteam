"""방어 관측·필터 테스트 — 감사/Falco 로그 구조화 수집 + 노이즈 축소.

    python3 tests/test_defender_observe.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.k8s_logs import parse_rfc3339  # noqa: E402
from defender.filter import filter_observations  # noqa: E402
from defender.observer import (  # noqa: E402
    Observer, parse_audit_line, parse_falco_line,
)

ADMIN = "system:serviceaccount:internal:admin-sa"


def _audit_line(user=ADMIN, verb="get", resource="secrets", ns="database",
                ts="2026-10-11T14:56:03.100000Z", reason="RBAC: admin-tools-binding"):
    return json.dumps({
        "verb": verb, "user": {"username": user},
        "objectRef": {"resource": resource, "namespace": ns, "name": "postgres-credentials"},
        "annotations": {"authorization.k8s.io/decision": "allow",
                        "authorization.k8s.io/reason": reason},
        "requestReceivedTimestamp": ts})


def _falco_line(rule="Terminal shell in container", priority="Notice",
                ts="2026-10-11T14:56:04.000000000Z"):
    return json.dumps({"rule": rule, "priority": priority, "output": "Shell spawned in container",
                       "time": ts, "output_fields": {"container.id": "abc"}})


def _reader(lines):
    return lambda: iter(lines)


# ───────────── 파서 ─────────────
def test_parse_audit_line():
    e = parse_audit_line(_audit_line())
    assert e.user == ADMIN and e.verb == "get" and e.resource == "secrets"
    assert e.namespace == "database" and e.decision == "allow"
    assert "admin-tools-binding" in e.reason


def test_parse_audit_bad():
    assert parse_audit_line("not json") is None
    assert parse_audit_line('{"verb":"get"}') is None       # 타임스탬프 없음


def test_parse_falco_line():
    f = parse_falco_line(_falco_line())
    assert f.rule == "Terminal shell in container" and f.priority == "Notice"
    assert f.fields.get("container.id") == "abc"
    assert f.timestamp == parse_rfc3339("2026-10-11T14:56:04.000000000Z")  # 나노초 파싱


# ───────────── 수집(증분 창) ─────────────
def test_collect_window():
    obs = Observer(_reader([_audit_line(ts="2026-10-11T14:56:03.100000Z"),
                            _audit_line(ts="2026-10-11T14:56:03.200000Z"), "garbage"]),
                   _reader([_falco_line()]))
    t0 = parse_rfc3339("2026-10-11T14:56:00Z")
    t1 = parse_rfc3339("2026-10-11T14:56:10Z")
    full = obs.collect(since_ts=t0, until_ts=t1)
    assert len(full.audit) == 2 and len(full.falco) == 1       # garbage 무시
    # 창을 좁히면 앞 이벤트 제외(since < ts 규칙)
    narrow = obs.collect(since_ts=parse_rfc3339("2026-10-11T14:56:03.150000Z"), until_ts=t1)
    assert len(narrow.audit) == 1                              # 03.2 만


# ───────────── 필터 ─────────────
def test_filter_drops_system_users_keeps_sa():
    obs = Observer(_reader([
        _audit_line(user=ADMIN),
        _audit_line(user="system:apiserver", ts="2026-10-11T14:56:03.300000Z"),
        _audit_line(user="system:node:vm-b", ts="2026-10-11T14:56:03.400000Z"),
    ]), _reader([]))
    rep = filter_observations(obs.collect(since_ts=0.0))
    assert rep.total_audit == 1                                # admin-sa만 남음
    assert len(rep.audit_highlights) == 1
    assert rep.audit_highlights[0].user == ADMIN


def test_filter_aggregates_audit():
    obs = Observer(_reader([
        _audit_line(ts="2026-10-11T14:56:03.100000Z"),
        _audit_line(ts="2026-10-11T14:56:03.200000Z"),       # 같은 user/verb/resource/ns
        _audit_line(resource="pods", ts="2026-10-11T14:56:03.300000Z"),
    ]), _reader([]))
    rep = filter_observations(obs.collect(since_ts=0.0))
    secrets = [h for h in rep.audit_highlights if h.resource == "secrets"][0]
    assert secrets.count == 2                                  # 집계됨
    assert rep.total_audit == 3


def test_filter_aggregates_falco_by_rule():
    obs = Observer(_reader([]), _reader([
        _falco_line(ts="2026-10-11T14:56:04.000000000Z"),
        _falco_line(ts="2026-10-11T14:56:05.000000000Z"),
        _falco_line(rule="Read sensitive file untrusted", priority="Warning",
                    ts="2026-10-11T14:56:06.000000000Z"),
    ]))
    rep = filter_observations(obs.collect(since_ts=0.0))
    assert rep.total_falco == 3
    # Warning(rank3) 이 Notice(rank2)보다 앞
    assert rep.falco_highlights[0].rule == "Read sensitive file untrusted"
    shell = [h for h in rep.falco_highlights if h.rule == "Terminal shell in container"][0]
    assert shell.count == 2


def test_quiet_and_prompt_dict():
    empty = filter_observations(Observer(_reader([]), _reader([])).collect(since_ts=0.0))
    assert empty.is_quiet()
    obs = Observer(_reader([_audit_line()]), _reader([_falco_line()]))
    rep = filter_observations(obs.collect(since_ts=0.0))
    d = rep.to_prompt_dict()
    assert set(d.keys()) == {"window_sec", "audit", "falco"}
    assert d["audit"][0]["resource"] == "secrets" and d["falco"][0]["rule"]


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
    print("── 방어 관측·필터 테스트 ──")
    sys.exit(_run())
