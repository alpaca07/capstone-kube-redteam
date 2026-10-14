"""방어 triage 파이프라인 + patcher 테스트 — fake LLM/클러스터로.

    python3 tests/test_defender_pipeline.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from defender.filter import AuditHighlight, SituationReport  # noqa: E402
from defender.patcher import OpResult, Patcher, render_op  # noqa: E402
from defender.triage import PatchStep, Severity, Triager  # noqa: E402

_TRIAGE_JSON = ('{"assessment":"admin-sa가 DB secret 조회","detected":['
                '{"type":"over_perm_sa","mitre":"T1078","evidence":"audit"}],'
                '"severity":"high","patch_plan":['
                '{"action":"restrict_rbac","target":"clusterrolebinding/admin-tools-binding"}]}')


def _report():
    return SituationReport(since_ts=0.0, until_ts=10.0,
                           audit_highlights=[AuditHighlight("admin-sa", "get", "secrets", "database", 2, "rbac")],
                           total_audit=2)


# ───────────── fakes ─────────────
class _FakeLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def chat_text(self, system, user, **kw):
        self.calls.append((system, user))
        return self.responses.pop(0) if self.responses else "{}"


class _FakeCluster:
    def __init__(self, *, apply_ok=True, delete_ok=True, dry_fail_on=None, healthy=True):
        self.calls = []
        self.apply_ok, self.delete_ok = apply_ok, delete_ok
        self.dry_fail_on, self.healthy = dry_fail_on, healthy

    def apply(self, manifest, *, dry_run=False):
        self.calls.append(("apply", dry_run, manifest))
        if dry_run and self.dry_fail_on and self.dry_fail_on in manifest:
            return OpResult(False, "dry-run reject")
        return OpResult(self.apply_ok, "")

    def delete(self, kind, name, namespace="", *, dry_run=False):
        self.calls.append(("delete", dry_run, f"{kind}/{name}"))
        if dry_run and self.dry_fail_on and self.dry_fail_on in name:
            return OpResult(False, "dry-run reject")
        return OpResult(self.delete_ok, "")

    def healthcheck(self):
        return OpResult(self.healthy, "ok" if self.healthy else "service down")


# ───────────── Triager ─────────────
def test_triage_valid():
    llm = _FakeLLM([_TRIAGE_JSON])
    r = Triager(llm, "sys").triage(_report())
    assert r.severity == Severity.HIGH and r.techniques() == ["T1078"]
    assert len(llm.calls) == 1


def test_triage_retries_then_succeeds():
    llm = _FakeLLM(["쓰레기, JSON 아님", _TRIAGE_JSON])
    r = Triager(llm, "sys").triage(_report())
    assert r.severity == Severity.HIGH
    assert len(llm.calls) == 2
    assert "유효한 JSON이 아니었습니다" in llm.calls[1][1]       # 2번째 호출에 피드백 주입


def test_triage_all_fail_safe_default():
    llm = _FakeLLM(["x", "y", "z"])                             # max_retries=2 → 3회
    r = Triager(llm, "sys", max_retries=2).triage(_report())
    assert r.detected == [] and r.patch_plan == [] and "파싱 실패" in r.assessment
    assert len(llm.calls) == 3


# ───────────── render ─────────────
def test_render_networkpolicy():
    op = render_op(PatchStep(action="add_networkpolicy", target="database"))
    assert op.kind == "apply" and "NetworkPolicy" in op.manifest and "database" in op.manifest


def test_render_rbac_delete():
    op = render_op(PatchStep(action="restrict_rbac", target="clusterrolebinding/admin-tools-binding"))
    assert op.kind == "delete" and op.del_kind == "clusterrolebinding" and op.del_name == "admin-tools-binding"


def test_render_rbac_sa_unsupported():
    assert render_op(PatchStep(action="restrict_rbac", target="sa/admin-sa")) is None


def test_render_unknown_unsupported():
    assert render_op(PatchStep(action="pray", target="x")) is None


def test_render_networkpolicy_natural_language_target_falls_back():
    # LLM이 "all namespaces"(공백 포함) 같은 자연어 타깃을 줘도 무효 매니페스트를 만들지 않고
    # 기본 NS(database)로 폴백 — dry-run 실패→세트 롤백 방지.
    op = render_op(PatchStep(action="add_networkpolicies", target="all namespaces"))
    assert op is not None and op.kind == "apply"
    assert "namespace: database" in op.manifest
    assert "all namespaces" not in op.manifest


# ───────────── Patcher ─────────────
def test_patcher_applies_set_and_healthchecks():
    cluster = _FakeCluster(healthy=True)
    out = Patcher(cluster).apply_plan([
        PatchStep(action="add_networkpolicy", target="database"),
        PatchStep(action="restrict_rbac", target="clusterrolebinding/admin-tools-binding")])
    assert out.patch_applied and out.healthcheck_passed
    assert len([c for c in cluster.calls if c[1] is True]) == 2    # dry-run 2
    assert len([c for c in cluster.calls if c[1] is False]) == 2   # 실제 적용 2


def test_patcher_atomic_dryrun_fail_applies_nothing():
    cluster = _FakeCluster(dry_fail_on="admin-tools-binding")
    out = Patcher(cluster).apply_plan([
        PatchStep(action="add_networkpolicy", target="database"),
        PatchStep(action="restrict_rbac", target="clusterrolebinding/admin-tools-binding")])
    assert not out.patch_applied
    assert not any(c[1] is False for c in cluster.calls)          # 실제 적용 전무(원자적)


def test_patcher_unsupported_recorded():
    out = Patcher(_FakeCluster()).apply_plan([PatchStep(action="pray", target="x")])
    assert not out.patch_applied
    assert any("미지원" in a.detail for a in out.applied)


def test_patcher_healthcheck_fail_flags():
    out = Patcher(_FakeCluster(healthy=False)).apply_plan(
        [PatchStep(action="add_networkpolicy", target="database")])
    assert out.patch_applied and not out.healthcheck_passed        # 과잉차단 신호


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
    print("── 방어 triage 파이프라인 + patcher 테스트 ──")
    sys.exit(_run())
