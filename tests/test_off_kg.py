"""self-run: python3 tests/test_off_kg.py (pytest 불필요)"""
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.off_kg import (  # noqa: E402
    SCHEMA_VERSION, Outcome, Anchor, Trigger, Target, Hint, StepResult,
    ProcStep, ReplayRef, Procedure, AttackerClaim, GodView, RecordId,
    OffKgRecord, derive_outcome, build_off_kg_record, procstep_from_replay,
    jsonl_file_sink, list_sink, read_journal,
)

PASS = 0


def check(cond, msg):
    global PASS
    assert cond, msg
    PASS += 1


def test_derive_outcome():
    check(derive_outcome(GodView(crown=True, confirmed=True), False) is Outcome.CROWN, "crown")
    check(derive_outcome(GodView(confirmed=True), False) is Outcome.PROGRESS, "progress")
    check(derive_outcome(GodView(confirmed=False), True) is Outcome.FAILED, "failed")
    check(derive_outcome(GodView(confirmed=False), False) is Outcome.UNCONFIRMED, "unconfirmed")
    check(derive_outcome(GodView(crown=True), True) is Outcome.CROWN, "crown beats failed")


def _make_record(godview: GodView) -> OffKgRecord:
    rec_id = RecordId(run_id="r1", episode=7, round=3, intent_id="12",
                      ts="2026-11-20T03:41:12Z", attacker_model="qwen-unc")
    return build_off_kg_record(
        rec_id=rec_id,
        trigger=Trigger(applicability=None,
                        missing_info=["kg_procedure_lookup empty for T1059"],
                        reason="off-KG: redis lua escape, planner-own technique",
                        selected_anchor=None),
        target=Target(cpe="cpe:2.3:a:redis:redis:5.0.1:*:*:*:*:*:*:*", service_type="cache",
                      endpoint="redis.backend.svc:6379",
                      preconditions=["unauthenticated redis reachable"]),
        hint=Hint(technique_id="T1059"),
        procedure=Procedure(
            replay_ref=ReplayRef(session_id="vmA", episode=7, round=3),
            steps=[ProcStep(step=1, step_id="3.1", tool="redis-cli",
                            args=["-h", "{redis_host}", "-p", "6379", "--eval", "escape.lua"],
                            produces=["cmd_out"], determinism="depends_on_prior",
                            result=StepResult(exit_code=0, success=True,
                                              stdout_hash="sha256:9f2c", excerpt="uid=0(root)"))]),
        attacker_claim=AttackerClaim(reached_flag=False, claimed_outcome="rce as root"),
        godview=godview,
        proc_failed=False,
    )


def test_build_and_outcome():
    rec = _make_record(GodView(confirmed=True, techniques_observed=["T1059"], evidence_channels=["falco"]))
    check(rec.outcome is Outcome.PROGRESS, "progress record")
    check(rec.schema_version == SCHEMA_VERSION, "version")
    check(rec.procedure.steps[0].determinism == "depends_on_prior", "determinism 3-value kept")


def test_roundtrip():
    rec = _make_record(GodView(confirmed=True, evidence_channels=["falco"]))
    back = OffKgRecord.model_validate_json(rec.to_jsonl())
    check(back == rec, "jsonl roundtrip equal")


# ── replay_schema.Step 덕타이핑 변환 ──
@dataclass
class _Cmd:
    tool: str
    args: list = field(default_factory=list)
    payload_ref: object = None


@dataclass
class _Res:
    exit_code: int = 0
    success: bool = False
    stdout_hash: object = None
    stdout_excerpt: str = ""


@dataclass
class _Det:
    value: str


@dataclass
class _Step:
    step: int
    step_id: str
    command: _Cmd
    inputs: dict
    produces: dict
    result: _Res
    determinism: _Det


def test_procstep_from_replay():
    s = _Step(step=2, step_id="3.2", command=_Cmd(tool="kubectl", args=["get", "secrets"]),
              inputs={"tok": object()}, produces={"sa_token": object()},
              result=_Res(exit_code=0, success=True, stdout_hash="sha256:aa", stdout_excerpt="NAME  TYPE"),
              determinism=_Det("depends_on_prior"))
    ps = procstep_from_replay(s)
    check(ps.step == 2 and ps.step_id == "3.2", "step/step_id")
    check(ps.tool == "kubectl" and ps.args == ["get", "secrets"], "tool/args")
    check(ps.inputs == ["tok"] and ps.produces == ["sa_token"], "input/produce names")
    check(ps.determinism == "depends_on_prior", "determinism value")
    check(ps.result.excerpt == "NAME  TYPE" and ps.result.success, "result mapped")


def test_list_sink():
    bucket: list = []
    list_sink(bucket)(_make_record(GodView(confirmed=True)))
    check(len(bucket) == 1, "list sink appended")


def test_file_sink_and_read():
    with tempfile.TemporaryDirectory() as d:
        path = Path(d) / "logs" / "off_kg.jsonl"
        sink = jsonl_file_sink(path)
        sink(_make_record(GodView(confirmed=True)))
        sink(_make_record(GodView(crown=True, confirmed=True)))
        recs = read_journal(path)
        check(len(recs) == 2, "read two")
        check(recs[1].outcome is Outcome.CROWN, "second crown")
        check(read_journal(Path(d) / "nope.jsonl") == [], "missing file -> empty")


if __name__ == "__main__":
    for fn in [test_derive_outcome, test_build_and_outcome, test_roundtrip,
               test_procstep_from_replay, test_list_sink, test_file_sink_and_read]:
        fn()
    print(f"off_kg: {PASS} checks passed")
