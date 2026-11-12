"""self-run: python3 tests/test_promote.py (pytest 불필요)

off-KG 저널 → 핵심층 승급 변환이 팀원 게이트(authoring.validate_env)를 통과하고,
build_core_layer(source=coevolution)로 실증 신뢰수준과 함께 적재 가능한지 검증.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from common.app_signals import CROWN_TARGETS  # noqa: E402
from common.off_kg import (  # noqa: E402
    AttackerClaim, GodView, Hint, Procedure, ProcStep, ReplayRef, RecordId,
    StepResult, Target, Trigger, build_off_kg_record,
)
from knowledge import authoring, graph_writer, promote  # noqa: E402

PASS = 0


def check(cond, msg):
    global PASS
    assert cond, msg
    PASS += 1


def _mk(gv: GodView, *, tech="T1059", cpe="cpe:2.3:a:redis:redis:5.0.1:*:*:*:*:*:*:*",
        endpoint="redis.backend.svc", fid=1, reason="off-KG redis lua escape"):
    return build_off_kg_record(
        rec_id=RecordId(run_id="20261120T0300Z", episode=7, round=3, intent_id=str(fid),
                        ts="t", attacker_model="qwen-unc"),
        trigger=Trigger(missing_info=[f"no KG procedure for {tech}"], reason=reason),
        target=Target(cpe=cpe, service_type="cache", endpoint=endpoint,
                      preconditions=["unauthenticated redis reachable"]),
        hint=Hint(technique_id=tech),
        procedure=Procedure(replay_ref=ReplayRef(session_id="vmA", episode=7, round=3),
                            steps=[ProcStep(step=1, step_id="3.1", tool="redis-cli",
                                            args=["-h", "{h}", "--eval", "x.lua"],
                                            result=StepResult(success=True, excerpt="uid=0(root)"))]),
        attacker_claim=AttackerClaim(claimed_outcome="rce as root"),
        godview=gv, proc_failed=False)


def test_gate_and_dedup():
    crown = _mk(GodView(confirmed=True, crown=True))
    prog = _mk(GodView(confirmed=True), tech="T1190", endpoint="struts")
    unconf = _mk(GodView(confirmed=False), tech="T1555", endpoint="vault")
    kept = promote.gate_and_dedup([crown, prog, unconf])
    check({r.hint.technique_id for r in kept} == {"T1059", "T1190"}, "progress+ only")
    # dedup same (tech,cpe) → best(crown)
    dup = promote.gate_and_dedup([_mk(GodView(confirmed=True)), crown])
    check(len(dup) == 1 and dup[0].godview.crown, "dedup keeps crown")


def test_env_passes_authoring_gate():
    env = promote.record_to_env(_mk(GodView(confirmed=True, crown=True)))
    errors, _ = authoring.validate_env(env)
    check(errors == [], f"env passes teammate gate: {errors}")
    check(env["_validation"] == "VERIFIED", "crown → VERIFIED level")
    check(env["technique"] == "T1059", "technique carried")
    kinds = {er["kind"] for er in env["expected_results"]}
    check(kinds == {"progress", "crown"}, "progress + crown ER")
    crown_er = next(er for er in env["expected_results"] if er["kind"] == "crown")
    c = crown_er["conditions"][0]
    check(c["channel"] == "crown" and c["field"] == "asset" and c["operator"] == "in"
          and c["expected"] == list(CROWN_TARGETS), "crown condition uses crown constants")
    prog_er = next(er for er in env["expected_results"] if er["kind"] == "progress")
    pc = prog_er["conditions"][0]
    check(pc == {"channel": "falco", "field": "technique", "operator": "eq", "expected": "T1059"},
          "progress condition falco/technique")


def test_progress_only_level_and_gate():
    env = promote.record_to_env(_mk(GodView(confirmed=True)))   # confirmed, not crown
    errors, _ = authoring.validate_env(env)
    check(errors == [], f"progress-only env valid: {errors}")
    check(env["_validation"] == "OBSERVED", "progress → OBSERVED level")
    check(all(er["kind"] == "progress" for er in env["expected_results"]), "no crown ER")


def test_invalid_technique_omitted():
    env = promote.record_to_env(_mk(GodView(confirmed=True, crown=True), tech="NOT-A-TID"))
    check("technique" not in env, "invalid technique omitted (no error)")
    errors, _ = authoring.validate_env(env)
    check(errors == [], "still valid via crown ER")           # crown ER carries it
    check(all(er["kind"] == "crown" for er in env["expected_results"]), "only crown ER (no valid tech)")


def test_load_coevolution_provenance_and_level():
    recs = promote.gate_and_dedup([_mk(GodView(confirmed=True, crown=True)),
                                   _mk(GodView(confirmed=True), tech="T1190", endpoint="struts")])
    envs, rejected = promote.promote(recs)
    check(rejected == [] and len(envs) == 2, "both promote cleanly")
    sess = graph_writer.DryRunSession()
    # load_envs 가 수준별로 build_core_layer(source=coevolution) 호출 → 스키마 검사 통과해야
    n, r = promote.load_envs(sess, envs)
    check(n > 0 and r > 0, "nodes/rels loaded")
    # 실제 노드/관계로 출처·신뢰수준 확인
    nodes, _ = sources_build(envs, "VERIFIED")
    ks = [x["id"] for x in nodes if x["label"] == "KnowledgeSource"]
    check("KS-coevolution-loop" in ks and "KS-core-layer" not in ks, "coevolution provenance")
    proc = next(x for x in nodes if x["label"] == "Procedure")
    check(proc["props"].get("validation_level") == "VERIFIED", "validation_level on Procedure")


def sources_build(envs, level):
    from knowledge import sources
    return sources.build_core_layer({"environments": envs}, source="coevolution",
                                    validation_level=level)


if __name__ == "__main__":
    for fn in [test_gate_and_dedup, test_env_passes_authoring_gate,
               test_progress_only_level_and_gate, test_invalid_technique_omitted,
               test_load_coevolution_provenance_and_level]:
        fn()
    print(f"promote: {PASS} checks passed")
