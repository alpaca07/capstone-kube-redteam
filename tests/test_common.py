"""공통 인터페이스 스모크 테스트 — pydantic 없이도 자체 실행 가능.

    python3 tests/test_common.py        # 자체 러너(초록/빨강)
    python3 -m pytest tests/            # pytest 있으면 그대로 수집됨

검증 범위:
  1) 메시지 10종 전부 build→wrap→JSON 직렬화→parse→payload_as 왕복
  2) 정보 비대칭 불변식(스키마 레벨): 방어 턴 시작엔 공격 필드 없음, type/payload 일관
  3) replay 검증 유틸: normalize_output(노이즈 마스킹), hash 안정성, determinism 규칙
  4) config 로더: config.example.yaml 을 읽어 검증 통과
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# 어떻게 실행하든(python3 tests/..., -m pytest) 저장소 루트를 import 경로에 둔다.
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.messages import (  # noqa: E402
    AgentRole, AgentState, AgentStatus,
    AttackEndReason, AttackTurnResult, AttackTurnStart,
    DefenseEndReason, DefenseTurnResult, DefenseTurnStart,
    Detection, Envelope, FlagObtained, Foothold,
    HealthCheck, HealthResult, MsgType, PAYLOAD_TYPE, PatchItem,
    ReplayPhase, ReplayRequest, ReplayResult,
    StateCheck, StateCheckResult, StateQuery, StateQueryResult,
    StepReplayRec, parse_envelope, wrap,
)
from common.replay_schema import (  # noqa: E402
    Command, Determinism, Extract, ExtractMethod, FlagCheck, InputRef,
    InputSource, ProducesRef, ReplayScript, Step,
    classify_determinism, hash_normalized, normalize_output,
)


# ───────────────────── 샘플 빌더 ─────────────────────
def _sample_replay_script() -> ReplayScript:
    """② SA토큰 → secret 조회 → ④ DB에서 FLAG, 동적 의존 포함한 2스텝."""
    step1 = Step(
        step=1,
        command=Command(tool="kubectl", args=["-n", "database", "get", "secret",
                                               "postgres-credentials", "-o", "json"]),
        produces={"pw": ProducesRef(extract=Extract(
            method=ExtractMethod.JSONPATH, path="$.data.password"))},
        determinism=Determinism.DETERMINISTIC,
    )
    step2 = Step(
        step=2,
        command=Command(tool="psql", args=["-c", "SELECT value FROM internal_secrets"]),
        inputs={"pw": InputRef(source=InputSource.STEP_OUTPUT, from_step=1,
                               extract=Extract(method=ExtractMethod.JSONPATH, path="$.data.password"))},
        flag_check=FlagCheck(flag_id="4", obtained=True),
    )
    return ReplayScript(session_id="s-001", episode=1, round=2,
                        base_snapshot="clean-baseline", steps=[step1, step2])


def _one_of_each() -> list:
    """메시지 10종 각 1개(요청/응답 포함)."""
    rs = _sample_replay_script()
    return [
        AttackTurnStart(time_limit_sec=300,
                        foothold=Foothold(attack_endpoint="10.0.0.5", notes="nginx NodePort")),
        AttackTurnResult(end_reason=AttackEndReason.FLAG,
                         flags_obtained=[FlagObtained(flag_id="4", value="FLAG{x}", step=2)],
                         replay_script=rs, attack_summary="② over-perm SA → DB", elapsed_sec=42.0),
        DefenseTurnStart(time_limit_sec=300),
        DefenseTurnResult(patch_applied=True, end_reason=DefenseEndReason.PATCHED,
                          detected=[Detection(technique="T1078", evidence="admin-sa get secret",
                                              confidence=0.8)],
                          patch_set=[PatchItem(kind="rbac", target="internal:admin-sa",
                                               summary="권한 축소")],
                          healthcheck_passed=True, elapsed_sec=30.0),
        ReplayRequest(replay_script=rs, phase=ReplayPhase.POST, target="10.0.0.5"),
        ReplayResult(phase=ReplayPhase.POST,
                     steps_result=[StepReplayRec(step=1, success=True),
                                   StepReplayRec(step=2, success=False, note="RBAC blocked")],
                     overall_success=False, flags_reached=[]),
        StateQuery(checks=[StateCheck(check_id="2", query="admin-sa cluster-wide secret get?")]),
        StateQueryResult(results=[StateCheckResult(check_id="2", vulnerable=False,
                                                   detail="forbidden after patch")]),
        HealthCheck(service="all"),
        HealthResult(service="all", healthy=True, response_time_ms=12.3),
        AgentStatus(agent=AgentRole.ATTACKER, state=AgentState.IDLE),
    ]


# ───────────────────── 테스트 ─────────────────────
def test_all_message_types_roundtrip():
    """10종(+응답) 전부 wrap→JSON→parse→payload_as 왕복, 값 보존."""
    for payload in _one_of_each():
        env = wrap(payload, episode=1, round=2)
        assert env.type == payload.MSG_TYPE, f"type 자동설정 실패: {payload}"

        raw = env.model_dump_json()                     # 전송 직렬화
        parsed = parse_envelope(raw)                    # 수신 역직렬화
        assert parsed.type == payload.MSG_TYPE
        assert parsed.episode == 1 and parsed.round == 2
        assert parsed.msg_id == env.msg_id

        back = parsed.payload_as(type(payload))         # 타입 확정
        assert back == payload, f"왕복 불일치: {type(payload).__name__}"


def test_registry_covers_all_10_types():
    """PAYLOAD_TYPE 레지스트리가 10종 전부를 덮는다(서버 디스패치용)."""
    assert set(PAYLOAD_TYPE.keys()) == set(MsgType), "레지스트리 누락/초과"
    assert len(MsgType) == 10


def test_payload_as_type_mismatch_raises():
    """봉투 type과 다른 모델로 꺼내면 거부(조용한 오파싱 방지)."""
    env = wrap(HealthCheck(service="web"))
    try:
        env.payload_as(AttackTurnStart)
    except ValueError:
        return
    raise AssertionError("type 불일치인데 통과함")


def test_info_asymmetry_defense_start_has_no_attack_fields():
    """★ 방어 턴 시작 payload엔 공격 관련 필드가 아예 없다(스키마로 강제)."""
    fields = set(DefenseTurnStart.model_fields.keys())
    assert fields == {"time_limit_sec"}, f"방어 시작에 과한 필드: {fields}"
    forbidden = {"foothold", "replay_script", "attack_summary", "flags_obtained",
                 "detected", "technique", "goal"}
    assert not (fields & forbidden)


def test_state_query_result_is_facts_only():
    """상태 응답은 '취약 여부 사실'만 — 점수/판정 필드 없음(판정은 VM C)."""
    fields = set(StateCheckResult.model_fields.keys())
    assert fields == {"check_id", "vulnerable", "detail"}
    assert "score" not in fields and "verdict" not in fields


def test_health_pair_shares_type_but_distinct_models():
    """health_check은 쌍 타입이 없어 요청/응답이 같은 type을 쓴다."""
    assert HealthCheck.MSG_TYPE == HealthResult.MSG_TYPE == MsgType.HEALTH_CHECK
    env = wrap(HealthResult(service="web", healthy=True, response_time_ms=5.0), status="ok")
    assert env.status == "ok"
    assert parse_envelope(env.model_dump_json()).payload_as(HealthResult).healthy is True


# ---- replay 검증 유틸 ----
def test_normalize_masks_volatile_fields():
    """타임스탬프·UUID·JWT·hex·IP·resourceVersion 마스킹."""
    raw = ('creationTimestamp: "2026-10-11T14:56:03Z"\n'
           'uid: 3f2504e0-4f89-41d3-9a0c-0305e82c3301\n'
           'token: eyJhbGciOi.eyJzdWIi.SflKxwRJ\n'
           'hash: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6\n'
           '"resourceVersion":"123456"\n'
           'podIP: 10.42.0.17')
    n = normalize_output(raw)
    for marker in ("<TS>", "<UUID>", "<JWT>", "<HEX>", "<RV>", "<IP>"):
        assert marker in n, f"{marker} 마스킹 안 됨:\n{n}"
    # 변동요소 제거 후엔 run이 달라도 같은 해시.
    raw2 = raw.replace("10.42.0.17", "10.42.9.99").replace("123456", "999999")
    assert hash_normalized(raw) == hash_normalized(raw2), "정규화 후에도 해시가 다름"


def test_normalize_empty():
    assert normalize_output("") == ""
    assert hash_normalized("").startswith("sha256:")


def test_classify_determinism_rules():
    """규칙 기반 판정: 내재적 비결정 > 선행 의존 > 결정적."""
    # 내재적 비결정(openssl rand)
    c_rand = Command(tool="openssl", args=["rand", "-hex", "16"])
    assert classify_determinism(c_rand, {}) == Determinism.NONDETERMINISTIC
    # 인자 힌트(random)
    c_hint = Command(tool="curl", args=["http://x/getRandomToken"])
    assert classify_determinism(c_hint, {}) == Determinism.NONDETERMINISTIC
    # 선행 스텝 의존
    c_dep = Command(tool="psql", args=["-c", "SELECT 1"])
    dep_inputs = {"pw": InputRef(source=InputSource.STEP_OUTPUT, from_step=1)}
    assert classify_determinism(c_dep, dep_inputs) == Determinism.DEPENDS_ON_PRIOR
    # 결정적(고정 입력만)
    c_det = Command(tool="kubectl", args=["get", "pods"])
    static_inputs = {"ns": InputRef(source=InputSource.STATIC, value="database")}
    assert classify_determinism(c_det, static_inputs) == Determinism.DETERMINISTIC


def test_replay_script_nested_json_roundtrip():
    """ReplayScript가 봉투 payload로 중첩돼도 깨지지 않는다(검증 핵심 경로)."""
    rs = _sample_replay_script()
    env = wrap(ReplayRequest(replay_script=rs, phase=ReplayPhase.PRE))
    back = parse_envelope(env.model_dump_json()).payload_as(ReplayRequest)
    assert back.replay_script.steps[1].flag_check.flag_id == "4"
    assert back.replay_script.steps[1].inputs["pw"].from_step == 1


# ---- config 로더 ----
def test_config_loads_example():
    """config.example.yaml 을 읽어 스키마 검증을 통과(필드명/구조 일치 확인)."""
    from common.config import load_config
    example = _ROOT / "common" / "config.example.yaml"
    assert example.is_file(), "config.example.yaml 없음"
    cfg = load_config(example)
    assert cfg.dgx.port == 11434
    assert cfg.dgx.base_url.endswith(":11434/v1")
    assert cfg.experiment.time_limit_sec == 300
    assert cfg.experiment.n_consecutive_defense == 3
    assert cfg.flags.format == "FLAG{...}"


def test_config_missing_raises():
    from common.config import load_config
    try:
        load_config(_ROOT / "common" / "nonexistent-config.yaml")
    except FileNotFoundError:
        return
    raise AssertionError("없는 파일인데 에러 안 남")


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
    print("── common 스모크 테스트 ──")
    sys.exit(_run())
