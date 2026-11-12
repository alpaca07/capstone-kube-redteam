"""2단 자동 저작·검증 게이트(knowledge/authoring.py) 스모크 — 네트워크·LLM 없이.

검증 범위:
  1) validate_env: 유효 env 통과 / 채널·연산자·크라운상수·기법패턴·필수필드 위반 거절
  2) 경고(반영은 되나 쓸모↓): 크라운 없음·스파인 없음·기법 없음
  3) author_env: 저작기 이음새(FakeAuthor) → 게이트, cve·status 강제, 무효 거절
  4) LlmAuthor: OllamaClient transport 주입으로 코드펜스 JSON 왕복
  5) build_core_layer(source=llm, validation_level=THEORETICAL): 스키마 통과 + 신뢰수준 속성 스탬프
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.app_signals import CROWN_TARGETS  # noqa: E402
from common.llm_client import OllamaClient  # noqa: E402
from knowledge import authoring, schema  # noqa: E402
from knowledge.sources import build_core_layer  # noqa: E402


GOOD_ENV = {
    "env": "cve-2017-5638", "technique": "T1190", "cve": "CVE-2017-5638", "cwe": "CWE-755",
    "procedure": {"id": "PROC-struts2-ognl", "name": "OGNL 주입 명령 실행",
                  "description": "Content-Type OGNL 식으로 컨테이너 명령 실행."},
    "preconditions": [{"id": "PRE-struts2-ver", "name": "취약 버전 + 멀티파트 엔드포인트",
                       "description": "취약 Struts2 버전, 멀티파트 처리 엔드포인트 도달.",
                       "config": {"key": "multipart_enabled", "expected_value": "true", "operator": "eq"}}],
    "expected_results": [
        {"id": "ER-s-progress", "kind": "progress", "outcome": {"id": "AO-cmd", "name": "명령 실행"},
         "conditions": [{"channel": "falco", "field": "technique", "operator": "eq", "expected": "T1059"}]},
        {"id": "ER-s-crown", "kind": "crown", "outcome": {"id": "AO-exfil", "name": "민감 데이터 유출"},
         "conditions": [{"channel": "crown", "field": "asset", "operator": "in",
                         "expected": list(CROWN_TARGETS)}]},
    ],
}


def _clone(**patch):
    env = copy.deepcopy(GOOD_ENV)
    env.update(patch)
    return env


# ───────────── validate_env: 통과 ─────────────
def test_good_env_passes():
    errors, _warnings = authoring.validate_env(GOOD_ENV)
    assert errors == [], errors


def test_good_env_expands_and_passes_schema():
    nodes, rels = build_core_layer({"environments": [GOOD_ENV]})
    for n in nodes:
        schema.check_node(n)
    for r in rels:
        schema.check_rel(r)


# ───────────── validate_env: 거절 ─────────────
def test_bad_channel_rejected():
    env = copy.deepcopy(GOOD_ENV)
    env["expected_results"][0]["conditions"][0]["channel"] = "bogus"
    errors, _ = authoring.validate_env(env)
    assert any("channel" in e for e in errors)


def test_bad_operator_rejected():
    env = copy.deepcopy(GOOD_ENV)
    env["expected_results"][0]["conditions"][0]["operator"] = "gt"
    errors, _ = authoring.validate_env(env)
    assert any("operator" in e for e in errors)


def test_crown_non_constant_rejected():
    env = copy.deepcopy(GOOD_ENV)
    env["expected_results"][1]["conditions"][0]["expected"] = ["not_a_crown"]
    errors, _ = authoring.validate_env(env)
    assert any("크라운 상수" in e for e in errors)


def test_falco_non_technique_rejected():
    env = copy.deepcopy(GOOD_ENV)
    env["expected_results"][0]["conditions"][0]["expected"] = "not-a-tid"
    errors, _ = authoring.validate_env(env)
    assert any("technique expected" in e for e in errors)


def test_missing_procedure_id_rejected():
    env = copy.deepcopy(GOOD_ENV)
    env["procedure"].pop("id")
    errors, _ = authoring.validate_env(env)
    assert any("procedure.id" in e for e in errors)


def test_no_expected_results_rejected():
    errors, _ = authoring.validate_env(_clone(expected_results=[]))
    assert any("expected_results" in e for e in errors)


def test_bad_technique_pattern_rejected():
    errors, _ = authoring.validate_env(_clone(technique="1190"))
    assert any("technique 형식" in e for e in errors)


# ───────────── validate_env: 경고(거절 아님) ─────────────
def test_no_crown_warns_not_rejects():
    env = copy.deepcopy(GOOD_ENV)
    env["expected_results"] = [env["expected_results"][0]]   # progress 만
    errors, warnings = authoring.validate_env(env)
    assert errors == []
    assert any("크라운" in w for w in warnings)


def test_no_spine_warns():
    env = copy.deepcopy(GOOD_ENV)
    env.pop("cve"); env.pop("cwe")
    errors, warnings = authoring.validate_env(env)
    assert errors == []
    assert any("스파인" in w for w in warnings)


# ───────────── author_env: 이음새 → 게이트 ─────────────
def test_fake_author_template_passes_and_is_theoretical():
    env, problems = authoring.author_env({"cve": "CVE-2024-0001"}, authoring.FakeAuthor())
    assert env is not None, problems
    assert env["procedure"]["status"] == "THEORETICAL"
    assert env["cve"] == "CVE-2024-0001"


def test_author_env_forces_cve_from_context():
    # 저작기가 cve 를 빠뜨려도 파이프라인이 아는 값으로 채운다(스파인 정합)
    no_cve = copy.deepcopy(GOOD_ENV)
    no_cve.pop("cve")
    author = authoring.FakeAuthor(by_cve={"CVE-2017-5638": no_cve})
    env, problems = authoring.author_env({"cve": "CVE-2017-5638"}, author)
    assert env is not None, problems
    assert env["cve"] == "CVE-2017-5638"


def test_author_env_rejects_invalid():
    env, problems = authoring.author_env({"cve": "CVE-2024-9999"},
                                         authoring.FakeAuthor(default_valid=False))
    assert env is None
    assert problems


# ───────────── LlmAuthor: 코드펜스 JSON 왕복 ─────────────
def test_llm_author_parses_fenced_json():
    def _transport(method, url, body, timeout):   # OllamaClient transport 계약
        content = "여기 결과입니다:\n```json\n" + json.dumps(GOOD_ENV, ensure_ascii=False) + "\n```"
        return {"choices": [{"message": {"content": content}, "finish_reason": "stop"}]}

    client = OllamaClient("http://x/v1", "m", transport=_transport)
    env, problems = authoring.author_env({"cve": "CVE-2017-5638"}, authoring.LlmAuthor(client))
    assert env is not None, problems
    assert env["technique"] == "T1190"


def test_llm_author_garbage_rejected():
    def _transport(method, url, body, timeout):
        return {"choices": [{"message": {"content": "죄송하지만 JSON을 못 만들겠어요"},
                             "finish_reason": "stop"}]}

    client = OllamaClient("http://x/v1", "m", transport=_transport)
    env, problems = authoring.author_env({"cve": "CVE-2017-5638"}, authoring.LlmAuthor(client))
    assert env is None
    assert any("파싱 실패" in p for p in problems)


# ───────────── build_core_layer(source=llm): 신뢰수준 스탬프 ─────────────
def test_llm_build_stamps_validation_level():
    nodes, _ = build_core_layer({"environments": [GOOD_ENV]},
                                source="llm", validation_level="THEORETICAL")
    procs = [n for n in nodes if n["label"] == "Procedure"]
    ers = [n for n in nodes if n["label"] == "ExpectedResult"]
    assert procs and all(n["props"].get("validation_level") == "THEORETICAL" for n in procs)
    assert ers and all(n["props"].get("validation_level") == "THEORETICAL" for n in ers)
    assert any(n["label"] == "KnowledgeSource" and n["id"] == "KS-llm-authored" for n in nodes)


def test_curated_build_unchanged_no_stamp():
    # 기본(source=core)은 신뢰수준 속성 안 박음 — 기존 수기 저작 동작 그대로
    nodes, _ = build_core_layer({"environments": [GOOD_ENV]})
    procs = [n for n in nodes if n["label"] == "Procedure"]
    assert procs and all("validation_level" not in n["props"] for n in procs)
    assert any(n["label"] == "KnowledgeSource" and n["id"] == "KS-core-layer" for n in nodes)


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
    print("── 2단 자동 저작·검증 게이트 스모크 ──")
    sys.exit(_run())
