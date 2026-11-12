"""신규 CVE → 핵심층 env(④⑤) 자동 저작(2단, THEORETICAL) + 형식 검증 게이트.

사람 검수를 대신하는 '자동 관문 ①'. LLM 이 뽑은 env 를 build_core_layer 적재 계약·조건 문법
(orchestrator/objectives.py·sources.EVIDENCE_TYPES 와 정렬: operator eq|in|exists)에 순수하게
대본다. 통과한 env 만 THEORETICAL 로 KG 에 반영하고, 실제 신뢰(VERIFIED) 승격은 god-view 가
학습런에서 한다(자동 관문 ②). 즉 '형식이 맞나'는 여기서, '정말 통하나'는 공수 루프가 가른다.

- validate_env: 순수 함수. 네트워크·LLM 없이 테스트된다.
- Author: 저작기 이음새. 실전=LlmAuthor(DGX 모델) / 테스트=FakeAuthor.
- author_env: 저작 → 게이트 → (통과 env | None, 문제·경고). 저작기 오류·파싱 실패는 '거절'로 흡수.
"""
from __future__ import annotations

import re
from typing import Protocol

from common.app_signals import CROWN_TARGETS
from common.llm_json import LLMJsonError, extract_and_load

from .sources import EVIDENCE_TYPES

# --- 조건 문법 (objectives.py 닫힌목록과 정렬) --------------------------------
CHANNELS: frozenset[str] = frozenset(EVIDENCE_TYPES)          # crown/audit/falco/cluster_state
OPERATORS: frozenset[str] = frozenset({"eq", "in", "exists"})
_CONFIG_OPERATORS: frozenset[str] = frozenset({"eq", "in", "exists", "equals"})
CROWN_CHANNEL = "crown"
TECHNIQUE_CHANNELS: frozenset[str] = frozenset({"falco", "audit"})

_TID = re.compile(r"^T\d{4}(\.\d{3})?$")
_CVE = re.compile(r"^CVE-\d{4}-\d+$")
_CWE = re.compile(r"^CWE-\d+$")
_SLUG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def _slug(text: str) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", (text or "").strip().lower()).strip("-")
    return s or "cve"


# --- 검증 게이트 (순수) ------------------------------------------------------
def _crown_expected_problems(operator: str, expected) -> list[str]:
    if operator == "eq":
        return [] if expected in CROWN_TARGETS else [
            f"crown expected 는 크라운 상수 {list(CROWN_TARGETS)} 중 하나: {expected!r}"]
    if operator == "in":
        if not isinstance(expected, (list, tuple)) or not expected:
            return ["crown in 은 비지 않은 목록이어야 함"]
        bad = [e for e in expected if e not in CROWN_TARGETS]
        return [f"crown expected 에 크라운 상수 아닌 값: {bad}"] if bad else []
    return []  # exists 는 값 불요


def _technique_expected_problems(operator: str, expected) -> list[str]:
    if operator == "eq":
        return [] if isinstance(expected, str) and _TID.match(expected) else [
            f"technique expected 는 T####[.###]: {expected!r}"]
    if operator == "in":
        if not isinstance(expected, (list, tuple)) or not expected:
            return ["technique in 은 비지 않은 목록이어야 함"]
        bad = [e for e in expected if not (isinstance(e, str) and _TID.match(e))]
        return [f"technique expected 에 기법 ID 아닌 값: {bad}"] if bad else []
    return []


def _validate_condition(c) -> list[str]:
    if not isinstance(c, dict):
        return ["조건이 객체(dict) 아님"]
    probs: list[str] = []
    ch, op, field = c.get("channel"), c.get("operator"), c.get("field")
    if ch not in CHANNELS:
        probs.append(f"channel 미지원(닫힌목록 {sorted(CHANNELS)}): {ch!r}")
    if op not in OPERATORS:
        probs.append(f"operator 미지원({sorted(OPERATORS)}): {op!r}")
    if not field:
        probs.append("field 누락")
    if ch == CROWN_CHANNEL:
        if field != "asset":
            probs.append("crown 통로는 field=asset")
        probs += _crown_expected_problems(op, c.get("expected"))
    elif ch in TECHNIQUE_CHANNELS:
        if field != "technique":
            probs.append(f"{ch} 통로는 field=technique")
        probs += _technique_expected_problems(op, c.get("expected"))
    return probs


def validate_env(env) -> tuple[list[str], list[str]]:
    """env(핵심층 고수준 스키마)를 적재 계약·조건 문법에 대본다. → (errors, warnings).

    errors 가 비면 build_core_layer 가 안전하게 펼칠 수 있고 조건이 심판 문법에 맞는다(=반영 가능).
    warnings 는 반영은 되지만 쓸모를 떨어뜨리는 것(스파인 미연결·크라운 없음 등).
    """
    if not isinstance(env, dict):
        return ["env 가 객체(dict) 아님"], []
    errors: list[str] = []
    warnings: list[str] = []

    name = env.get("env")
    if not name or not _SLUG.match(str(name)):
        errors.append(f"env 이름 누락/형식오류: {name!r}")

    cve, cwe = env.get("cve"), env.get("cwe")
    if cve and not _CVE.match(str(cve)):
        errors.append(f"cve 형식오류: {cve!r}")
    if cwe and not _CWE.match(str(cwe)):
        errors.append(f"cwe 형식오류: {cwe!r}")
    if not cve and not cwe:
        warnings.append("cve·cwe 둘 다 없음 — 스파인(취약점·약점) 연결 안 됨")

    tech = env.get("technique")
    if tech and not _TID.match(str(tech)):
        errors.append(f"technique 형식오류(T####[.###] 아님): {tech!r}")
    elif not tech:
        warnings.append("technique 없음 — REALIZED_BY(기법→절차) 연결 안 됨")

    proc = env.get("procedure")
    if not isinstance(proc, dict):
        errors.append("procedure 누락")
    else:
        if not _SLUG.match(str(proc.get("id", ""))):
            errors.append(f"procedure.id 누락/형식오류: {proc.get('id')!r}")
        if not proc.get("name"):
            errors.append("procedure.name 누락")

    for i, pre in enumerate(env.get("preconditions") or []):
        if not isinstance(pre, dict) or not _SLUG.match(str(pre.get("id", ""))):
            errors.append(f"precondition[{i}].id 누락/형식오류")
            continue
        cfg = pre.get("config")
        if cfg is not None:
            if not cfg.get("key"):
                errors.append(f"precondition[{i}].config.key 누락")
            op = cfg.get("operator", "eq")
            if op not in _CONFIG_OPERATORS:
                errors.append(f"precondition[{i}].config.operator 미지원: {op!r}")

    ers = env.get("expected_results") or []
    if not ers:
        errors.append("expected_results 비어 있음(달성 조건 없음)")
    has_crown = False
    for i, er in enumerate(ers):
        if not isinstance(er, dict) or not _SLUG.match(str(er.get("id", ""))):
            errors.append(f"expected_results[{i}].id 누락/형식오류")
            continue
        if er.get("kind") not in ("crown", "progress"):
            errors.append(f"expected_results[{i}].kind 은 crown|progress: {er.get('kind')!r}")
        if er.get("kind") == "crown":
            has_crown = True
        out = er.get("outcome")
        if out is not None and not _SLUG.match(str(out.get("id", ""))):
            errors.append(f"expected_results[{i}].outcome.id 형식오류")
        conds = er.get("conditions") or []
        if not conds:
            errors.append(f"expected_results[{i}] 조건 없음")
        for j, c in enumerate(conds):
            errors += [f"expected_results[{i}].conditions[{j}]: {m}" for m in _validate_condition(c)]
    if ers and not has_crown:
        warnings.append("크라운(kind=crown) 결과 없음 — god-view 실증 승격 대상이 안 됨")

    return errors, warnings


# --- 저작기 이음새 -----------------------------------------------------------
class Author(Protocol):
    """신규 CVE 맥락 → 핵심층 env(dict). 실전=LlmAuthor / 테스트=FakeAuthor."""
    def draft(self, ctx: dict) -> dict: ...


SYSTEM_PROMPT = (
    "당신은 취약점 지식을 구조화하는 분석가다. 주어진 CVE 정보를 바탕으로, 공격 절차와 "
    "예상 결과를 아래 JSON 스키마로만 출력한다. 설명·코드펜스 없이 JSON 객체 하나만 낸다.\n"
    "\n"
    "스키마:\n"
    '{\n'
    '  "env": "<슬러그, 예: cve-2021-44228>",\n'
    '  "technique": "<MITRE 기법 ID, 예: T1190 또는 T1059. 익스플로잇 수법>",\n'
    '  "cve": "<CVE-YYYY-N>", "cwe": "<CWE-N, 선택>",\n'
    '  "procedure": {"id": "PROC-<env>-<수법>", "name": "<짧은 이름>", "description": "<어떻게 터지나>"},\n'
    '  "preconditions": [{"id": "PRE-<env>-<조건>", "name": "...", "description": "..."}],\n'
    '  "expected_results": [\n'
    '    {"id": "ER-<env>-progress", "kind": "progress",\n'
    '     "outcome": {"id": "AO-command-execution", "name": "명령 실행"},\n'
    '     "conditions": [{"channel": "falco", "field": "technique", "operator": "eq", "expected": "T1059"}]},\n'
    '    {"id": "ER-<env>-crown", "kind": "crown",\n'
    '     "outcome": {"id": "AO-data-exposure", "name": "민감 데이터 유출"},\n'
    '     "conditions": [{"channel": "crown", "field": "asset", "operator": "in",\n'
    '                     "expected": ["internal_secrets", "customers_pii"]}]}\n'
    '  ]\n'
    '}\n'
    "\n"
    "규칙(반드시 지킨다):\n"
    f"- channel 은 {sorted(CHANNELS)} 중에서만. operator 는 ['eq','in','exists'] 중에서만.\n"
    "- crown 통로: field='asset', expected 는 ['internal_secrets','customers_pii'] 안의 값(또는 그 부분목록).\n"
    "- falco/audit 통로: field='technique', expected 는 MITRE 기법 ID(T####[.###]).\n"
    "- 데이터 탈취·파일 유출로 이어질 수 있으면 kind='crown' 결과를 반드시 하나 넣는다.\n"
    "  명령 실행 등 중간 단계는 kind='progress' 로 둔다.\n"
    "- 모든 id 는 영문·숫자·.-_ 로만. 추측이 서지 않는 필드는 생략한다(빈 값 넣지 말 것)."
)


def build_user_prompt(ctx: dict) -> str:
    lines = [f"CVE: {ctx.get('cve', '')}"]
    if ctx.get("cwes"):
        lines.append(f"CWE: {', '.join(ctx['cwes'])}")
    if ctx.get("technique_candidates"):
        lines.append(f"후보 기법(참고, 확정 아님): {', '.join(ctx['technique_candidates'])}")
    if ctx.get("description"):
        lines.append(f"설명: {ctx['description']}")
    refs = ctx.get("references") or []
    if refs:
        lines.append("참조:")
        lines += [f"  - {r}" for r in refs[:8]]
    return "\n".join(lines)


class LlmAuthor:
    """DGX 모델(common.llm_client.OllamaClient 호환)로 env 를 뽑는다. JSON 추출은 공유 모듈."""

    def __init__(self, client, *, max_tokens: int = 2048) -> None:
        self.client = client
        self.max_tokens = max_tokens

    def draft(self, ctx: dict) -> dict:
        text = self.client.chat_text(SYSTEM_PROMPT, build_user_prompt(ctx),
                                     max_tokens=self.max_tokens)
        return extract_and_load(text)   # 실패 시 LLMJsonError → author_env 가 '거절'로 흡수


def _template_env(cve: str) -> dict:
    """테스트·폴백용 최소 유효 env(순수 RCE 틀: 진행도 T1059 + 크라운 호스트파일 read T1611)."""
    env = _slug(cve)
    return {
        "env": env, "technique": "T1190", "cve": cve or None,
        "procedure": {"id": f"PROC-{env}-rce", "name": f"{cve} 원격 명령 실행",
                      "description": "취약 엔드포인트로 컨테이너에서 임의 명령을 실행한다."},
        "preconditions": [{"id": f"PRE-{env}-vuln-version", "name": "취약 버전 + 엔드포인트 접근",
                           "description": "취약 버전이 배포돼 있고 공격 엔드포인트에 도달 가능."}],
        "expected_results": [
            {"id": f"ER-{env}-progress", "kind": "progress",
             "outcome": {"id": "AO-command-execution", "name": "명령 실행"},
             "conditions": [{"channel": "falco", "field": "technique", "operator": "eq",
                             "expected": "T1059"}]},
            {"id": f"ER-{env}-crown", "kind": "crown",
             "outcome": {"id": "AO-data-exposure", "name": "민감 데이터 유출"},
             "conditions": [{"channel": "falco", "field": "technique", "operator": "eq",
                             "expected": "T1611"}]},
        ],
    }


class FakeAuthor:
    """테스트용 저작기. by_cve 사전에 있으면 그 env, 없으면 최소 유효 틀(default_valid=False 면 무효)."""

    def __init__(self, by_cve: dict | None = None, *, default_valid: bool = True) -> None:
        self.by_cve = by_cve or {}
        self.default_valid = default_valid

    def draft(self, ctx: dict) -> dict:
        cve = ctx.get("cve", "")
        if cve in self.by_cve:
            return self.by_cve[cve]
        if not self.default_valid:
            return {"env": "", "procedure": {}}   # 게이트에서 걸릴 무효 env
        return _template_env(cve)


def author_env(ctx: dict, author: Author) -> tuple[dict | None, list[str]]:
    """저작 → 게이트. (통과 env | None, 문제/경고). 저작기 예외·파싱 실패는 '거절'로 흡수.

    파이프라인이 사실로 아는 값(cve)은 LLM 추측보다 우선해 스파인 정합을 지키고,
    procedure.status 를 THEORETICAL 로 못박아 '제안' 지식임을 표시한다(실증 전).
    """
    try:
        env = author.draft(ctx)
    except LLMJsonError as e:
        return None, [f"JSON 파싱 실패: {e}"]
    except Exception as e:   # noqa: BLE001 — 저작기 내부 오류가 파이프라인을 죽이지 않게
        return None, [f"저작 오류 {type(e).__name__}: {e}"]

    if not isinstance(env, dict):
        return None, ["저작 결과가 객체(dict) 아님"]
    env.setdefault("env", _slug(ctx.get("cve", "")))
    if ctx.get("cve"):
        env["cve"] = ctx["cve"]
    if isinstance(env.get("procedure"), dict):
        env["procedure"]["status"] = "THEORETICAL"

    errors, warnings = validate_env(env)
    if errors:
        return None, errors
    return env, warnings


__all__ = [
    "CHANNELS", "OPERATORS", "CROWN_CHANNEL", "TECHNIQUE_CHANNELS",
    "validate_env", "Author", "LlmAuthor", "FakeAuthor", "author_env",
    "SYSTEM_PROMPT", "build_user_prompt",
]
