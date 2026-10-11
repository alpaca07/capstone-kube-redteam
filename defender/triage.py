"""LLM 트리아지 결과 모델 + 파서 — 일반(정렬) 모델의 진단 출력을 구조화.

방어 LLM은 {assessment, detected:[{type,mitre,evidence}], severity, patch_plan:[{action,
target,detail}]} JSON을 뱉는다. 지저분한 출력의 JSON 추출은 common.llm_json(공유)에 맡기고,
여기선 트리아지 구조로 매핑한다. 위협 없으면 detected=[].

파싱은 관대하게(severity 오타·동의어 흡수, 누락 필드 기본값) — 방어자 진단은 자연어 성격이라
구조가 조금 어긋나도 뽑을 수 있는 건 뽑는다. 단 detected/patch_plan 항목이 객체가 아니면
재시도(ParseError). LLM 호출·파이프라인 배선은 다음 단계(triage 파이프라인)에서.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Protocol

from common.llm_json import LLMJsonError, extract_json_object, loads_lenient
from .filter import SituationReport

ParseError = LLMJsonError


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


def _coerce_severity(raw: object) -> Severity:
    """low/medium/high + 동의어 흡수. 알 수 없으면 MEDIUM(보수적)."""
    s = str(raw).strip().lower()
    if s in ("low", "info", "informational", "none", "낮음"):
        return Severity.LOW
    if s in ("high", "critical", "crit", "severe", "높음"):
        return Severity.HIGH
    if s in ("medium", "moderate", "med", "중간"):
        return Severity.MEDIUM
    return Severity.MEDIUM


@dataclass
class DetectedThreat:
    type: str                          # 공격 유형(자유 서술, 예: container_escape)
    mitre: Optional[str] = None        # MITRE 기법 ID(예: T1078) — 탐지 채점에 쓰임
    evidence: str = ""                 # 근거(로그 줄 등)


@dataclass
class PatchStep:
    action: str                        # restrict_rbac | add_networkpolicy | delete_pod | rotate_secret ...
    target: str = ""                   # 적용 대상(sa/web-app, ns/database ...)
    detail: str = ""


@dataclass
class TriageResult:
    assessment: str
    detected: list[DetectedThreat] = field(default_factory=list)
    severity: Severity = Severity.LOW
    patch_plan: list[PatchStep] = field(default_factory=list)
    raw: str = ""

    def has_threat(self) -> bool:
        return len(self.detected) > 0

    def techniques(self) -> list[str]:
        """탐지가 매핑한 MITRE 기법들(중복 제거, 순서 유지) — 채점용 detected[]."""
        out: list[str] = []
        for d in self.detected:
            if d.mitre and d.mitre not in out:
                out.append(d.mitre)
        return out


def parse_triage(text: str) -> TriageResult:
    """방어 LLM 출력 → TriageResult. 실패 시 ParseError(재시도용)."""
    obj = loads_lenient(extract_json_object(text))
    if not isinstance(obj, dict):
        raise ParseError("최상위가 객체가 아님")

    assessment = str(obj.get("assessment", ""))
    severity = _coerce_severity(obj.get("severity", "low"))

    detected: list[DetectedThreat] = []
    for d in (obj.get("detected") or []):
        if not isinstance(d, dict):
            raise ParseError(f"detected 항목이 객체가 아님: {d!r}")
        mitre = d.get("mitre")
        detected.append(DetectedThreat(
            type=str(d.get("type", "unknown")),
            mitre=str(mitre) if mitre else None,
            evidence=str(d.get("evidence", ""))))

    patch_plan: list[PatchStep] = []
    for p in (obj.get("patch_plan") or []):
        if not isinstance(p, dict):
            raise ParseError(f"patch_plan 항목이 객체가 아님: {p!r}")
        patch_plan.append(PatchStep(
            action=str(p.get("action", "")),
            target=str(p.get("target", "")),
            detail=str(p.get("detail", ""))))

    return TriageResult(assessment=assessment, detected=detected,
                        severity=severity, patch_plan=patch_plan, raw=text)


class _LLM(Protocol):
    def chat_text(self, system: str, user: str, **kw) -> str:
        ...


class Triager:
    """상황 보고서 → LLM 진단 → TriageResult. 파싱 실패 시 재시도, 끝내 실패면 안전 기본값.

    llm: chat_text(system, user)를 가진 것(OllamaClient 등). 프롬프트는 호출자가 로드해 주입.
    """

    def __init__(self, llm: _LLM, system_prompt: str, *, max_retries: int = 2) -> None:
        self.llm = llm
        self.system_prompt = system_prompt
        self.max_retries = max_retries

    def triage(self, report: SituationReport) -> TriageResult:
        base = json.dumps(report.to_prompt_dict(), ensure_ascii=False)
        user = base
        last: Optional[Exception] = None
        for _ in range(self.max_retries + 1):
            text = self.llm.chat_text(self.system_prompt, user)
            try:
                return parse_triage(text)
            except ParseError as e:                 # 로컬 모델 JSON 불안정 → 재시도
                last = e
                user = base + "\n\n(이전 응답이 유효한 JSON이 아니었습니다. 지정된 JSON 형식으로만 응답하세요.)"
        # 끝내 못 파싱 → 안전 기본값(탐지·패치 없음). 과잉조치보다 무행동이 안전.
        return TriageResult(assessment=f"트리아지 파싱 실패: {last}", severity=Severity.LOW)


__all__ = ["Severity", "DetectedThreat", "PatchStep", "TriageResult",
           "ParseError", "parse_triage", "Triager"]
