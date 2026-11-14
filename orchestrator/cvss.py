"""CVSS v3.1 Base 점수 — 공인 심각도 산식(FIRST.org 사양 그대로).

발견(침해)의 위험도를 '우리만의 기준'이 아니라 업계 표준으로 매기기 위한 모듈.
심판이 god-view 관측(어떤 자산이 어떤 영향으로 침해됐나)을 아래 8개 Base 메트릭으로
매핑하면, 이 모듈이 0–10 점수와 Low/Medium/High/Critical 등급·벡터 문자열을 산출한다.

메트릭(값):
  AV 공격 벡터        N(네트워크)·A(인접)·L(로컬)·P(물리)
  AC 공격 복잡도      L(낮음)·H(높음)
  PR 필요 권한        N(없음)·L(낮음)·H(높음)
  UI 사용자 상호작용   N(불필요)·R(필요)
  S  범위(Scope)      U(불변)·C(변경 — 다른 보안 권한 범위로 확대)
  C/I/A 기밀·무결·가용 N(없음)·L(낮음)·H(높음)

산식은 CVSS v3.1 명세 §7(공식 Roundup 포함)을 따른다.
"""
from __future__ import annotations

import math
from dataclasses import dataclass

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}   # Scope Unchanged
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.50}   # Scope Changed(권한 가중 상향)
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"N": 0.0, "L": 0.22, "H": 0.56}


def _roundup(x: float) -> float:
    """CVSS v3.1 공식 Roundup — 소수 1자리 '올림'(부동소수 오차 없이 정수 연산)."""
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def base_score(*, av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="N") -> float:
    """CVSS v3.1 Base 점수(0.0–10.0)."""
    iss = 1 - (1 - _CIA[c]) * (1 - _CIA[i]) * (1 - _CIA[a])   # Impact Sub-Score
    if s == "U":
        impact = 6.42 * iss
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    pr_w = (_PR_C if s == "C" else _PR_U)[pr]
    expl = 8.22 * _AV[av] * _AC[ac] * pr_w * _UI[ui]
    if impact <= 0:
        return 0.0
    if s == "U":
        return _roundup(min(impact + expl, 10))
    return _roundup(min(1.08 * (impact + expl), 10))


def severity_of(score: float) -> str:
    """CVSS v3.1 정성 등급(qualitative rating scale)."""
    if score <= 0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def vector_string(*, av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="N") -> str:
    return f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{s}/C:{c}/I:{i}/A:{a}"


@dataclass(frozen=True)
class CvssResult:
    score: float
    severity: str
    vector: str

    def to_dict(self) -> dict:
        return {"score": self.score, "severity": self.severity, "vector": self.vector}


def score(*, av="N", ac="L", pr="N", ui="N", s="U", c="N", i="N", a="N") -> CvssResult:
    """메트릭 → 점수·등급·벡터 한 번에."""
    kw = dict(av=av, ac=ac, pr=pr, ui=ui, s=s, c=c, i=i, a=a)
    sc = base_score(**kw)
    return CvssResult(score=sc, severity=severity_of(sc), vector=vector_string(**kw))


__all__ = ["base_score", "severity_of", "vector_string", "score", "CvssResult"]
