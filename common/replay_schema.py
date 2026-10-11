"""replay_script 스키마 + 검증 유틸 — "검증 불능 예방"의 핵심.

공격 하네스(execute_action)가 실행과 동시에 기록하고, 오케스트레이터(verifier)가
VM A에 재생을 위임한다. VM C는 이 대본만 보고 "이해 없이" 재현 가능해야 한다.

구조:
  ReplayScript{ session_id, episode, round, base_snapshot, steps[] }
  Step{ step, command, inputs, produces, result, flag_check, determinism }

핵심 메커니즘:
- inputs/produces 로 동적값(토큰 등) 의존성 재실행 — 녹음된 만료 토큰 대신
  재생 중 선행 스텝에서 새로 얻은 값을 주입한다(3중 그물 ① 예방).
- determinism 등급은 LLM이 아니라 코드가 규칙 기반으로 판정. 애매하면 보수적으로
  nondeterministic → ② 상태검증으로 라우팅.
- 판정 우선순위: ① success 지표(불린) → ② 정규화 해시(노이즈 마스킹) → ③ 상태검증.
  해시는 '정규화된 stdout'에만 건다(타임스탬프·랜덤ID 등 변동요소 제거 후).
"""
from __future__ import annotations

import hashlib
import re
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


# ───────────────────────── 열거형 ─────────────────────────
class ExtractMethod(str, Enum):
    JSONPATH = "jsonpath"   # 구조화 출력(-o json)에서 의미 필드만 — 재현 안정성 우선
    REGEX = "regex"
    FULL = "full"           # 전체 stdout 사용


class InputSource(str, Enum):
    STEP_OUTPUT = "step_output"   # 선행 스텝 결과에서 추출(동적 의존)
    STATIC = "static"             # 고정값
    FOOTHOLD = "foothold"         # 오케스트레이터가 준 발판 값


class Determinism(str, Enum):
    DETERMINISTIC = "deterministic"       # 그대로 재생 가능
    DEPENDS_ON_PRIOR = "depends_on_prior" # 선행 스텝 동적값 주입하면 재생 가능
    NONDETERMINISTIC = "nondeterministic" # 재생 불가 → 상태검증으로


# ───────────────────────── 모델 ─────────────────────────
class Extract(BaseModel):
    method: ExtractMethod = ExtractMethod.JSONPATH
    path: Optional[str] = None   # jsonpath 식 또는 regex 패턴. FULL이면 None.


class InputRef(BaseModel):
    """동적값 의존관계 하나."""
    source: InputSource
    from_step: Optional[int] = None    # STEP_OUTPUT일 때 참조할 스텝 번호
    extract: Optional[Extract] = None  # STEP_OUTPUT일 때 추출 방법
    value: Optional[str] = None        # STATIC/FOOTHOLD일 때 값


class ProducesRef(BaseModel):
    """이 스텝이 산출해 다음 스텝이 참조할 값의 추출법."""
    extract: Extract


class Command(BaseModel):
    tool: str                          # kubectl / nmap / curl / psql / sh ...
    args: list[str] = Field(default_factory=list)
    payload_ref: Optional[str] = None  # 큰 페이로드는 파일로 고정(예: payloads/step7.yaml)


class StepResultRec(BaseModel):
    """baseline 기록용(원래 통했나). 재생 결과(ReplayResult)와는 별개."""
    exit_code: int = 0
    success: bool = False              # ★ 판정 1순위 지표
    stdout_hash: Optional[str] = None  # 정규화된 stdout의 sha256 (보조 비교)
    stdout_excerpt: str = ""           # 판정 근거 발췌
    stdout_full: Optional[str] = None  # 플래그 등 중요 스텝만


class FlagCheck(BaseModel):
    flag_id: str
    obtained: bool = False


class Step(BaseModel):
    step: int
    command: Command
    inputs: dict[str, InputRef] = Field(default_factory=dict)
    produces: dict[str, ProducesRef] = Field(default_factory=dict)
    result: StepResultRec = Field(default_factory=StepResultRec)
    flag_check: Optional[FlagCheck] = None
    determinism: Determinism = Determinism.DETERMINISTIC


class ReplayScript(BaseModel):
    session_id: str
    episode: int
    round: int
    base_snapshot: Optional[str] = None
    steps: list[Step] = Field(default_factory=list)


# ───────────────── 정규화 & 해시 (해시 노이즈 대응) ─────────────────
# 해시 걸기 전에 run마다 바뀌는 변동요소를 마스킹 → 같은 '성공'이면 해시도 같아짐.
_NORMALIZERS: list[tuple[re.Pattern, str]] = [
    # ISO8601 타임스탬프 (creationTimestamp 등)
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?"), "<TS>"),
    # UUID (k8s uid 등)
    (re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "<UUID>"),
    # JWT / 서비스어카운트 토큰
    (re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "<JWT>"),
    # 긴 hex 토큰(32자+) — 랜덤 토큰·해시값
    (re.compile(r"\b[0-9a-f]{32,}\b"), "<HEX>"),
    # k8s resourceVersion
    (re.compile(r'("resourceVersion"\s*:\s*)"\d+"'), r'\1"<RV>"'),
    # IPv4
    (re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b"), "<IP>"),
]


def normalize_output(text: str) -> str:
    """stdout의 변동요소(타임스탬프·UUID·토큰·IP·resourceVersion)를 마스킹."""
    if not text:
        return ""
    out = text
    for pat, repl in _NORMALIZERS:
        out = pat.sub(repl, out)
    # 끝 공백/개행 정리(라인별 rstrip)
    return "\n".join(line.rstrip() for line in out.splitlines()).strip()


def hash_normalized(text: str) -> str:
    """정규화 후 sha256. 비교용 3벌(원본·pre·post)에 동일 적용."""
    return "sha256:" + hashlib.sha256(normalize_output(text).encode("utf-8")).hexdigest()


# ───────────────── determinism 규칙 기반 판정 ─────────────────
# 출력이 run마다 내재적으로 바뀌는(입력 주입으로도 못 잡는) 도구/인자.
_NONDET_TOOLS = {"date", "uuidgen", "openssl"}  # openssl rand 등
_NONDET_ARG_HINTS = ("rand", "random", "--now", "$random")


def classify_determinism(command: Command, inputs: dict[str, InputRef]) -> Determinism:
    """LLM이 아니라 코드가 규칙으로 판정. 애매하면 보수적으로 NONDETERMINISTIC.

    우선순위: 내재적 비결정 > 선행 의존 > 결정적.
    """
    joined = (command.tool + " " + " ".join(command.args)).lower()
    if command.tool.lower() in _NONDET_TOOLS or any(h in joined for h in _NONDET_ARG_HINTS):
        return Determinism.NONDETERMINISTIC
    if any(ref.source == InputSource.STEP_OUTPUT for ref in inputs.values()):
        return Determinism.DEPENDS_ON_PRIOR
    return Determinism.DETERMINISTIC
