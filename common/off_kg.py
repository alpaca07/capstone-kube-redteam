"""off_kg.py — off-KG 공격 포획 저널 스키마 (v1.1)

VM C(오케스트레이터)가 라운드마다, 플래너가 KG에 없는 지식으로 자력 구성한 의도
(off-KG intent)에 대해 off_kg.jsonl 에 레코드 한 줄을 남긴다. 개발기에서
knowledge/promote.py 가 이 저널을 읽어 지식 그래프로 승격한다.

신뢰 경계:
  hint, attacker_claim = 공격자 자기보고 (비신뢰, 힌트)
  godview              = 심판 god-view 관측 (신뢰)
  procedure            = replay 기록 (실행 사실)

v1.1: 실제 common/replay_schema.py·attacker/planner.py 타입에 맞춤
  - ProcStep: args(list)·step_id·payload_ref·determinism(3값 문자열)·result.exit_code
  - Trigger.applicability: 문자열 high|medium|low (플래너 1차 선별값), off-KG는 보통 None
"""
from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Callable, Optional, Union

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1.1"


class Outcome(str, Enum):
    CROWN = "CROWN"              # 심판이 크라운(민감자산 실제 침해) 확인
    PROGRESS = "PROGRESS"        # 심판이 절차 효과(진행도) 확인, 크라운 미달
    UNCONFIRMED = "UNCONFIRMED"  # 공격자 주장만, 심판 미확인
    FAILED = "FAILED"            # 절차 실패·포기


class Anchor(BaseModel):
    label: str                  # KG 라벨 (예: CVE, Technique)
    id: str


class Trigger(BaseModel):        # 플래너 출처 — 왜 off-KG였나
    applicability: Optional[str] = None   # 1차 선별값 high|medium|low. off-KG는 선별 밖이라 보통 None
    missing_info: list[str] = Field(default_factory=list)  # 예: ["kg_procedure_lookup empty for T1059"]
    reason: str = ""            # 의도 요약 + off-KG 근거
    selected_anchor: Optional[Anchor] = None   # 앵커됐으면 그 KG 노드(없으면 None)


class Target(BaseModel):         # 자산 그래프 출처(VM A에서 실어 보냄) — 지식 결속점
    cpe: Optional[str] = None    # 자산 앵커의 CPE. 미식별 자산이면 None
    service_type: Optional[str] = None   # 자산 kind
    endpoint: str = ""           # 자산명/엔드포인트
    preconditions: list[str] = Field(default_factory=list)


class Hint(BaseModel):           # 공격자 자기보고 — 비신뢰
    technique_id: Optional[str] = None   # 플래너가 붙인 기법(KG 미선별 = off-KG 핵심)
    cve: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)


class StepResult(BaseModel):     # replay_schema.StepResultRec 미러
    exit_code: int = 0
    success: bool = False        # 판정 1순위 지표
    stdout_hash: Optional[str] = None
    excerpt: str = ""            # StepResultRec.stdout_excerpt


class ProcStep(BaseModel):       # replay_schema.Step 미러 — Procedure(④) 원재료
    step: int
    step_id: str = ""            # "{round}.{step}" — fact 노드가 가리키는 포인터(의도↔스텝 조인키)
    tool: str
    args: list[str] = Field(default_factory=list)   # 동적값은 {name} 템플릿
    payload_ref: Optional[str] = None               # 큰 페이로드 파일 고정 경로
    inputs: list[str] = Field(default_factory=list)   # InputRef 키 이름들(의존 요약)
    produces: list[str] = Field(default_factory=list)  # ProducesRef 키 이름들
    determinism: str = "deterministic"              # deterministic|depends_on_prior|nondeterministic
    result: StepResult = Field(default_factory=StepResult)


class ReplayRef(BaseModel):
    session_id: str
    episode: int
    round: int


class Procedure(BaseModel):      # replay 기록 — Procedure(④) 원재료
    replay_ref: ReplayRef
    steps: list[ProcStep] = Field(default_factory=list)


class AttackerClaim(BaseModel):  # 비신뢰
    reached_flag: bool = False
    claimed_outcome: str = ""


class GodView(BaseModel):        # 심판 — 신뢰
    confirmed: bool = False
    progress_stages: list[str] = Field(default_factory=list)   # 확인된 킬체인 단계 "1".."4"
    crown: bool = False
    techniques_observed: list[str] = Field(default_factory=list)
    evidence_channels: list[str] = Field(default_factory=list)  # audit/falco/db_app_log/state_query/value_match


class RecordId(BaseModel):
    run_id: str
    episode: int
    round: int
    intent_id: str              # 탐색 그래프 intent 노드 id(정수를 문자열로)
    ts: str                     # RFC3339
    attacker_model: str


class OffKgRecord(BaseModel):
    schema_version: str = SCHEMA_VERSION
    id: RecordId
    trigger: Trigger
    target: Target
    hint: Hint = Field(default_factory=Hint)
    procedure: Procedure
    attacker_claim: AttackerClaim = Field(default_factory=AttackerClaim)
    godview: GodView = Field(default_factory=GodView)
    outcome: Outcome

    def to_jsonl(self) -> str:
        return self.model_dump_json()


def derive_outcome(godview: GodView, proc_failed: bool) -> Outcome:
    """심판 관측 우선 — 크라운 > 진행도 > (실패|미확인). 공격자 주장 아님."""
    if godview.crown:
        return Outcome.CROWN
    if godview.confirmed:
        return Outcome.PROGRESS
    return Outcome.FAILED if proc_failed else Outcome.UNCONFIRMED


def procstep_from_replay(s) -> ProcStep:
    """replay_schema.Step(덕타이핑) → ProcStep. common.replay_schema 임포트 없이 변환."""
    r = s.result
    return ProcStep(
        step=s.step,
        step_id=getattr(s, "step_id", "") or "",
        tool=s.command.tool,
        args=list(s.command.args),
        payload_ref=getattr(s.command, "payload_ref", None),
        inputs=list(s.inputs.keys()),
        produces=list(s.produces.keys()),
        determinism=getattr(s.determinism, "value", str(s.determinism)),
        result=StepResult(exit_code=getattr(r, "exit_code", 0), success=r.success,
                          stdout_hash=getattr(r, "stdout_hash", None),
                          excerpt=getattr(r, "stdout_excerpt", "")),
    )


def build_off_kg_record(
    *,
    rec_id: RecordId,
    trigger: Trigger,
    target: Target,
    hint: Hint,
    procedure: Procedure,
    attacker_claim: AttackerClaim,
    godview: GodView,
    proc_failed: bool,
) -> OffKgRecord:
    """순수 조립 — outcome은 심판 관측에서 파생."""
    return OffKgRecord(
        id=rec_id, trigger=trigger, target=target, hint=hint,
        procedure=procedure, attacker_claim=attacker_claim,
        godview=godview, outcome=derive_outcome(godview, proc_failed),
    )


# --- 싱크 (scorer.py 패턴: 테스트=리스트 / 실전=jsonl 파일) ---
OffKgSink = Callable[[OffKgRecord], None]


def jsonl_file_sink(path: Union[str, Path]) -> OffKgSink:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)

    def _sink(record: OffKgRecord) -> None:
        with p.open("a", encoding="utf-8") as f:
            f.write(record.to_jsonl() + "\n")

    return _sink


def list_sink(bucket: list) -> OffKgSink:
    def _sink(record: OffKgRecord) -> None:
        bucket.append(record)

    return _sink


def read_journal(path: Union[str, Path]) -> list[OffKgRecord]:
    """개발기 승격(knowledge/promote.py)이 쓰는 로더."""
    p = Path(path)
    if not p.exists():
        return []
    out: list[OffKgRecord] = []
    with p.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                out.append(OffKgRecord.model_validate_json(line))
    return out
