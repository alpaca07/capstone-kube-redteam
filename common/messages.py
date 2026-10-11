"""공통 인터페이스 — 메시지 10종 스키마 (VM A/B/C HTTP 통신).

전송: HTTP(FastAPI). VM C = 중심 클라이언트(요청 주도), VM A·B = 서버(대기).
공통 봉투(Envelope): type + msg_id + episode + round + timestamp + payload (+ status).
인증: 관리망 격리라 공유 토큰 정도로 가볍게(스키마 밖, 헤더에서 처리).

========================= 메시지 10종 =========================
  attack_turn_start    C→A  공격 턴 시작   AttackTurnStart
  attack_turn_result   A→C  공격 결과+대본 AttackTurnResult
  defense_turn_start   C→B  방어 턴 시작   DefenseTurnStart   (공격정보 0)
  defense_turn_result  B→C  방어 결과      DefenseTurnResult
  replay_request       C→A  재생 요청      ReplayRequest
  replay_result        A→C  재생 결과      ReplayResult
  state_query          C→B  상태 질의      StateQuery
  state_query_result   B→C  상태 응답      StateQueryResult   (사실만)
  health_check         C→B  가용성 확인    HealthCheck / HealthResult
  agent_status         A/B→C 하트비트·에러  AgentStatus
==============================================================

정보 비대칭 (스키마에 박음 — 코드로 강제되는 설계):
- 공격 보고(A→C)는 상세해도 됨 — 받는 쪽이 심판(VM C)이라 god-view 유출 아님.
- 방어 턴 시작(C→B)엔 공격 정보가 **아예 없음** — 방어자는 관측으로 스스로 추론.
- state_query_result 는 '취약 조건의 사실 여부'만 — 그게 점수로 뭘 의미하는지는 VM C 판정.
리플레이 재생은 VM A가 수행(execute_action 로직 보유), VM C는 스냅샷만 맞추고 요청만 보냄.
"""
from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, ClassVar, Optional, TypeVar

from pydantic import BaseModel, Field

from .replay_schema import ReplayScript


# ───────────────────────── 메시지 타입 ─────────────────────────
class MsgType(str, Enum):
    ATTACK_TURN_START = "attack_turn_start"
    ATTACK_TURN_RESULT = "attack_turn_result"
    DEFENSE_TURN_START = "defense_turn_start"
    DEFENSE_TURN_RESULT = "defense_turn_result"
    REPLAY_REQUEST = "replay_request"
    REPLAY_RESULT = "replay_result"
    STATE_QUERY = "state_query"
    STATE_QUERY_RESULT = "state_query_result"
    HEALTH_CHECK = "health_check"
    AGENT_STATUS = "agent_status"


# ───────────────────────── 보조 열거형 ─────────────────────────
class AttackEndReason(str, Enum):
    FLAG = "flag"          # 값 기반 플래그(④) 획득 → 성공 종료
    TIMEOUT = "timeout"    # 제한시간 T 초과
    DEADEND = "deadend"    # 더 진행 못 함(막다른 길)
    ERROR = "error"        # 하네스/도구 오류


class DefenseEndReason(str, Enum):
    PATCHED = "patched"    # 패치 적용 완료
    TIMEOUT = "timeout"    # 제한시간 초과
    NOOP = "noop"          # 관측상 조치 불필요로 판단(오탐/무행동)
    ERROR = "error"


class ReplayPhase(str, Enum):
    PRE = "pre"            # 패치 전 재생(원래 통했나 재확인)
    POST = "post"          # 패치 후 재생(막혔나 확인) — 방어 성공 판정 핵심


class AgentRole(str, Enum):
    ATTACKER = "attacker"
    DEFENDER = "defender"


class AgentState(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    ERROR = "error"


# ───────────────────────── payload 베이스 ─────────────────────────
class Payload(BaseModel):
    """모든 payload의 베이스. MSG_TYPE으로 봉투 type을 자동 결정(둘이 어긋날 수 없음)."""
    MSG_TYPE: ClassVar[MsgType]


# ───────────────── ① attack_turn_start (C→A) ─────────────────
class Foothold(BaseModel):
    """첫 라운드에만 주는 발판. 이후 라운드엔 None(공격자는 직전 상태에서 이어감)."""
    attack_endpoint: str               # 공격망에서 본 대상 진입점(IP/호스트)
    notes: Optional[str] = None        # 최소한의 힌트만(과도한 정보 금지)


class AttackTurnStart(Payload):
    MSG_TYPE: ClassVar[MsgType] = MsgType.ATTACK_TURN_START
    time_limit_sec: int
    goal: str = "대상 클러스터에서 DB의 값 기반 FLAG 획득"
    flag_format: str = "FLAG{...}"     # 형식만 공개, 값·위치는 비공개
    foothold: Optional[Foothold] = None   # 첫 라운드만 채움


# ───────────────── ② attack_turn_result (A→C) ─────────────────
class FlagObtained(BaseModel):
    flag_id: str                       # 예: "4" (값 기반 ④)
    value: Optional[str] = None        # 실제 획득 문자열(값 기반일 때)
    step: Optional[int] = None         # 대본상 획득 스텝 번호


class AttackTurnResult(Payload):
    MSG_TYPE: ClassVar[MsgType] = MsgType.ATTACK_TURN_RESULT
    end_reason: AttackEndReason
    flags_obtained: list[FlagObtained] = Field(default_factory=list)
    replay_script: Optional[ReplayScript] = None   # ★ 검증 핵심(VM C가 재생 위임)
    attack_summary: str = ""           # 자연어 요약 — 심판(VM C) 기록용. 방어자엔 안 감.
    elapsed_sec: float = 0.0


# ───────────────── ③ defense_turn_start (C→B) ─────────────────
class DefenseTurnStart(Payload):
    """★ 공격 정보가 전혀 없음. 방어자는 감사로그·Falco·상태diff로만 추론한다."""
    MSG_TYPE: ClassVar[MsgType] = MsgType.DEFENSE_TURN_START
    time_limit_sec: int


# ───────────────── ④ defense_turn_result (B→C) ─────────────────
class Detection(BaseModel):
    """방어자가 관측에서 추론한 것 — 틀릴 수 있음(FN/FP 포함이 설계 의도)."""
    technique: Optional[str] = None    # 추정 MITRE 기법(예: "T1078")
    evidence: str = ""                 # 근거(로그 줄 등)
    confidence: Optional[float] = None  # 0~1


class PatchItem(BaseModel):
    kind: str                          # networkpolicy | rbac | secret | config ...
    target: str                        # 적용 대상(ns/리소스)
    manifest_ref: Optional[str] = None  # 적용한 매니페스트 경로/식별자
    summary: str = ""


class DefenseTurnResult(Payload):
    MSG_TYPE: ClassVar[MsgType] = MsgType.DEFENSE_TURN_RESULT
    patch_applied: bool
    end_reason: DefenseEndReason
    detected: list[Detection] = Field(default_factory=list)
    patch_set: list[PatchItem] = Field(default_factory=list)
    healthcheck_passed: bool = False   # 패치 후 서비스 정상?(과잉차단=서비스 죽이면 감점)
    elapsed_sec: float = 0.0


# ───────────────── ⑤ replay_request (C→A) ─────────────────
class ReplayRequest(Payload):
    MSG_TYPE: ClassVar[MsgType] = MsgType.REPLAY_REQUEST
    replay_script: ReplayScript
    phase: ReplayPhase
    target: Optional[str] = None       # 재생 대상 진입점(스냅샷 맞춘 상태 기준)


# ───────────────── ⑥ replay_result (A→C) ─────────────────
class StepReplayRec(BaseModel):
    """재생 시점의 스텝 결과(대본 기록용 StepResultRec와 구분)."""
    step: int
    exit_code: int = 0
    success: bool = False              # 이 스텝 성공 지표(판정 1순위)
    stdout_hash: Optional[str] = None  # 정규화 해시 — 기록본과 비교(판정 2순위)
    matched_baseline: Optional[bool] = None  # 기록본 해시와 일치?
    note: str = ""


class ReplayResult(Payload):
    MSG_TYPE: ClassVar[MsgType] = MsgType.REPLAY_RESULT
    phase: ReplayPhase
    steps_result: list[StepReplayRec] = Field(default_factory=list)
    overall_success: bool = False      # 체인 전체가 재현됐나
    flags_reached: list[str] = Field(default_factory=list)  # 재생으로 도달한 flag_id


# ───────────────── ⑦ state_query (C→B) ─────────────────
class StateCheck(BaseModel):
    check_id: str                      # 예: "2"(②), "3"(③) — 어느 취약점인지
    query: str                         # 방어자가 수행할 상태 조회(자연어/명령 식별자)
    expect: Optional[str] = None       # 참고용 기대값(판정은 VM C가 함)


class StateQuery(Payload):
    MSG_TYPE: ClassVar[MsgType] = MsgType.STATE_QUERY
    checks: list[StateCheck] = Field(default_factory=list)


# ───────────────── ⑧ state_query_result (B→C) ─────────────────
class StateCheckResult(BaseModel):
    check_id: str
    vulnerable: bool                   # 질의한 '취약 조건'의 사실 여부(점수 판정 아님)
    detail: str = ""                   # 근거(관측된 상태)


class StateQueryResult(Payload):
    MSG_TYPE: ClassVar[MsgType] = MsgType.STATE_QUERY_RESULT
    results: list[StateCheckResult] = Field(default_factory=list)


# ───────────────── ⑨ health_check (C→B) / 응답 ─────────────────
class HealthCheck(Payload):
    MSG_TYPE: ClassVar[MsgType] = MsgType.HEALTH_CHECK
    service: str                       # 확인할 서비스명 또는 "all"


class HealthResult(Payload):
    """health_check의 응답. 쌍 타입이 없어 같은 type 문자열을 재사용한다."""
    MSG_TYPE: ClassVar[MsgType] = MsgType.HEALTH_CHECK
    service: str
    healthy: bool
    response_time_ms: Optional[float] = None


# ───────────────── ⑩ agent_status (A/B→C) ─────────────────
class AgentStatus(Payload):
    MSG_TYPE: ClassVar[MsgType] = MsgType.AGENT_STATUS
    agent: AgentRole
    state: AgentState
    error: Optional[str] = None


# ───────────────────────── 봉투 & 헬퍼 ─────────────────────────
P = TypeVar("P", bound=Payload)


class Envelope(BaseModel):
    """모든 메시지를 감싸는 봉투. payload는 dict로 들고, payload_as로 꺼내 검증."""
    type: MsgType
    msg_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    episode: int = 0
    round: int = 0
    timestamp: float = Field(default_factory=time.time)
    payload: dict[str, Any] = Field(default_factory=dict)
    status: Optional[str] = None       # 응답 상태(ok|error 등). 요청엔 보통 None.

    def payload_as(self, model: type[P]) -> P:
        """payload를 지정 모델로 파싱. 봉투 type과 모델 MSG_TYPE 불일치면 에러."""
        if self.type != model.MSG_TYPE:
            raise ValueError(
                f"type mismatch: envelope={self.type.value} "
                f"but asked for {model.__name__}({model.MSG_TYPE.value})"
            )
        return model.model_validate(self.payload)


# type → '요청' payload 모델 (서버가 들어온 메시지를 디스패치할 때 사용).
# HEALTH_CHECK는 요청(HealthCheck)으로 등록 — 응답은 HealthResult로 직접 payload_as.
PAYLOAD_TYPE: dict[MsgType, type[Payload]] = {
    MsgType.ATTACK_TURN_START: AttackTurnStart,
    MsgType.ATTACK_TURN_RESULT: AttackTurnResult,
    MsgType.DEFENSE_TURN_START: DefenseTurnStart,
    MsgType.DEFENSE_TURN_RESULT: DefenseTurnResult,
    MsgType.REPLAY_REQUEST: ReplayRequest,
    MsgType.REPLAY_RESULT: ReplayResult,
    MsgType.STATE_QUERY: StateQuery,
    MsgType.STATE_QUERY_RESULT: StateQueryResult,
    MsgType.HEALTH_CHECK: HealthCheck,
    MsgType.AGENT_STATUS: AgentStatus,
}


def wrap(
    payload: Payload,
    *,
    episode: int = 0,
    round: int = 0,
    status: Optional[str] = None,
    msg_id: Optional[str] = None,
) -> Envelope:
    """payload를 봉투로 감싼다. type은 payload.MSG_TYPE에서 자동 — 수동 지정 불필요."""
    env = Envelope(
        type=payload.MSG_TYPE,
        episode=episode,
        round=round,
        payload=payload.model_dump(mode="json"),
        status=status,
    )
    if msg_id is not None:
        env.msg_id = msg_id
    return env


def parse_envelope(raw: dict[str, Any] | str | bytes) -> Envelope:
    """수신 JSON(dict/str/bytes)을 Envelope로. payload는 아직 dict — payload_as로 확정."""
    if isinstance(raw, (str, bytes)):
        return Envelope.model_validate_json(raw)
    return Envelope.model_validate(raw)


__all__ = [
    "MsgType",
    "AttackEndReason", "DefenseEndReason", "ReplayPhase", "AgentRole", "AgentState",
    "Payload",
    "Foothold", "AttackTurnStart",
    "FlagObtained", "AttackTurnResult",
    "DefenseTurnStart",
    "Detection", "PatchItem", "DefenseTurnResult",
    "ReplayRequest",
    "StepReplayRec", "ReplayResult",
    "StateCheck", "StateQuery",
    "StateCheckResult", "StateQueryResult",
    "HealthCheck", "HealthResult",
    "AgentStatus",
    "Envelope", "PAYLOAD_TYPE", "wrap", "parse_envelope",
]
