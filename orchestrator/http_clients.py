"""실 어댑터 — HTTP로 VM A/B와 통신하는 AttackerClient/DefenderClient 구현.

Protocol(clients.py) 뒤에 끼우는 실제 층. 설계 핵심: '봉투 wrap→전송→parse'의 순수
로직과 '실제 네트워크 전송'을 분리한다. transport(주입 가능한 콜백)만 교체하면 네트워크
없이 로직을 테스트할 수 있고, 실전에선 requests로 POST한다.

HTTP 계약(하네스 서버가 구현):
  POST {base}/{요청타입}   body=Envelope JSON   → 응답 Envelope JSON
    예: POST /attack_turn_start → attack_turn_result 봉투
        POST /defense_turn_start → defense_turn_result 봉투
        POST /replay_request → replay_result,  POST /state_query → state_query_result
  POST {base}/status       body={}             → agent_status 봉투
  인증: Authorization: Bearer <shared_token> (관리망 공유 토큰)
"""
from __future__ import annotations

from typing import Callable, Optional

from common.messages import (
    AgentStatus, AttackTurnResult, AttackTurnStart,
    DefenseTurnResult, DefenseTurnStart, Envelope, HealthCheck, HealthResult,
    Payload, ReplayRequest, ReplayResult, StateQuery, StateQueryResult,
    parse_envelope, wrap,
)

# transport: (url, envelope_dict, timeout_sec) -> response_dict
Transport = Callable[[str, dict, float], dict]

_REPLAY_TIMEOUT = 600.0   # 리플레이 재생은 길 수 있음(대본 전체 재실행)
_SHORT_TIMEOUT = 30.0     # 하트비트(/status)
_STATE_TIMEOUT = 120.0    # 상태질의·헬스 — verify 내부 revert 직후 VM B(k3s·방어자)가 재개 중이라 느림


def requests_transport(token: str = "") -> Transport:
    """기본 전송 — requests로 JSON POST. requests는 지연 import(미설치 시 호출 때만 에러)."""
    def _t(url: str, body: dict, timeout: float) -> dict:
        import requests  # 지연 import
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        resp = requests.post(url, json=body, headers=headers, timeout=timeout)
        resp.raise_for_status()
        return resp.json()
    return _t


class _BaseHttpClient:
    def __init__(self, base_url: str, *, token: str = "",
                 transport: Optional[Transport] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.transport = transport or requests_transport(token)

    def _post(self, payload: Payload, *, episode: int, round: int, timeout: float) -> Envelope:
        env = wrap(payload, episode=episode, round=round)
        resp = self.transport(f"{self.base_url}/{payload.MSG_TYPE.value}",
                              env.model_dump(mode="json"), timeout)
        return parse_envelope(resp)

    def _status(self) -> AgentStatus:
        resp = self.transport(f"{self.base_url}/status", {}, _SHORT_TIMEOUT)
        return parse_envelope(resp).payload_as(AgentStatus)


class HttpAttackerClient(_BaseHttpClient):
    """VM A(공격 하네스) HTTP 어댑터."""

    def attack_turn(self, start: AttackTurnStart, *, episode: int, round: int) -> AttackTurnResult:
        env = self._post(start, episode=episode, round=round,
                         timeout=start.time_limit_sec + _SHORT_TIMEOUT)
        return env.payload_as(AttackTurnResult)

    def replay(self, req: ReplayRequest, *, episode: int, round: int) -> ReplayResult:
        env = self._post(req, episode=episode, round=round, timeout=_REPLAY_TIMEOUT)
        return env.payload_as(ReplayResult)

    def status(self) -> AgentStatus:
        return self._status()


class HttpDefenderClient(_BaseHttpClient):
    """VM B(방어 하네스) HTTP 어댑터."""

    def defense_turn(self, start: DefenseTurnStart, *, episode: int, round: int) -> DefenseTurnResult:
        env = self._post(start, episode=episode, round=round,
                         timeout=start.time_limit_sec + _SHORT_TIMEOUT)
        return env.payload_as(DefenseTurnResult)

    def state_query(self, query: StateQuery, *, episode: int, round: int) -> StateQueryResult:
        env = self._post(query, episode=episode, round=round, timeout=_STATE_TIMEOUT)
        return env.payload_as(StateQueryResult)

    def health_check(self, hc: HealthCheck, *, episode: int, round: int) -> HealthResult:
        env = self._post(hc, episode=episode, round=round, timeout=_STATE_TIMEOUT)
        return env.payload_as(HealthResult)

    def status(self) -> AgentStatus:
        return self._status()


__all__ = ["Transport", "requests_transport", "HttpAttackerClient", "HttpDefenderClient"]
