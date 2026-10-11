"""상태조회 핸들러 — VM C의 state_query 처리. 사실만, LLM 없음.

VM C가 "이 취약 조건이 지금 존재하나?"(check_id별)를 물으면, 클러스터 상태를 조회해
vulnerable: true/false 사실만 돌려준다. 그게 점수로 뭘 의미하는지의 판정은 VM C.

킬체인 상태검증(god-view가 재생 불가 시 쓰는 안전망):
  ① 크레덴셜 유출: 설정/위키에 접속문자열이 아직 노출돼 있나
  ② 과권한 SA:    admin-sa가 여전히 클러스터 전역 secret get 가능한가
  ③ 측면이동:      database NS에 ingress 제한 NetworkPolicy가 없나

조회 불가/미지원 check는 결과에서 생략 → VM C가 '응답 누락'으로 보고 INCONCLUSIVE 처리.
상태 읽기(I/O)는 ClusterReader 주입 → fake 테스트.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from common.messages import StateCheckResult, StateQuery, StateQueryResult

ADMIN_SA = "system:serviceaccount:internal:admin-sa"


@runtime_checkable
class ClusterReader(Protocol):
    """상태 조회 이음새(읽기 전용). 실 구현=kubectl, 테스트=fake."""

    def can_i(self, verb: str, resource: str, *, as_user: str = "",
              all_namespaces: bool = False, namespace: str = "") -> bool:
        ...

    def get(self, kind: str, *, namespace: str = "", name: str = "") -> list:
        """리소스 목록(dict들). 없으면 빈 리스트."""
        ...

    def find_text(self, needle: str, *, kinds: list[str], namespaces: list[str]) -> bool:
        """지정 리소스들의 내용에 needle 문자열이 있나(크레덴셜 노출 탐지용)."""
        ...


# check_id → (vulnerable, detail) 판정 함수
def _check_cred_leak(c: ClusterReader) -> tuple[bool, str]:
    leaked = c.find_text("postgresql://", kinds=["configmap"],
                         namespaces=["internal", "backend"])
    return leaked, f"configmap에 DB 접속문자열 노출 = {leaked}"


def _check_overperm_sa(c: ClusterReader) -> tuple[bool, str]:
    v = c.can_i("get", "secrets", as_user=ADMIN_SA, all_namespaces=True)
    return v, f"admin-sa 클러스터 전역 secret get = {v}"


def _check_netpol_absent(c: ClusterReader) -> tuple[bool, str]:
    nps = c.get("networkpolicy", namespace="database")
    absent = len(nps) == 0
    return absent, f"database NetworkPolicy {len(nps)}개 (부재={absent})"


STATE_CHECKS = {
    "1": _check_cred_leak,
    "2": _check_overperm_sa,
    "3": _check_netpol_absent,
}


class StateQueryHandler:
    def __init__(self, cluster: ClusterReader) -> None:
        self.cluster = cluster

    def handle(self, query: StateQuery) -> StateQueryResult:
        results: list[StateCheckResult] = []
        for chk in query.checks:
            fn = STATE_CHECKS.get(chk.check_id)
            if fn is None:
                continue                      # 미지원 → 생략(VM C가 INCONCLUSIVE)
            try:
                vuln, detail = fn(self.cluster)
            except Exception as e:            # noqa: BLE001 — 조회 실패 → 생략(불능)
                continue
            results.append(StateCheckResult(check_id=chk.check_id, vulnerable=vuln, detail=detail))
        return StateQueryResult(results=results)


__all__ = ["ClusterReader", "STATE_CHECKS", "StateQueryHandler", "ADMIN_SA"]
