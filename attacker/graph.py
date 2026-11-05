"""탐색 그래프 이음새(seam) — 공격 하네스가 '의도·사실·발견'을 쌓고 읽는 계약.

ARTEX의 exploration 그래프를 차용: 노드 kind(goal/intent/fact/finding/hint)와
관계 rel(spawns/derived_from/yields/proves), 그리고 의도의 상태머신. 이 파일은
'계약(작은 인터페이스)'만 정의한다. 실제 저장은 두 구현이 이 계약을 만족한다:
  - 인메모리 fake: 테스트·오프라인 (attacker/graph_fake.py, 이 조각)
  - 실 Neo4j 어댑터: 단일 DB에 라벨로 3그래프 공존 (다음 단계)

핵심 설계(이번 세션 확정):
  · 플래너만 intent 생성자 → frontier(열린 intent 큐) → 워커 N이 claim해 실행
  · claim_next는 '원자적' 계약 — 두 워커가 같은 의도를 집지 못한다.
    ARTEX도 CAS(`WHERE state='open'` 조건부 갱신, 영향행=1이면 성공)로 구현.
    fake는 같은 원자 의미를 프로세스 락으로 흉내, Neo4j는 조건부 MATCH로.
  · 워커 간 값(produces) 공유 없음 — 지식은 fact 노드로만 공유(ARTEX와 동일).
  · 에피소드 스코프: 그래프는 에피소드 단위. 노드에 episode_id를 달아 리셋 시
    그 에피소드 노드만 비운다(지식 그래프는 보존).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Protocol, runtime_checkable


# ───────────────── 노드 종류 (ARTEX kind 차용) ─────────────────
class NodeKind(str, Enum):
    GOAL = "goal"        # 에피소드 목표(어느 중요자산 침해)
    INTENT = "intent"    # 탐색 방향 — 워커가 claim하는 작업 단위(소유자·상태 보유)
    FACT = "fact"        # 워커의 관측·결론(부정 결론 포함). source_step_ids 보유
    FINDING = "finding"  # 공격자가 주장하는 침해(진실 판정은 god-view 별도)
    HINT = "hint"        # 외부 주입 단서(발판 등)


# ───────────────── 의도 상태머신 ─────────────────
# open → running → (done | blocked | exhausted | stopped)
# blocked는 frontier로 재투입 가능, 나머지 종료상태는 재claim 안 됨.
class IntentState(str, Enum):
    OPEN = "open"            # frontier에 있음(claim 대상)
    RUNNING = "running"      # 워커가 claim해 실행 중
    DONE = "done"           # 결론 산출(yields fact/finding)
    BLOCKED = "blocked"      # 모델·툴 실패 → 재투입 가능
    EXHAUSTED = "exhausted"  # 시간 T 소진(부분결과 보존)
    STOPPED = "stopped"      # 플래너가 중단(목표달성·중복)


# ───────────────── 관계 (ARTEX rel 차용) ─────────────────
class Rel(str, Enum):
    SPAWNS = "spawns"              # intent → 하위 intent
    DERIVED_FROM = "derived_from"  # fact → 그 근거가 된 fact
    YIELDS = "yields"              # intent → fact (의도가 사실을 낳음)
    PROVES = "proves"              # fact → finding (사실이 침해를 입증)


# claim 종료 시 넘어갈 수 있는 상태(open은 claim의 출발이라 제외)
_TERMINAL = {IntentState.DONE, IntentState.BLOCKED,
             IntentState.EXHAUSTED, IntentState.STOPPED}


@dataclass
class Node:
    """탐색 그래프의 한 노드. payload는 kind별로 모양이 다른 자유 영역.

    fact payload 예: {summary, detail, evidence, confidence, source_step_ids:[...]}
    intent payload 예: {summary, target, why, technique}
    """
    id: int
    kind: NodeKind
    payload: dict = field(default_factory=dict)
    state: str = ""                      # intent면 IntentState, 그 외 kind별 상태
    owner: str = ""                      # intent를 claim한 워커 id
    priority: int = 0
    episode: int = 0
    anchors: list[int] = field(default_factory=list)  # → 자산 노드 id(ANCHORED_TO)


@dataclass
class Edge:
    src_id: int
    rel: Rel
    dst_id: int


@runtime_checkable
class ExplorationGraph(Protocol):
    """탐색 그래프 계약. 플래너·워커·실행레인이 공유하는 상태 저장소.

    메서드는 '무엇을'만 정한다. 원자성(claim)·동시성은 구현이 책임진다.
    """

    # ── 쓰기 ──
    def add_goal(self, payload: dict, *, anchors: Optional[list[int]] = None) -> int:
        """에피소드 목표(크라운) 노드를 쓰고 id를 돌려준다. frontier엔 안 들어감.
        개막 의도의 출처(루트)로 쓰여 그래프를 하나로 잇는다."""
        ...

    def add_intent(self, payload: dict, *, priority: int = 0,
                   anchors: Optional[list[int]] = None, origin: str = "planner",
                   spawned_by=None) -> int:
        """열린 intent를 frontier에 추가하고 id를 돌려준다.

        spawned_by: 이 의도를 낳은 출처 노드 id(목표·사실·상위의도). int 하나 또는 리스트.
        각 출처에서 (출처)-[:SPAWNS]->(이 의도) 엣지를 건다 → 추론 트리가 하나로 이어진다.
        (사실→SPAWNS→의도 = '이 사실을 보고 이 의도가 나왔다')
        """
        ...

    def add_fact(self, payload: dict, *, intent_id: Optional[int] = None,
                 anchors: Optional[list[int]] = None,
                 derived_from: Optional[list[int]] = None) -> int:
        """fact 노드를 쓰고, intent_id가 있으면 intent→YIELDS→fact를 건다."""
        ...

    def add_finding(self, payload: dict, *, proved_by: Optional[list[int]] = None,
                    anchors: Optional[list[int]] = None,
                    dedup_key: Optional[str] = None) -> int:
        """finding 노드를 쓰고, proved_by fact들에서 PROVES 엣지를 건다.

        dedup_key가 주어지고 같은 키의 finding이 이미 있으면 새 노드를 안 만들고 그걸 병합
        (심각도=최댓값, 원 보고들은 reports[]로 보존, proved_by 엣지 추가)해 그 id를 돌려준다.
        같은 침해(같은 기법)가 여러 의도에서 중복 보고돼도 그래프엔 하나로 수렴시키기 위함.
        """
        ...

    # ── frontier / claim ──
    def frontier(self, limit: int = 20) -> list[Node]:
        """열린(open) intent들을 우선순위·id 순으로 돌려준다(읽기, claim 아님)."""
        ...

    def claim_next(self, worker: str, limit: int = 20) -> Optional[Node]:
        """frontier에서 열린 intent 하나를 '원자적으로' 집어 running으로.

        두 워커가 동시에 불러도 같은 의도를 둘 다 집지 못한다(계약). 집을 게
        없으면 None. 실제 원자성은 구현이 보장(fake=락, Neo4j=CAS).
        """
        ...

    def settle_intent(self, intent_id: int, state: IntentState,
                      reason: str = "") -> bool:
        """running intent를 종료상태로. blocked는 frontier 재투입을 위해 open 복귀 별도."""
        ...

    def reopen_intent(self, intent_id: int) -> bool:
        """blocked 등으로 중단된 intent를 다시 open으로(재claim 가능)."""
        ...

    def anchor_to(self, node_id: int, asset_ids: list[int]) -> None:
        """탐색 노드(의도·발견)를 자산 그래프 노드에 ANCHORED_TO로 잇는다.
        node.anchors에 asset id를 채운다 — '이 의도/침해는 이 자산을 건드렸다'.
        (지금은 name 매칭 앵커, CPE 기반 매칭은 KG 단계에서)"""
        ...

    # ── 읽기 ──
    def get_node(self, node_id: int) -> Optional[Node]:
        ...

    def recent_facts(self, limit: int = 20) -> list[Node]:
        """최근 fact들(플래너가 다음 의도를 설계할 때 보는 태세)."""
        ...

    def recent_findings(self, limit: int = 20) -> list[Node]:
        """최근 finding들(공격자 주장 침해 — 라운드 결과 요약·채점 입력용)."""
        ...

    def running_intents(self) -> list[Node]:
        """지금 워커가 돌리고 있는 intent들(종료 판정·중복 방지용)."""
        ...


# ───────────── 발견 병합(공유) — 인메모리·Neo4j가 같은 의미를 쓰도록 ─────────────
SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def max_severity(a: str, b: str) -> str:
    """두 심각도 중 높은 것. 모르는 값(빈 문자열 등)은 0위."""
    ra, rb = SEVERITY_RANK.get(a, 0), SEVERITY_RANK.get(b, 0)
    return a if ra >= rb else b


def merge_finding_payload(existing: dict, incoming: dict) -> dict:
    """같은 침해(같은 dedup_key)가 중복 보고될 때 payload 병합 규칙.
    심각도=최댓값 · occurrences=총 보고횟수 · reports=서로 다른 요약 보존(정보 손실 없음)."""
    out = dict(existing)
    out["severity"] = max_severity(existing.get("severity", ""), incoming.get("severity", ""))
    out["occurrences"] = int(existing.get("occurrences", 1)) + 1
    reports = list(existing.get("reports") or [existing.get("summary", "")])
    s = str(incoming.get("summary", "")).strip()
    if s and s not in reports:
        reports.append(s)
    out["reports"] = reports
    return out


__all__ = [
    "NodeKind", "IntentState", "Rel", "Node", "Edge", "ExplorationGraph",
    "SEVERITY_RANK", "max_severity", "merge_finding_payload",
]
