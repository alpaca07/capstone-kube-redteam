"""자산 그래프 이음새(seam) — 공격 대상 자산을 '관측대로' 쌓는 계약.

ARTEX의 assets 그래프를 차용(화이트보드 확정 구조). 탐색 그래프(의도·사실·발견)와 별개의
축으로, '무엇이 존재하는가'를 담는다. 탐색 그래프가 '공격 사고·진행'이라면 자산 그래프는
'대상 지형'이다. 둘은 ANCHORED_TO 앵커로 이어진다(탐색 노드의 anchors 필드 = 자산 노드 id).

설계 불변(화이트보드):
  · 노드 타입은 '유동' — 특정 타깃 용어(domain/service/endpoint…)를 코드에 안 박는다.
    kind는 관측한 대로의 자유 문자열. 불변은 '구조 원리'뿐:
      - 관측 → 부모자식 계층(CONTAINS): 큰 것이 작은 것을 담는다(호스트⊃서비스⊃엔드포인트 등).
      - CPE 식별자: 있으면 '식별된 자산'(KG와 CPE로 조인 가능 = 공격 가능), 없으면 '정찰 필요'.
      - 신뢰값(confidence): 이 관측을 얼마나 믿나.
  · '무슨 기술인가' 분류는 지식 그래프(KG) 몫. 자산 그래프는 CPE 조인키만 들고, 분류는 안 한다.
  · 회차 스코프(episode) — 탐색 그래프와 함께 리셋(KG는 보존).

같은 자산을 여러 워커가 관측할 수 있으므로 name으로 dedup(병합) — 공유 규칙은
merge_asset_fields. 저장은 단일 Neo4j에 :Asset 라벨(:Explore와 구분). 실제 구현 둘:
  - 인메모리 fake (assets_fake.py) — 테스트·오프라인
  - Neo4j (assets_neo4j.py) — 영속
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable


# 자산 그래프 내부 관계(부모자식)
class AssetRel:
    CONTAINS = "CONTAINS"        # 부모 자산이 자식 자산을 담음(호스트→서비스→엔드포인트 등)


@dataclass
class AssetNode:
    """자산 하나. kind는 유동(관측한 대로). cpe 유무가 '식별/미식별'을 가른다."""
    id: int
    kind: str                            # 유동 타입(host/service/endpoint/… — 코드에 안 박음)
    name: str                            # 관측된 식별자(호스트·서비스명·엔드포인트·IP:port 등)
    cpe: str = ""                        # 있으면 KG 조인키(식별 자산), 없으면 정찰 필요
    confidence: str = ""                 # 신뢰값(observed/inferred 등 — 자유)
    attrs: dict = field(default_factory=dict)   # port·proto·title·status 등 자유 속성
    episode: int = 0

    @property
    def identified(self) -> bool:
        """CPE가 있으면 '식별된(=공격 가능 후보)' 자산."""
        return bool(self.cpe)


def merge_asset_fields(existing: AssetNode, *, kind: str = "", cpe: str = "",
                       confidence: str = "", attrs: Optional[dict] = None) -> None:
    """같은 자산(같은 name)이 다시 관측될 때 제자리 병합:
    · cpe: 비어있다가 생기면 채운다(미식별→식별 승격). 이미 있으면 유지.
    · attrs: 합친다(새 관측이 덮어씀).
    · confidence: 둘 중 '더 센' 것(observed > inferred). kind도 비어있던 걸 채운다.
    """
    if cpe and not existing.cpe:
        existing.cpe = cpe
    if kind and not existing.kind:
        existing.kind = kind
    if attrs:
        existing.attrs = {**existing.attrs, **attrs}
    existing.confidence = _stronger_conf(existing.confidence, confidence)


_CONF_RANK = {"inferred": 1, "observed": 2, "confirmed": 3}


def _stronger_conf(a: str, b: str) -> str:
    ra, rb = _CONF_RANK.get(a, 0), _CONF_RANK.get(b, 0)
    return a if ra >= rb else b


@runtime_checkable
class AssetGraph(Protocol):
    """자산 그래프 계약. 관측으로 쌓고, 계층·CPE로 조회한다."""

    # ── 쓰기 ──
    def add_asset(self, kind: str, name: str, *, cpe: str = "", confidence: str = "",
                  attrs: Optional[dict] = None, parent: Optional[int] = None,
                  anchors: Optional[list[int]] = None) -> int:
        """자산을 추가하고 id를 돌려준다. 같은 name이 이미 있으면 새 노드 대신 병합(그 id 반환).
        parent가 있으면 (parent)-[:CONTAINS]->(이 자산) 계층 엣지를 건다."""
        ...

    def link_contains(self, parent_id: int, child_id: int) -> None:
        """부모 자산이 자식 자산을 담는 계층 엣지(관측으로 나중에 계층이 드러날 때)."""
        ...

    # ── 읽기 ──
    def get_asset(self, asset_id: int) -> Optional[AssetNode]:
        ...

    def find_by_name(self, name: str) -> Optional[AssetNode]:
        """이름으로 자산 하나(탐색 노드가 target 문자열을 자산에 앵커링할 때 해소용)."""
        ...

    def find_by_cpe(self, cpe: str) -> list[AssetNode]:
        """CPE로 자산들(자산↔KG 조회시점 매칭용). 빈 CPE는 매칭 안 함."""
        ...

    def assets(self, limit: int = 100) -> list[AssetNode]:
        """회차의 자산들(최근 id 순). 태세·시각화용."""
        ...

    def children(self, asset_id: int) -> list[AssetNode]:
        """이 자산이 담은 자식 자산들(CONTAINS)."""
        ...

    def unidentified(self, limit: int = 100) -> list[AssetNode]:
        """CPE 없는 자산들 = 아직 '정찰 필요'(플래너가 식별 의도를 낼 후보)."""
        ...


__all__ = [
    "AssetNode", "AssetGraph", "AssetRel",
    "merge_asset_fields",
]
