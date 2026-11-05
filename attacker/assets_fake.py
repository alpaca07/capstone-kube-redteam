"""인메모리 자산 그래프 — AssetGraph 계약의 테스트/오프라인 구현.

name으로 dedup(같은 자산을 여러 워커가 관측해도 노드 하나). 병합은 공유 규칙
(merge_asset_fields) — CPE 승격·attrs 합성·신뢰값 최댓값. 스레드 안전(락).
"""
from __future__ import annotations

import threading
from typing import Optional

from .assets import AssetGraph, AssetNode, AssetRel, merge_asset_fields


class InMemoryAssetGraph(AssetGraph):
    def __init__(self, *, episode: int = 0) -> None:
        self._episode = episode
        self._lock = threading.Lock()
        self._nodes: dict[int, AssetNode] = {}
        self._by_name: dict[str, int] = {}          # name → id(dedup)
        self._contains: list[tuple[int, int]] = []  # (parent, child)
        self._seq = 0

    def _copy(self, n: AssetNode) -> AssetNode:
        return AssetNode(id=n.id, kind=n.kind, name=n.name, cpe=n.cpe,
                         confidence=n.confidence, attrs=dict(n.attrs), episode=n.episode)

    # ── 쓰기 ──
    def add_asset(self, kind: str, name: str, *, cpe: str = "", confidence: str = "",
                  attrs: Optional[dict] = None, parent: Optional[int] = None,
                  anchors: Optional[list[int]] = None) -> int:
        with self._lock:
            name = (name or "").strip()
            if name and name in self._by_name:
                nid = self._by_name[name]
                merge_asset_fields(self._nodes[nid], kind=kind, cpe=cpe,
                                   confidence=confidence, attrs=attrs)
                if parent is not None and (parent, nid) not in self._contains:
                    self._contains.append((parent, nid))
                return nid
            self._seq += 1
            nid = self._seq
            self._nodes[nid] = AssetNode(
                id=nid, kind=kind, name=name, cpe=cpe, confidence=confidence,
                attrs=dict(attrs or {}), episode=self._episode)
            if name:
                self._by_name[name] = nid
            if parent is not None:
                self._contains.append((parent, nid))
            return nid

    def link_contains(self, parent_id: int, child_id: int) -> None:
        with self._lock:
            if (parent_id, child_id) not in self._contains:
                self._contains.append((parent_id, child_id))

    # ── 읽기 ──
    def get_asset(self, asset_id: int) -> Optional[AssetNode]:
        with self._lock:
            n = self._nodes.get(asset_id)
            return self._copy(n) if n else None

    def find_by_name(self, name: str) -> Optional[AssetNode]:
        with self._lock:
            nid = self._by_name.get((name or "").strip())
            return self._copy(self._nodes[nid]) if nid else None

    def find_by_cpe(self, cpe: str) -> list[AssetNode]:
        if not cpe:
            return []
        with self._lock:
            return [self._copy(n) for n in self._nodes.values() if n.cpe == cpe]

    def assets(self, limit: int = 100) -> list[AssetNode]:
        with self._lock:
            ns = sorted(self._nodes.values(), key=lambda n: n.id, reverse=True)
            return [self._copy(n) for n in ns[:limit]]

    def children(self, asset_id: int) -> list[AssetNode]:
        with self._lock:
            kids = [c for (p, c) in self._contains if p == asset_id]
            return [self._copy(self._nodes[c]) for c in kids if c in self._nodes]

    def unidentified(self, limit: int = 100) -> list[AssetNode]:
        with self._lock:
            ns = [n for n in self._nodes.values() if not n.cpe]
            ns.sort(key=lambda n: n.id, reverse=True)
            return [self._copy(n) for n in ns[:limit]]

    # ── 테스트 편의 ──
    def contains_edges(self) -> list[tuple[int, int]]:
        with self._lock:
            return list(self._contains)


__all__ = ["InMemoryAssetGraph"]
