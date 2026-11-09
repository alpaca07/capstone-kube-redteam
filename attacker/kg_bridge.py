"""자산 그래프 ↔ 지식 그래프(KG) 다리 — 플래너 situation 에 넣을 'KG 후보 기법' 블록을 만든다.

설계(B, LLM 바인딩): 자산은 CPE 식별 전이라 기계 조인이 안 되므로, 관측 용어(이름·kind·cpe
조각)로 KG 를 느슨 검색해 후보 기법을 모은다. 플래너 LLM 이 자산과 이 후보를 묶어 technique 를
고른다(히트 없으면 빈 블록 → 자기 지식 폴백). round_engine 은 KG 를 모른 채 이 콜백만 호출한다
(이음새). 실제 Neo4j session 주입은 조립부(server)에서.
"""
from __future__ import annotations

import re
from typing import Callable, Optional

from knowledge.query import knowledge_for_terms, render_kg_candidates

# 영문으로 시작하는 3자 이상 토큰(버전 숫자 '13.10' 등은 제외). ':' '/' 는 공백처럼.
_TOK = re.compile(r"[a-z][a-z0-9_-]{2,}")
# 제품 식별에 무의미한 흔한 잡음(검색 노이즈만 키움).
_STOP = frozenset({
    "cpe", "the", "and", "for", "http", "https", "tcp", "udp", "svc", "pod",
    "app", "api", "web", "service", "server", "cluster", "local", "default",
    "com", "net", "org", "node", "port", "host", "name",
})


def _tokenize(raw: str) -> list[str]:
    """관측 문자열 → 검색 용어 토큰. 소문자화, cpe/경로 구분자 분해, 버전·잡음 제거."""
    if not raw:
        return []
    low = raw.lower().replace(":", " ").replace("/", " ")
    return [t for t in _TOK.findall(low) if t not in _STOP]


def asset_terms(asset_graph, *, limit: int = 50, max_terms: int = 24) -> list[str]:
    """자산 그래프 → KG 느슨 매칭용 관측 용어(이름·kind·cpe 조각), 중복 제거·상한.

    식별 자산(cpe 보유)을 앞에 둬 더 정확한 용어가 먼저 쓰이게 한다(상한에 걸릴 때 유리).
    """
    if asset_graph is None:
        return []
    assets = list(asset_graph.assets(limit=limit))
    assets.sort(key=lambda a: 0 if getattr(a, "cpe", "") else 1)   # 식별 자산 먼저
    terms: list[str] = []
    seen: set[str] = set()
    for a in assets:
        for raw in (getattr(a, "cpe", ""), getattr(a, "name", ""), getattr(a, "kind", "")):
            for tok in _tokenize(raw):
                if tok not in seen:
                    seen.add(tok)
                    terms.append(tok)
                    if len(terms) >= max_terms:
                        return terms
    return terms


def make_kg_lookup(session) -> Callable[[object], str]:
    """단일 session(읽기)으로 'asset_graph → kg_block(텍스트)' 콜백을 만든다.

    round_engine 이 매 웨이브 이 콜백을 호출해 플래너 situation 의 KG 후보 블록을 얻는다.
    session 은 knowledge.query 가 쓰는 run(query, **params) 계약이면 된다(주로 테스트 Fake).
    실 Neo4j 는 장수명 session 회피를 위해 make_kg_lookup_from_driver 를 쓴다.
    """
    def lookup(asset_graph) -> str:
        terms = asset_terms(asset_graph)
        if not terms:
            return ""
        return render_kg_candidates(knowledge_for_terms(session, terms))
    return lookup


def make_kg_lookup_from_driver(driver, database=None) -> Callable[[object], str]:
    """Neo4j driver 로 콜백 — 매 호출 짧은 읽기 session 을 연다(장수명 session 회피).

    조립부(server)가 자산·탐색 그래프와 '같은 Neo4j'(KG 는 라벨로 공존)를 쓰므로 공유 driver 를
    그대로 받는다. 용어가 없으면 session 도 안 연다.
    """
    def lookup(asset_graph) -> str:
        terms = asset_terms(asset_graph)
        if not terms:
            return ""
        with driver.session(database=database) as s:
            return render_kg_candidates(knowledge_for_terms(s, terms))
    return lookup


# round_engine 이 받는 콜백 타입(가독성용 별칭)
KgLookup = Optional[Callable[[object], str]]


__all__ = ["asset_terms", "make_kg_lookup", "make_kg_lookup_from_driver", "KgLookup"]
