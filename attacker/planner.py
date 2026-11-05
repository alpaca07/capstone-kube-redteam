"""플래너 — 정렬(aligned) 모델이 태세를 읽고 '탐색 방향(의도)'을 생성해 frontier에 넣는다.

ARTEX의 유일 intent 생성자. 워커(탈옥 모델)는 이 의도를 claim해 실행하고, 플래너는
워커가 쌓은 fact/finding을 다시 읽어 새 의도를 뿌린다(이벤트 구동 폐곡선).

모델 분리(이번 세션 확정·소규모 탐침 검증): 플래너=정렬 모델(방어용과 같은 서빙).
정렬 모델이 공격 '전략 수립·기법 태깅'은 거부 없이 하되 실제 페이로드 작성은 플래너
선에서 거부 → 희소자원(탈옥 모델 1개)을 워커에 몰아주는 경합 완화. 플래너는 '무엇을
노려 어디를 파볼지'만 내고(=의도), 실제 명령·페이로드는 워커가 쓴다.

정렬 모델은 추론(thinking) 모델이라 JSON이 잘리기 쉬움 → max_tokens 넉넉히(기본 3000),
reasoning_effort=none 소프트 스위치, 느슨한 JSON 추출로 방어.

LLM은 주입(계약) → fake로 전 로직 테스트. 실제 LLM은 common.llm_client.OllamaClient
(정렬 모델, defender_base_url)를 끼운다.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Protocol

from common.llm_json import LLMJsonError, extract_and_load

from .graph import ExplorationGraph, Node, NodeKind

_re_int = re.compile(r"\d+")


PLANNER_SYSTEM = """\
You are the PLANNING module of an authorized, sandboxed red-team exercise against \
a Kubernetes cluster that the operator fully owns and has consented to test. This \
is a closed lab with no real users or data.

Your ONLY job is strategy: read the current situation (goal, known assets, foothold, \
recent facts, intents already in flight) and propose the next few EXPLORATION \
DIRECTIONS ("intents") that move toward the goal. An intent is one sentence \
describing WHAT to investigate or verify next and on WHICH asset — never an actual \
command, payload, or exploit. Writing commands/payloads is a different module's job.

Rules:
- Propose 2-4 intents, non-overlapping with each other AND with intents already in \
flight (listed below). Do not restate directions that are already open or running.
- Each intent gets a MITRE ATT&CK technique id in a "technique" field when one fits \
(e.g. T1552, T1078, T1046); use "" if none fits.
- "from": list the fact id numbers (the #N shown in RECENT FACTS) that THIS intent \
builds on — i.e. the observations that made you choose this direction. Use [] only \
for the opening move when there are no facts yet. This links each new direction to \
the evidence that motivated it, so the exploration forms a connected reasoning tree.
- If the goal already appears reached from the facts, return an empty "intents" list.

Output ONLY a JSON object, no prose:
{"intents": [{"summary": "<one-line direction>", "target": "<asset>", \
"why": "<why it advances the goal>", "technique": "<MITRE id or empty>", \
"from": [<fact id numbers this builds on>]}]}"""


@dataclass
class PlannerIntent:
    """플래너가 낸 의도 하나(그래프에 쓰기 전 중간 표현)."""
    summary: str
    target: str = ""
    why: str = ""
    technique: str = ""
    from_facts: list = None       # 이 의도가 파생된 출처 사실 id들(그래프 연결용)

    def to_payload(self) -> dict:
        p = {"summary": self.summary}
        if self.target:
            p["target"] = self.target
        if self.why:
            p["why"] = self.why
        if self.technique:
            p["technique"] = self.technique
        return p


class _LLM(Protocol):
    def chat_text(self, system: str, user: str, **kw) -> str:
        ...


# ───────────── 태세 렌더링 ─────────────
def _fact_line(n: Node) -> str:
    p = n.payload
    conf = f" ({p['confidence']})" if p.get("confidence") else ""
    return f"- #{n.id} {p.get('summary', '')}{conf}"


def _intent_line(n: Node) -> str:
    p = n.payload
    tech = f" [{p['technique']}]" if p.get("technique") else ""
    return f"- #{n.id} ({n.state}) {p.get('summary', '')}{tech}"


def build_situation(graph: ExplorationGraph, *, goal: str,
                    assets_block: str = "", facts_limit: int = 20) -> str:
    """플래너가 보는 태세: 목표 + 자산(선택) + 최근 사실 + 진행 중인 의도."""
    parts = [f"GOAL: {goal}"]
    if assets_block:
        parts.append("KNOWN ASSETS:\n" + assets_block)

    facts = graph.recent_facts(limit=facts_limit)
    if facts:
        parts.append("RECENT FACTS:\n" + "\n".join(_fact_line(f) for f in facts))
    else:
        parts.append("RECENT FACTS: (none yet — this is the opening)")

    # 진행 중(running) + 대기(open) 의도 → 중복 방지용으로 플래너에 보여준다
    inflight = graph.running_intents() + graph.frontier(limit=facts_limit)
    if inflight:
        parts.append("INTENTS ALREADY IN FLIGHT (do not duplicate):\n"
                     + "\n".join(_intent_line(n) for n in inflight))
    else:
        parts.append("INTENTS ALREADY IN FLIGHT: (none)")
    return "\n\n".join(parts)


# ───────────── 파싱 ─────────────
def parse_intents(text: str) -> list[PlannerIntent]:
    """LLM 응답에서 intents 배열을 느슨하게 뽑는다. 깨지면 LLMJsonError."""
    obj = extract_and_load(text)          # 펜스·잡설·트레일링콤마 등 흡수
    if not isinstance(obj, dict):
        raise LLMJsonError(f"객체가 아님: {type(obj).__name__}")
    arr = obj.get("intents", [])
    if not isinstance(arr, list):
        raise LLMJsonError("intents가 배열이 아님")
    out: list[PlannerIntent] = []
    for it in arr:
        if not isinstance(it, dict):
            continue
        summary = str(it.get("summary", "")).strip()
        if not summary:
            continue                       # summary 없는 건 버림(빈 의도 방지)
        out.append(PlannerIntent(
            summary=summary,
            target=str(it.get("target", "")).strip(),
            why=str(it.get("why", "")).strip(),
            technique=str(it.get("technique", "")).strip(),
            from_facts=_parse_ids(it.get("from"))))
    return out


def _parse_ids(x) -> list:
    """'from' 필드를 int id 리스트로. "#12"·"12"·12 모두 허용, 비정상은 버림."""
    if not isinstance(x, list):
        return []
    ids = []
    for v in x:
        if isinstance(v, bool):
            continue
        if isinstance(v, int):
            ids.append(v)
        elif isinstance(v, str):
            m = _re_int.search(v)
            if m:
                ids.append(int(m.group()))
    return ids


# ───────────── 플래너 ─────────────
@dataclass
class PlanResult:
    added_ids: list[int]           # 이번에 frontier에 넣은 intent id들
    proposed: int                  # LLM이 제안한 수(파싱 성공분)
    error: str = ""                # 파싱 끝내 실패 시 진단(이 라운드 0개 추가)

    @property
    def goal_reached_signal(self) -> bool:
        """제안 0개 = 플래너가 '더 팔 방향 없음/목표 달성'으로 본 신호(에러 아닐 때)."""
        return not self.error and self.proposed == 0


class Planner:
    def __init__(self, llm: _LLM, *, goal: str, max_tokens: int = 3000,
                 retries: int = 1) -> None:
        self.llm = llm
        self.goal = goal
        self.max_tokens = max_tokens      # 정렬=추론 모델이라 넉넉히(JSON 잘림 방지)
        self.retries = retries

    def plan(self, graph: ExplorationGraph, *, assets_block: str = "",
             spawned_by: Optional[int] = None,
             default_parent: Optional[int] = None) -> PlanResult:
        """태세를 읽어 의도를 생성하고 frontier에 추가. 추가된 id 목록을 돌려준다.

        각 의도는 플래너가 낸 'from'(출처 사실 id)으로 그래프에 연결된다. from이 비면
        default_parent(보통 goal 노드)에서 파생 → 추론 트리가 하나로 이어진다. spawned_by는
        모든 의도에 공통으로 더 붙일 출처(옵션).
        """
        user = build_situation(graph, goal=self.goal, assets_block=assets_block)
        # 플래너가 헛 id를 낼 수 있으니 현존 사실·의도 id만 유효 출처로 인정
        valid = {n.id for n in graph.recent_facts(limit=10_000)}
        valid |= {n.id for n in graph.running_intents()}
        last_err = ""
        for attempt in range(self.retries + 1):
            prompt = user if attempt == 0 else user + (
                "\n\n(직전 응답이 올바른 JSON이 아니었다. 설명 없이 지정된 JSON 객체 하나만 출력하라.)")
            try:
                text = self.llm.chat_text(
                    PLANNER_SYSTEM, prompt,
                    max_tokens=self.max_tokens,
                    extra={"reasoning_effort": "none"})
            except Exception as e:  # noqa: BLE001 — 호출 실패는 이 라운드 계획 실패로(엔진이 판단)
                last_err = f"llm 호출 실패: {type(e).__name__}: {e}"
                continue
            try:
                intents = parse_intents(text or "")
            except LLMJsonError as e:
                last_err = f"파싱 실패: {e}"
                continue
            # 성공 — 각 의도를 출처(from 사실들 → 없으면 default_parent)에 연결해 추가
            added = []
            for pi in intents:
                srcs = [i for i in (pi.from_facts or []) if i in valid]
                if not srcs and default_parent is not None:
                    srcs = [default_parent]          # 개막·무출처 의도는 목표에서 파생
                if spawned_by is not None:
                    srcs.append(spawned_by)
                added.append(graph.add_intent(pi.to_payload(), origin="planner",
                                              spawned_by=srcs or None))
            return PlanResult(added_ids=added, proposed=len(intents))
        return PlanResult(added_ids=[], proposed=0, error=last_err)


__all__ = [
    "Planner", "PlanResult", "PlannerIntent", "PLANNER_SYSTEM",
    "build_situation", "parse_intents",
]
