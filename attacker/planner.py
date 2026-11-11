"""플래너 — 정렬(aligned) 모델이 태세를 읽고 '탐색 방향(의도)'을 생성해 frontier에 넣는다.

2단 구성(ARTEX+KG 설계, 2026-11-11 확정):
  1차 select_knowledge — 상황 + 원시 KG 후보(candidate techniques)를 읽고 '이 지형·목표에
    실제 적용되는 지식(기법)'만 선별(근거·적용성). 행동/의도는 안 낸다.
  2차 plan — 1차 선별을 받아 워커가 claim할 '의도노드 + 공격계획(plan 단계 배열)'을 생성.
둘 다 정렬 모델(전략·기법 태깅·단계 방향까지는 거부 없이 수행, 실제 페이로드는 워커=탈옥 모델).
1차가 KG→기법을 선별(applicability), 2차가 그 위에 의도·계획을 올린다.

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


# ───────────── 1차: 지식 선별(knowledge triage) ─────────────
SELECT_SYSTEM = """\
You are STAGE 1 (knowledge triage) of an authorized, sandboxed red-team planner against \
a Kubernetes cluster the operator fully owns and consented to test. Closed lab, no real data.

Your ONLY job: read the situation (goal, known assets, recent facts, previously-breached) \
and the CANDIDATE KNOWLEDGE (ATT&CK techniques the knowledge base loosely associated with the \
observed assets, each with a confidence, matched asset terms, and CVEs). Decide WHICH candidates \
are genuinely applicable to THIS terrain on the path to the goal. You do NOT propose actions, \
intents, commands, or payloads — that is stage 2. You only triage knowledge.

Rules:
- Select a candidate ONLY when its technique plausibly applies to a known asset that lies on the \
path to the goal. Drop weak-bridge guesses whose technique or asset does not actually fit.
- Confidence is a hint: high (~0.9) is a curated mapping worth trusting; low (~0.2) is often off — \
keep a low one ONLY when it plainly matches an asset, otherwise drop it. Never invent CVEs.
- For each selection give the asset(s) it applies to, a one-line why, and applicability (high|medium|low).
- Fewer, well-grounded selections beat a long list. Return an empty list when no candidate genuinely applies.

Output ONLY a JSON object, no prose:
{"selected": [{"technique": "<MITRE id>", "assets": ["<asset>"], "why": "<one line>", \
"applicability": "high|medium|low"}]}"""


# ───────────── 2차: 의도·계획 생성(planning) ─────────────
PLANNER_SYSTEM = """\
You are STAGE 2 (planning) of an authorized, sandboxed red-team exercise against a Kubernetes \
cluster the operator fully owns and consented to test. Closed lab, no real users or data.

Your job: read the current situation (goal, known assets, foothold, recent facts, \
previously-breached accesses, SELECTED KNOWLEDGE from stage 1, intents already in flight) and \
propose the next EXPLORATION DIRECTIONS ("intents") that move toward the goal. An intent names \
WHAT to investigate/verify next and on WHICH asset, plus a short step plan — never an actual \
command, payload, or exploit string. Writing commands/payloads is the worker's job.

Rules:
- Propose intents UP TO the target count given in the situation (TARGET INTENTS), \
non-overlapping with each other AND with intents already in flight (listed below). Do not \
restate directions already open or running. Produce as many distinct, genuinely worthwhile \
directions as actually exist — proposing FEWER than the target is expected and correct when the \
surface is thin. NEVER invent filler, vague, or redundant directions just to reach the number.
- KNOWN ASSETS is the discovered terrain (host > service > endpoint), each tagged [explored] \
(a worker already probed it) or [untouched]. Prefer [untouched] assets and ones not already \
covered by recent facts or in-flight intents — spend new intents on unexplored surface.
- BALANCE breadth with DEPTH — do not spend every intent opening new ground. Whenever a recent \
fact or known asset is a concrete lead toward the GOAL (a secret/credential/token endpoint, a \
reachable service on the path to the crown), dedicate at least one intent to DRIVING THAT LEAD \
to an actual compromise end-to-end. A single path finished to the goal beats ten assets mapped.
- MATCH the method to the asset. Data held in a DATABASE is exfiltrated by connecting to that DB \
service with a DB credential and running a query on the target tables — NOT with a Kubernetes \
service-account token or the K8s secrets API, which return cluster objects, not table rows. When \
the goal asset is a database and a DB credential has been found, dedicate an intent to connecting \
to the DB service and reading the target tables directly.
- SELECTED KNOWLEDGE (when shown) lists ATT&CK techniques stage-1 already judged applicable to \
the observed assets (with the asset, a why, and applicability). Build intents around these and \
reuse their technique ids; add an intent with your own technique only when the situation clearly \
calls for one not in the list. Put a MITRE id in "technique" when one fits, else "".
- "plan": an ORDERED list of 2-5 concrete sub-steps the worker should follow for this intent — \
still direction-level (what to retrieve / which endpoint / what to do with it), NEVER raw \
commands or payloads. Example: ["locate the DB service and port on the path to the goal", \
"authenticate to it with the discovered DB credential", "query the target tables and read the \
sensitive rows"].
- "from": list the fact id numbers (the #N in RECENT FACTS) this intent builds on. Use [] only \
for the opening move with no facts yet. This links each direction to the evidence that motivated it.
- PREVIOUSLY BREACHED, when shown, lists accesses achieved in an EARLIER round. The defender may \
have patched them between rounds, so they are NOT done: when one lies on the path to the goal, \
propose an intent to RE-VERIFY it still works this round (and find another route if now blocked).
- Judge "goal reached" ONLY from THIS round's RECENT FACTS, never from PREVIOUSLY BREACHED. \
Return an empty "intents" list only when this round's facts already show the goal reached.

Output ONLY a JSON object, no prose:
{"intents": [{"summary": "<one-line direction>", "target": "<asset>", \
"why": "<why it advances the goal>", "technique": "<MITRE id or empty>", \
"plan": ["<step 1>", "<step 2>"], "from": [<fact id numbers this builds on>]}]}"""


@dataclass
class KnowledgeSelection:
    """1차가 선별한 지식 하나(그래프/2차에 넘기기 전 중간 표현)."""
    technique: str
    assets: Optional[list] = None
    why: str = ""
    applicability: str = ""

    def __post_init__(self) -> None:
        if self.assets is None:
            self.assets = []


@dataclass
class PlannerIntent:
    """플래너가 낸 의도 하나(그래프에 쓰기 전 중간 표현)."""
    summary: str
    target: str = ""
    why: str = ""
    technique: str = ""
    plan: Optional[list] = None    # 공격 계획 — 워커가 따를 단계 배열(방향 수준, 페이로드 아님)
    from_facts: Optional[list] = None   # 이 의도가 파생된 출처 사실 id들(그래프 연결용)

    def to_payload(self) -> dict:
        p = {"summary": self.summary}
        if self.target:
            p["target"] = self.target
        if self.why:
            p["why"] = self.why
        if self.technique:
            p["technique"] = self.technique
        if self.plan:
            p["plan"] = list(self.plan)
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


def build_situation(graph: ExplorationGraph, *, goal: str, assets_block: str = "",
                    kg_block: str = "", selected_block: str = "",
                    prior_findings_block: str = "", facts_limit: int = 20,
                    target_intents: Optional[int] = None) -> str:
    """플래너가 보는 태세. 1차엔 kg_block(원시 후보), 2차엔 selected_block(1차 선별)을 넣는다.

    assets_block: 자산 그래프를 렌더한 '대상 지형'(라운드 엔진이 만들어 넣음).
    kg_block: 자산↔지식그래프 느슨 매칭 '후보 기법'(1차 select_knowledge 입력).
    selected_block: 1차가 적용성으로 걸러낸 '선별 지식'(2차 plan 입력).
    prior_findings_block: 지난 라운드 침해 — '끝난 일'이 아니라 '재검증 후보'(공진화).
    """
    parts = [f"GOAL: {goal}"]
    if assets_block:
        parts.append("KNOWN ASSETS:\n" + assets_block)
    if kg_block:
        parts.append("CANDIDATE KNOWLEDGE (ATT&CK techniques the KB associates with the assets "
                     "above — triage these):\n" + kg_block)
    if selected_block:
        parts.append("SELECTED KNOWLEDGE (stage-1 triage — techniques judged applicable to the "
                     "assets):\n" + selected_block)

    facts = graph.recent_facts(limit=facts_limit)
    if facts:
        parts.append("RECENT FACTS:\n" + "\n".join(_fact_line(f) for f in facts))
    else:
        parts.append("RECENT FACTS: (none yet — this is the opening)")

    if prior_findings_block:                 # 지난 라운드 침해 → 재검증 대상(공진화)
        parts.append("PREVIOUSLY BREACHED (last round — re-verify, may be patched):\n"
                     + prior_findings_block)

    # 진행 중(running) + 대기(open) 의도 → 중복 방지용으로 플래너에 보여준다
    inflight = graph.running_intents() + graph.frontier(limit=facts_limit)
    if inflight:
        parts.append("INTENTS ALREADY IN FLIGHT (do not duplicate):\n"
                     + "\n".join(_intent_line(n) for n in inflight))
    else:
        parts.append("INTENTS ALREADY IN FLIGHT: (none)")

    if target_intents:                       # 워커 수만큼 목표 — 단 억지 패딩 금지
        parts.append(
            f"TARGET INTENTS THIS WAVE: up to {target_intents} "
            f"({target_intents} parallel workers will drain them). Give as many distinct, "
            "genuinely worthwhile directions as the current surface supports — fewer than "
            f"{target_intents} is correct when there isn't that much worth probing. Do NOT "
            "pad to the number with filler or near-duplicate directions.")
    return "\n\n".join(parts)


def render_selection(sels: list) -> str:
    """1차 선별 → 2차 프롬프트용 블록(없으면 빈 문자열)."""
    lines = []
    for s in sels:
        a = ", ".join(s.assets) if s.assets else "-"
        conf = f" [{s.applicability}]" if s.applicability else ""
        lines.append(f"- {s.technique}{conf} on {a}: {s.why}")
    return "\n".join(lines)


# ───────────── 파싱 ─────────────
def parse_selection(text: str) -> list:
    """1차 응답에서 selected 배열을 느슨하게 뽑는다. 깨지면 LLMJsonError."""
    obj = extract_and_load(text)
    if not isinstance(obj, dict):
        raise LLMJsonError(f"객체가 아님: {type(obj).__name__}")
    arr = obj.get("selected", [])
    if not isinstance(arr, list):
        raise LLMJsonError("selected가 배열이 아님")
    out: list = []
    for it in arr:
        if not isinstance(it, dict):
            continue
        tech = str(it.get("technique", "")).strip()
        if not tech:
            continue                       # 기법 없는 선별은 의미 없음 → 버림
        raw_assets = it.get("assets")
        assets = ([str(a).strip() for a in raw_assets if str(a).strip()]
                  if isinstance(raw_assets, list) else [])
        out.append(KnowledgeSelection(
            technique=tech, assets=assets,
            why=str(it.get("why", "")).strip(),
            applicability=str(it.get("applicability", "")).strip()))
    return out


def _parse_steps(x) -> list:
    """'plan' 필드를 문자열 단계 리스트로. 배열 아니면 []. 최대 8단계."""
    if not isinstance(x, list):
        return []
    return [str(s).strip() for s in x if str(s).strip()][:8]


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
            plan=_parse_steps(it.get("plan")),
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
def _norm_target(t: str) -> str:
    """target 정규화(소문자·공백제거) — 자산 겹침 판정 키."""
    return (t or "").strip().lower()


@dataclass
class SelectResult:
    selected: list                 # KnowledgeSelection 리스트(1차 선별)
    error: str = ""                # 파싱/호출 끝내 실패 시 진단(이 웨이브 선별 0개)

    def render(self) -> str:
        return render_selection(self.selected)


@dataclass
class PlanResult:
    added_ids: list[int]           # 이번에 frontier에 넣은 intent id들
    proposed: int                  # LLM이 제안한 수(파싱 성공분)
    error: str = ""                # 파싱 끝내 실패 시 진단(이 라운드 0개 추가)
    deduped: int = 0               # 자산 겹침으로 떨군 의도 수(워커 동시 중복 방지)

    @property
    def goal_reached_signal(self) -> bool:
        """제안 0개 = 플래너가 '더 팔 방향 없음/목표 달성'으로 본 신호(에러 아닐 때)."""
        return not self.error and self.proposed == 0


class Planner:
    def __init__(self, llm: _LLM, *, goal: str, max_tokens: int = 3000,
                 retries: int = 1, target_intents: int = 4) -> None:
        self.llm = llm
        self.goal = goal
        self.max_tokens = max_tokens      # 정렬=추론 모델이라 넉넉히(JSON 잘림 방지)
        self.retries = retries
        self.target_intents = max(1, int(target_intents))   # 웨이브당 의도 목표 수(=워커 수)

    def _chat(self, system: str, user: str, timeout: Optional[float]) -> str:
        return self.llm.chat_text(system, user, max_tokens=self.max_tokens,
                                  timeout=timeout, extra={"reasoning_effort": "none"})

    # ── 1차: 지식 선별 ──
    def select_knowledge(self, graph: ExplorationGraph, *, assets_block: str = "",
                         kg_block: str = "", prior_findings_block: str = "",
                         timeout: Optional[float] = None) -> SelectResult:
        """원시 KG 후보(kg_block)를 상황에 비춰 적용 지식만 선별. kg_block 비면 선별 생략
        (KG 미연결/후보 0 → 2차가 자기 지식으로). 실패해도 2차는 계속(빈 선별)."""
        if not kg_block.strip():
            return SelectResult(selected=[], error="")
        user = build_situation(graph, goal=self.goal, assets_block=assets_block,
                               kg_block=kg_block, prior_findings_block=prior_findings_block)
        last_err = ""
        for attempt in range(self.retries + 1):
            prompt = user if attempt == 0 else user + (
                "\n\n(직전 응답이 올바른 JSON이 아니었다. 설명 없이 지정된 JSON 객체 하나만 출력하라.)")
            try:
                text = self._chat(SELECT_SYSTEM, prompt, timeout)
            except Exception as e:  # noqa: BLE001 — 호출 실패는 선별 실패(2차가 폴백)
                last_err = f"llm 호출 실패: {type(e).__name__}: {e}"
                continue
            try:
                return SelectResult(selected=parse_selection(text or ""), error="")
            except LLMJsonError as e:
                last_err = f"파싱 실패: {e}"
                continue
        return SelectResult(selected=[], error=last_err)

    # ── 2차: 의도·계획 생성 ──
    def plan(self, graph: ExplorationGraph, *, assets_block: str = "",
             selected_block: str = "", prior_findings_block: str = "",
             spawned_by: Optional[int] = None,
             default_parent: Optional[int] = None,
             timeout: Optional[float] = None) -> PlanResult:
        """1차 선별(selected_block)을 받아 의도노드+공격계획(plan)을 생성해 frontier에 추가.

        각 의도는 'from'(출처 사실 id, 없으면 default_parent)으로 그래프에 연결되고, technique
        가 있으면 graph.select_knowledge 로 KG 기법에 SELECTED 프로비넌스를 남긴다.
        """
        user = build_situation(graph, goal=self.goal, assets_block=assets_block,
                               selected_block=selected_block,
                               prior_findings_block=prior_findings_block,
                               target_intents=self.target_intents)
        # 플래너가 헛 id를 낼 수 있으니 현존 사실·의도 id만 유효 출처로 인정
        valid = {n.id for n in graph.recent_facts(limit=10_000)}
        valid |= {n.id for n in graph.running_intents()}
        last_err = ""
        for attempt in range(self.retries + 1):
            prompt = user if attempt == 0 else user + (
                "\n\n(직전 응답이 올바른 JSON이 아니었다. 설명 없이 지정된 JSON 객체 하나만 출력하라.)")
            try:
                text = self._chat(PLANNER_SYSTEM, prompt, timeout)
            except Exception as e:  # noqa: BLE001 — 호출 실패는 이 라운드 계획 실패로(엔진이 판단)
                last_err = f"llm 호출 실패: {type(e).__name__}: {e}"
                continue
            try:
                intents = parse_intents(text or "")
            except LLMJsonError as e:
                last_err = f"파싱 실패: {e}"
                continue
            # 워커 겹침 방지: 같은 자산(target)을 '동시에' 겨냥하는 의도는 떨군다.
            #   - 이미 떠 있는(open/running) 의도의 target + 이번 배치 내 target 으로 중복 차단.
            #   - 빈 target 은 자산 식별 불가 → 안 떨군다. 탐색 끝난 자산 '재겨냥'(재검증)은
            #     여기서 안 막는다(종료 상태 의도는 안 보므로) — 라운드 간 재검증 보존.
            inflight = {_norm_target(n.payload.get("target", ""))
                        for n in graph.running_intents() + graph.frontier(limit=10_000)}
            inflight.discard("")
            # 성공 — 각 의도를 출처(from 사실들 → 없으면 default_parent)에 연결해 추가
            added: list[int] = []
            seen_batch: set[str] = set()
            deduped = 0
            for pi in intents:
                key = _norm_target(pi.target)
                if key and (key in inflight or key in seen_batch):
                    deduped += 1                 # 같은 자산 동시 겨냥 → 생략(워커 낭비 방지)
                    continue
                if key:
                    seen_batch.add(key)
                srcs = [i for i in (pi.from_facts or []) if i in valid]
                if not srcs and default_parent is not None:
                    srcs = [default_parent]          # 개막·무출처 의도는 목표에서 파생
                if spawned_by is not None:
                    srcs.append(spawned_by)
                iid = graph.add_intent(pi.to_payload(), origin="planner",
                                       spawned_by=srcs or None)
                if pi.technique:                     # 프로비넌스: 의도 → KG 기법(SELECTED)
                    try:
                        graph.select_knowledge(iid, [pi.technique])
                    except Exception:  # noqa: BLE001 — 프로비넌스 실패는 계획을 막지 않음
                        pass
                added.append(iid)
            return PlanResult(added_ids=added, proposed=len(intents), deduped=deduped)
        return PlanResult(added_ids=[], proposed=0, error=last_err)


__all__ = [
    "Planner", "PlanResult", "SelectResult", "PlannerIntent", "KnowledgeSelection",
    "PLANNER_SYSTEM", "SELECT_SYSTEM",
    "build_situation", "parse_intents", "parse_selection", "render_selection",
]
