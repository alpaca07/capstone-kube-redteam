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

# ── 파싱 재시도 진단 — attacker/react_loop.py 의 3분기 전략과 동일 계약(finish_reason 기반) ──
# Qwen3 계열은 Ollama /v1 에서 reasoning_effort='none' 이 간헐적으로 안 먹혀 <think> 가 토큰
# 상한을 다 먹고 content 가 '{' 만 연 채 끊긴다(finish=='length', 내용은 있지만 사고가 대부분) →
# 매 라운드 똑같이 재현되는 "JSON 객체가 닫히지 않음" 연속 실패의 근본 원인. cap 을 키워봐도
# 더 길게 생각할 뿐이라 — 빈 content 면 cap 을 확 줄여 빨리 자르고 /no_think 로 전환한다.
_FORMAT_RETRY_NOTE = "\n\n(직전 응답이 올바른 JSON이 아니었다. 설명 없이 지정된 JSON 객체 하나만 출력하라.)"
_LENGTH_RETRY_NOTE = ("\n\n(직전 응답이 너무 길어 잘렸다. 설명 문장을 쓰지 말고 "
                      "JSON 객체 하나만 출력하라.)")
_NO_THINK_NOTE = "\n\n/no_think"
_OVERFLOW_CAP = 512   # 사고 overflow(빈 content) 감지 시 — 재시도 낭비 줄이려 확 줄임


def _next_retry(finish: Optional[str], text: str, cap: int) -> tuple[int, str]:
    """파싱 실패 1건을 보고 (다음 호출 max_tokens, 다음 프롬프트에 덧붙일 문구) 를 고른다.
    cap 은 '잘렸다고 키우지 않는다'(장황함만 조장) — 사고 overflow(빈 content)일 때만 줄인다."""
    if finish == "length" and not text.strip():      # 사고 overflow(빈 content) → cap 축소+폴백
        return _OVERFLOW_CAP, _NO_THINK_NOTE
    if finish == "length":                            # 내용 있는 잘림(장황함) → cap 유지 + '짧게'
        return cap, _LENGTH_RETRY_NOTE
    return cap, _FORMAT_RETRY_NOTE                     # 형식 위반 → cap 유지 + 형식 재지시


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
(a worker already probed it), [untouched], or [closed:R<N> <reason>] (previously PROVEN to \
not hold the goal data — do NOT propose intents against a [closed] asset; it is a confirmed \
dead end. Child endpoints of a closed asset stay open unless closed themselves). Prefer \
[untouched] assets and ones not already covered by recent facts or in-flight intents — spend \
new intents on unexplored surface.
- BALANCE breadth with DEPTH — do not spend every intent opening new ground. Whenever a recent \
fact or known asset is a concrete lead toward the GOAL (a secret/credential/token endpoint, a \
reachable service on the path to the crown), dedicate at least one intent to DRIVING THAT LEAD \
to an actual compromise end-to-end. A single path finished to the goal beats ten assets mapped.
- MATCH the method to the asset. Data held in a DATABASE is exfiltrated by connecting to that DB \
service with a DB credential and running a query on the target tables — NOT with a Kubernetes \
service-account token or the K8s secrets API, which return cluster objects, not table rows. When \
the goal asset is a database and a DB credential has been found, dedicate an intent to connecting \
to the DB service and reading the target tables directly.
- Do NOT keep proposing intents that enumerate the Kubernetes API, service-account tokens, or \
cluster Secrets once the foothold's own SA has shown it is unprivileged (no token mounted, or a \
prior intent already got 401/403 from the API server). That path is RBAC-locked by design here — \
re-proposing it burns intents. Spend them on the network kill chain instead: enumerate reachable \
services, compromise the exposed app (its admin/manager interface or a known CVE) to pivot deeper, \
and drive toward the database that holds the goal data.
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
- "enables": when this intent USES one of the UNUSED FINDINGS (a credential/access already \
obtained), list that finding's F-number(s) here. This records finding→follow-up so the credential \
is marked used and not re-discovered next wave. Use [] when the intent builds on no prior finding.
- PREVIOUSLY BREACHED, when shown, lists accesses achieved in an EARLIER round. The defender may \
have patched them between rounds, so they are NOT done: when one lies on the path to the goal, \
propose an intent to RE-VERIFY it still works this round (and find another route if now blocked).
- APPROACHES ALREADY TRIED, when shown, lists intents from earlier rounds/waves that RAN AND \
PRODUCED NO BREACH. These are failure memory — do NOT propose a near-identical intent against \
the same target. If a target really does need another attempt, the new intent's "summary" MUST \
describe a genuinely different angle (different technique, different endpoint path, new evidence \
from RECENT FACTS). Repeating an already-tried approach wastes intents and the attempt count \
on that target stacks up as proof that the lead is not productive — spend your intents elsewhere.
- TARGETS MUST BE REAL. The "target" field MUST name an asset (or a child endpoint path, e.g. \
'host.name/path') that appears in KNOWN ASSETS above, OR the exact string "cluster-network" / \
"current-pod" for pod-local/foothold-level probes. Do NOT invent service names, namespaces, or \
FQDNs that are not in KNOWN ASSETS (e.g. a 'prod' or 'production' namespace that was never \
observed). Inventing targets burns an intent on a non-existent asset and yields nothing.
- Judge "goal reached" ONLY from THIS round's RECENT FACTS, never from PREVIOUSLY BREACHED. \
Return an empty "intents" list only when this round's facts already show the goal reached.

Output ONLY a JSON object, no prose:
{"intents": [{"summary": "<one-line direction>", "target": "<asset>", \
"why": "<why it advances the goal>", "technique": "<MITRE id or empty>", \
"plan": ["<step 1>", "<step 2>"], "from": [<fact id numbers this builds on>], \
"enables": [<F-numbers from UNUSED FINDINGS this intent uses, else empty>]}]}"""


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
    from_findings: Optional[list] = None  # 이 의도가 활용하는 finding id들(ENABLES — 발견→후속 의도)

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

    def chat_text_meta(self, system: str, user: str, **kw) -> tuple[str, Optional[str]]:
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
                    prior_findings_block: str = "", unexploited_block: str = "",
                    attempts_block: str = "",
                    facts_limit: int = 20,
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

    if unexploited_block:                     # 확보했으나 아직 안 쓴 발견(자격증명·접근) → 후속 의도로
        parts.append(
            "UNUSED FINDINGS (credentials/accesses already obtained but NOT yet leveraged — "
            "each line is 'F<id>: ...'). For every one that advances the GOAL, add ONE follow-up "
            "intent that USES it against the next target (e.g. authenticate to a service with the "
            "credential, or pivot deeper), and put that finding's number in \"enables\": [<id>]. "
            "Do not merely re-discover it — act on it:\n" + unexploited_block)

    if prior_findings_block:                 # 지난 라운드 침해 → 재검증 대상(공진화)
        parts.append("PREVIOUSLY BREACHED (last round — re-verify, may be patched):\n"
                     + prior_findings_block)

    if attempts_block:                       # 시도했으나 침해 없음 — 라운드 간 반복 재제안 방지
        parts.append(
            "APPROACHES ALREADY TRIED (previous rounds/waves ran these and got no breach — "
            "DO NOT propose a near-identical intent against the same target. If you must revisit "
            "one, state a genuinely DIFFERENT angle in \"summary\" and \"why\" — a new technique, "
            "a different endpoint path, fresh evidence that changes the picture. Repeating the "
            "same approach wastes intents and the attempt count stacks up as proof of futility):\n"
            + attempts_block)

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
            from_facts=_parse_ids(it.get("from")),
            from_findings=_parse_ids(it.get("enables"))))
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


def _norm_summary(s: str) -> str:
    """summary 정규화 — 내부 공백 정리 + 소문자. 완전 일치 dedup 용(같은 target 아니어도 문장 그대로 겹치면 중복)."""
    return " ".join((s or "").split()).lower()


_HALLUCINATION_RE = re.compile(r"[./:]")   # FQDN·경로·IP·포트 같이 '구체 이름' 냄새 패턴


def _target_tokens(t: str) -> list[str]:
    """콤마·슬래시 분해 후 첫 토큰(호스트:포트/경로)만 남김 — 콤마 리스트 target 을 자산명 단위로."""
    t = (t or "").strip()
    if not t:
        return []
    out: list[str] = []
    for chunk in t.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        # 'host.name/path' → 'host.name' (엔드포인트 경로는 자산명 매칭에서 호스트명으로 환원)
        host = chunk.split("/", 1)[0].strip().lower()
        if host:
            out.append(host)
    return out


def _is_hallucinated_target(target: str, known: set) -> bool:
    """target 이 KNOWN ASSETS 에 전혀 없고, FQDN/경로/IP 같은 '구체 이름' 냄새가 나면 유령으로 판정.
    'cluster-network' 처럼 특수 허용값은 known 에 포함돼 들어와 통과. 빈 target 은 유령 아님(그 자체로 허용).
    느슨한 서술형 target(예: 'DB service')엔 개입 안 함 — 구체 이름(hallucinated FQDN)만 잡는다."""
    t = (target or "").strip()
    if not t or not known:
        return False
    tokens = _target_tokens(t)
    if not tokens:
        return False
    # 하나라도 KNOWN 과 매칭되거나, 어느 KNOWN 의 서브스트링이면 통과(엔드포인트 경로 포함)
    for tok in tokens:
        if tok in known:
            return False
        for name in known:
            if tok and (tok in name or name in tok):
                return False
    # 모든 토큰이 미매칭 — '구체 이름' 냄새(점·슬래시·콜론)가 나면 유령으로 판정
    return any(_HALLUCINATION_RE.search(tok) for tok in tokens)


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
    deduped: int = 0               # 자산 겹침·요약 일치로 떨군 의도 수(워커 동시 중복 방지)
    dropped_ghost: int = 0         # KNOWN ASSETS 에 없는 유령 target 으로 떨군 수(환각 가드)

    @property
    def goal_reached_signal(self) -> bool:
        """제안 0개 = 플래너가 '더 팔 방향 없음/목표 달성'으로 본 신호(에러 아닐 때)."""
        return not self.error and self.proposed == 0


# ───────────── 폐쇄 승격(closure promotion) — 2단 게이트의 플래너 쪽 ─────────────
# 워커가 사실에 closure_candidate 를 달면(1단: 워커 신호), 플래너가 다음 라운드 전에
# 그 후보들을 보고 '정말 그 자산을 영구 폐쇄할 증거인가' 를 재판(2단: 플래너 승격). 통과한
# 것만 asset_graph.add_closure() → _asset_situation 에 [closed:R<N> <reason>] 로 영구 표시
# → PLANNER_SYSTEM 룰이 그 자산에 새 의도 생성 금지. 비대칭 보완: ENABLES 가 '성공 리드'를
# 영구 추적하듯 closure 는 '막다른 리드' 를 영구 추적한다.
CLOSURE_SYSTEM = """\
You are the CLOSURE REVIEWER of an authorized, sandboxed red-team planner. A worker has \
flagged one or more facts with closure_candidate=true, claiming the referenced asset does \
NOT hold the goal data. Your job: REJECT those claims unless they meet ALL of these strict \
criteria (err heavily toward keeping the asset open — a wrongly closed asset is a dead \
investigation):

1) The worker had READ access to the asset (query succeeded, response parsed, content seen) \
— NOT a transient failure (DNS, timeout, 403, 404, auth-required, connection refused).
2) The asset was fully read, not a subset (e.g. "Solr demo core has no PII" is NOT a full \
read of the Solr cluster — other cores may exist; "the /api/customers endpoint returned []" \
IS a full read of that endpoint).
3) The absence of goal data is positively confirmed by the evidence line, not inferred.

Close only AT THE ENDPOINT/CHILD LEVEL the evidence actually covers — never the whole \
service or whole host unless the evidence actually covered the whole service/host.

Output ONLY a JSON object, no prose:
{"closures": [{"fact_id": <F#>, "reason": "<<=15 words, states what was read and what was \
absent>"}]}
Return "closures": [] when nothing meets the criteria. Omit candidates that fail any \
criterion — do not try to salvage them with reworded reasons."""


@dataclass
class PromoteResult:
    closed_ids: list[int]          # 이번에 asset_graph 에 폐쇄 태그가 달린 자산 id들
    reviewed: int                  # 플래너가 검토한 후보 사실 수
    rejected: int = 0              # 심사에서 떨군 후보 수(엄격한 기준에 못 미침)
    error: str = ""                # 파싱/호출 실패 — 폐쇄 승격 생략(라운드 자체는 계속)


class Planner:
    def __init__(self, llm: _LLM, *, goal: str, max_tokens: int = 3000,
                 retries: int = 1, target_intents: int = 4) -> None:
        self.llm = llm
        self.goal = goal
        self.max_tokens = max_tokens      # 정렬=추론 모델이라 넉넉히(JSON 잘림 방지)
        self.retries = retries
        self.target_intents = max(1, int(target_intents))   # 웨이브당 의도 목표 수(=워커 수)

    def _chat_meta(self, system: str, user: str, timeout: Optional[float], *,
                   max_tokens: Optional[int] = None) -> tuple[str, Optional[str]]:
        """(응답, finish_reason) — finish=='length' 면 토큰 상한에 '잘림'(ReAct 루프와 동일 계약).
        max_tokens 를 호출마다 override 가능 — 사고(thinking) overflow 감지 시 cap 을 줄여 재시도."""
        return self.llm.chat_text_meta(
            system, user, max_tokens=max_tokens if max_tokens is not None else self.max_tokens,
            timeout=timeout, extra={"reasoning_effort": "none"})

    # ── 0차: 폐쇄 승격(2단 게이트의 플래너 쪽) ──
    def promote_closures(self, graph: ExplorationGraph, asset_graph,
                         *, round: int, timeout: Optional[float] = None) -> PromoteResult:
        """지난 라운드까지의 closure_candidate 사실들을 심사해 승격분만 asset_graph 에 폐쇄 태그.

        반드시 라운드 시작 '전' 에 1회 호출 — 그래야 _asset_situation 에 [closed] 표시가 붙은
        채로 플래너가 의도를 낸다. asset_graph 없으면 아무 것도 안 함(단위테스트/오프라인).
        승격은 '사실 payload 의 closure_candidate=true 그리고 promoted=false' 인 것만 대상.
        승격 결과는 사실 payload 에 promoted=round 로 기록 → 다음 라운드엔 재심사 안 함."""
        if asset_graph is None or round <= 0:
            return PromoteResult(closed_ids=[], reviewed=0)
        # 후보 수집: closure_candidate==true & 아직 심사 안 됨 & 앵커가 있어 자산으로 해소 가능
        cands: list[Node] = []
        for f in graph.recent_facts(limit=10_000):
            p = f.payload
            if not p.get("closure_candidate"):
                continue
            if p.get("promoted"):                 # 이미 심사된 후보(승격이든 거부든) 재심사 안 함
                continue
            if not f.anchors:                     # 앵커 없는 후보는 자산으로 해소 불가 → 스킵
                continue
            cands.append(f)
        if not cands:
            return PromoteResult(closed_ids=[], reviewed=0)
        # 심사용 블록 — F#·앵커자산명·evidence 를 간결히
        lines: list[str] = []
        fact_by_id: dict[int, Node] = {f.id: f for f in cands}
        for f in cands:
            ev = (f.payload.get("evidence") or f.payload.get("detail")
                  or f.payload.get("summary") or "")[:200]
            names = [asset_graph.get_asset(aid).name for aid in f.anchors
                     if asset_graph.get_asset(aid) is not None]
            tgt = ", ".join(names[:3]) if names else "(no asset)"
            lines.append(f"F{f.id} on [{tgt}]: {f.payload.get('summary','')} | evidence: {ev}")
        user = ("CLOSURE CANDIDATES (worker-flagged, needs your strict review):\n"
                + "\n".join(lines))
        try:
            text, _finish = self._chat_meta(CLOSURE_SYSTEM, user, timeout)
        except Exception as e:  # noqa: BLE001 — 호출 실패는 승격 생략(라운드 자체 계속)
            return PromoteResult(closed_ids=[], reviewed=len(cands),
                                 error=f"llm 호출 실패: {type(e).__name__}: {e}")
        # 파싱 — 실패하면 이번 라운드 승격 생략(그래도 다음 라운드엔 재심사; promoted 플래그 안 찍음)
        try:
            obj = extract_and_load(text or "")
        except LLMJsonError as e:
            return PromoteResult(closed_ids=[], reviewed=len(cands), error=f"파싱 실패: {e}")
        approved: list[dict] = []
        for it in (obj.get("closures", []) if isinstance(obj, dict) else []) or []:
            if not isinstance(it, dict):
                continue
            try:
                fid = int(it.get("fact_id"))
            except (TypeError, ValueError):
                continue
            if fid not in fact_by_id:
                continue
            approved.append({"fact_id": fid, "reason": str(it.get("reason", "")).strip()})
        # 적용 — 승격된 후보의 앵커 자산들에 closure 를 건다. 거부된 후보도 promoted 는 찍어
        # (재심사 루프 방지 — 워커가 또 같은 신호를 내면 새 사실 id 로 들어오므로 괜찮다).
        closed_ids: list[int] = []
        approved_fids = {a["fact_id"] for a in approved}
        for a in approved:
            f = fact_by_id[a["fact_id"]]
            for aid in f.anchors:
                if asset_graph.add_closure(aid, round=round, reason=a["reason"] or "proven empty"):
                    closed_ids.append(aid)
        # 심사된 모든 후보에 promoted 플래그 → 재심사 방지
        for f in cands:
            try:
                graph.annotate_fact(f.id, {"promoted": int(round)})
            except Exception:   # noqa: BLE001 — annotate 미지원이면 플래그 없이도 다음 라운드엔
                pass             # 같은 후보가 다시 cand 로 잡히지만 폐쇄는 idempotent(이미 닫힘 반환)
        return PromoteResult(closed_ids=closed_ids, reviewed=len(cands),
                             rejected=len(cands) - len(approved_fids))

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
        cap = self.max_tokens
        retry_note = _FORMAT_RETRY_NOTE
        for attempt in range(self.retries + 1):
            prompt = user if attempt == 0 else user + retry_note
            try:
                text, finish = self._chat_meta(SELECT_SYSTEM, prompt, timeout, max_tokens=cap)
            except Exception as e:  # noqa: BLE001 — 호출 실패는 선별 실패(2차가 폴백)
                last_err = f"llm 호출 실패: {type(e).__name__}: {e}"
                continue
            try:
                return SelectResult(selected=parse_selection(text or ""), error="")
            except LLMJsonError as e:
                t = text or ""
                last_err = f"파싱 실패: {e} (finish={finish} len={len(t)})"
                cap, retry_note = _next_retry(finish, t, cap)
                continue
        return SelectResult(selected=[], error=last_err)

    # ── 2차: 의도·계획 생성 ──
    def plan(self, graph: ExplorationGraph, *, assets_block: str = "",
             selected_block: str = "", prior_findings_block: str = "",
             unexploited_block: str = "", attempts_block: str = "",
             known_asset_names: Optional[set] = None,
             spawned_by: Optional[int] = None,
             default_parent: Optional[int] = None,
             timeout: Optional[float] = None) -> PlanResult:
        """1차 선별(selected_block)을 받아 의도노드+공격계획(plan)을 생성해 frontier에 추가.

        각 의도는 'from'(출처 사실 id, 없으면 default_parent)으로 그래프에 연결되고, technique
        가 있으면 graph.select_knowledge 로 KG 기법에 SELECTED 프로비넌스를 남긴다.

        known_asset_names: 'KNOWN ASSETS'에 실재하는 자산 이름 집합(소문자). 유령 target 가드.
        None 이면 가드 건너뜀(기존 호출 호환).
        """
        user = build_situation(graph, goal=self.goal, assets_block=assets_block,
                               selected_block=selected_block,
                               prior_findings_block=prior_findings_block,
                               unexploited_block=unexploited_block,
                               attempts_block=attempts_block,
                               target_intents=self.target_intents)
        # 플래너가 헛 id를 낼 수 있으니 현존 사실·의도 id만 유효 출처로 인정
        valid = {n.id for n in graph.recent_facts(limit=10_000)}
        valid |= {n.id for n in graph.running_intents()}
        valid_findings = {n.id for n in graph.recent_findings(limit=10_000)}  # enables 검증용
        last_err = ""
        cap = self.max_tokens
        retry_note = _FORMAT_RETRY_NOTE
        for attempt in range(self.retries + 1):
            prompt = user if attempt == 0 else user + retry_note
            try:
                text, finish = self._chat_meta(PLANNER_SYSTEM, prompt, timeout, max_tokens=cap)
            except Exception as e:  # noqa: BLE001 — 호출 실패는 이 라운드 계획 실패로(엔진이 판단)
                last_err = f"llm 호출 실패: {type(e).__name__}: {e}"
                continue
            try:
                intents = parse_intents(text or "")
            except LLMJsonError as e:
                t = text or ""
                last_err = f"파싱 실패: {e} (finish={finish} len={len(t)})"
                cap, retry_note = _next_retry(finish, t, cap)
                continue
            # 워커 겹침 방지 — 같은 자산(target)이나 같은 요약(summary)의 중복 의도를 떨군다.
            # 'inflight' 는 ① 떠 있는(open/running) 의도 ② 이번 라운드에 이미 완료된(done/exhausted)
            # 의도 모두 커버 → 같은 라운드 웨이브→웨이브 사이 중복(R34 복제 케이스) 결정론적 차단.
            # summary 완전 일치도 dedup 키에 포함(동일 자산 아니어도 문자열 같은 의도는 중복으로 본다).
            # 라운드 간 재제안은 'ATTEMPTS ALREADY TRIED' 블록으로 플래너 판단에 맡김(여기선 안 막음).
            cur_round = 0
            try:
                cur_round = int(getattr(graph, "_cur_round", 0) or 0)
            except (TypeError, AttributeError):
                pass
            inflight_tgt: set[str] = {_norm_target(n.payload.get("target", ""))
                                      for n in graph.running_intents()
                                      + graph.frontier(limit=10_000)}
            inflight_sum: set[str] = {_norm_summary(n.payload.get("summary", ""))
                                      for n in graph.running_intents()
                                      + graph.frontier(limit=10_000)}
            # 이번 라운드에 이미 완료된 의도들도 inflight 에 넣어 웨이브 간 재생성을 막는다.
            # cur_round==0 (라운드 스탬프 미사용 백엔드/테스트)일 땐 이 확장만 건너뜀 — 기존 동작 호환.
            if cur_round > 0:
                for n in graph.recent_attempts(limit=200):
                    if int(n.payload.get("_round") or 0) == cur_round:
                        inflight_tgt.add(_norm_target(n.payload.get("target", "")))
                        inflight_sum.add(_norm_summary(n.payload.get("summary", "")))
            inflight_tgt.discard(""); inflight_sum.discard("")
            # 성공 — 각 의도를 출처(from 사실들 → 없으면 default_parent)에 연결해 추가
            added: list[int] = []
            seen_batch_tgt: set[str] = set()
            seen_batch_sum: set[str] = set()
            deduped = 0
            dropped_ghost = 0
            for pi in intents:
                tkey = _norm_target(pi.target)
                skey = _norm_summary(pi.summary)
                # 유령 target 가드 — KNOWN ASSETS 에 없는 구체 이름(FQDN·경로)만 드롭(느슨한 서술형은 통과).
                if (known_asset_names is not None
                        and _is_hallucinated_target(pi.target, known_asset_names)):
                    dropped_ghost += 1
                    continue
                if (tkey and (tkey in inflight_tgt or tkey in seen_batch_tgt)) \
                        or (skey and (skey in inflight_sum or skey in seen_batch_sum)):
                    deduped += 1                 # 같은 자산·같은 요약 → 생략
                    continue
                if tkey:
                    seen_batch_tgt.add(tkey)
                if skey:
                    seen_batch_sum.add(skey)
                srcs = [i for i in (pi.from_facts or []) if i in valid]
                if not srcs and default_parent is not None:
                    srcs = [default_parent]          # 개막·무출처 의도는 목표에서 파생
                if spawned_by is not None:
                    srcs.append(spawned_by)
                ens = [i for i in (pi.from_findings or []) if i in valid_findings]
                iid = graph.add_intent(pi.to_payload(), origin="planner",
                                       spawned_by=srcs or None, enabled_by=ens or None)
                if pi.technique:                     # 프로비넌스: 의도 → KG 기법(SELECTED)
                    try:
                        graph.select_knowledge(iid, [pi.technique])
                    except Exception:  # noqa: BLE001 — 프로비넌스 실패는 계획을 막지 않음
                        pass
                added.append(iid)
            return PlanResult(added_ids=added, proposed=len(intents),
                              deduped=deduped, dropped_ghost=dropped_ghost)
        return PlanResult(added_ids=[], proposed=0, error=last_err)


__all__ = [
    "Planner", "PlanResult", "SelectResult", "PlannerIntent", "KnowledgeSelection",
    "PLANNER_SYSTEM", "SELECT_SYSTEM",
    "build_situation", "parse_intents", "parse_selection", "render_selection",
]
