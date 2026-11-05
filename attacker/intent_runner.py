"""의도 실행기 — 워커 풀에 주입하는 '진짜 run_intent'. 의도 하나를 ReAct로 돌리고(탈옥
모델) 결론을 정착 호출(방식 B)로 fact/finding을 그래프에 쓴다.

병렬 워커 구조의 마지막 접합부: [[WorkerPool]]이 claim한 의도를 이 콜러블에 넘기면
  1) 의도-스코프 ReAct — 기존 [[ReActLoop]]을 재사용(executor=WorkerContext=공유 레인).
     round 목표를 배경으로, 이 의도의 방향(summary/target/why)을 전경으로 탐색.
  2) 정착 호출(방식 B 확정) — ReAct가 끝나면 LLM 한 번으로 '이번 의도에서 뭘 알아냈나'를
     구조화 JSON(facts[] + 선택 finding)으로 뽑아 그래프에 쓴다. fact는 '실행'이 아니라
     '결론'이라 재생 대본엔 안 들어가고, source_step_ids로 원본 스텝을 역참조만 한다.
  3) IntentOutcome 반환 — TIMEOUT→EXHAUSTED, 그 외→DONE. (예외는 풀이 BLOCKED로 격리)

LLM 주입 계약 → fake로 전 로직 테스트. 실제는 OllamaClient(탈옥, attacker_base_url).
상태 없는 콜러블이라 워커 스레드 N이 공유해도 안전(호출마다 지역 상태만).
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from common.llm_json import LLMJsonError, extract_and_load
from common.messages import AttackEndReason
from common.replay_schema import make_step_id

from .graph import ExplorationGraph, IntentState, Node
from .history import AttackHistory
from .react_loop import ReActLoop
from .worker_pool import IntentOutcome


SETTLE_SYSTEM = """\
You are concluding one exploration direction of an authorized, sandboxed red-team \
exercise. You have just run some commands toward a sub-goal. Summarize ONLY what you \
actually observed — conclusions, including NEGATIVE results (port closed, not \
injectable, no login found). Do not invent. Keep facts compact: usually one fact per \
direction, merging related observations.

Output ONLY a JSON object, no prose:
{"facts": [{"summary": "<one-line conclusion>", "detail": "<specifics, optional>", \
"evidence": "<command + the key output line that supports it>", \
"confidence": "observed|inferred"}], \
"finding": {"summary": "<the breach, if one was achieved>", "severity": "<low|medium|high|critical>", \
"evidence": "<what proves it>"}}
Set "finding" to null unless this direction actually achieved a concrete compromise."""


@dataclass
class FactDraft:
    summary: str
    detail: str = ""
    evidence: str = ""
    confidence: str = ""

    def to_payload(self, source_step_ids: list[str]) -> dict:
        p: dict = {"summary": self.summary}
        if self.detail:
            p["detail"] = self.detail
        if self.evidence:
            p["evidence"] = self.evidence
        if self.confidence:
            p["confidence"] = self.confidence
        if source_step_ids:
            p["source_step_ids"] = source_step_ids
        return p


@dataclass
class FindingDraft:
    summary: str
    severity: str = ""
    evidence: str = ""

    def to_payload(self, technique: str = "") -> dict:
        p: dict = {"summary": self.summary}
        if self.severity:
            p["severity"] = self.severity
        if self.evidence:
            p["evidence"] = self.evidence
        if technique:                       # 채점 조인 열쇠(공격보고 기법ID ↔ 심판 조건표)
            p["technique"] = technique
        return p


def parse_settlement(text: str) -> tuple[list[FactDraft], Optional[FindingDraft]]:
    """정착 응답에서 facts[] + 선택 finding을 느슨하게 뽑는다. 깨지면 LLMJsonError."""
    obj = extract_and_load(text)
    if not isinstance(obj, dict):
        raise LLMJsonError(f"객체가 아님: {type(obj).__name__}")
    facts: list[FactDraft] = []
    for it in obj.get("facts", []) or []:
        if not isinstance(it, dict):
            continue
        summary = str(it.get("summary", "")).strip()
        if not summary:
            continue
        facts.append(FactDraft(
            summary=summary,
            detail=str(it.get("detail", "")).strip(),
            evidence=str(it.get("evidence", "")).strip(),
            confidence=str(it.get("confidence", "")).strip()))
    finding = None
    f = obj.get("finding")
    if isinstance(f, dict) and str(f.get("summary", "")).strip():
        finding = FindingDraft(
            summary=str(f["summary"]).strip(),
            severity=str(f.get("severity", "")).strip(),
            evidence=str(f.get("evidence", "")).strip())
    return facts, finding


@dataclass
class IntentRunnerConfig:
    system_prompt: str                      # 탈옥 공격 시스템 프롬프트(ReAct용)
    round_goal: str                         # 이 라운드의 크라운 목표(배경)
    flag_format: str = "FLAG{...}"
    intent_budget_sec: float = 120.0        # 의도 하나당 시간 예산
    max_steps: int = 20
    react_max_tokens: Optional[int] = None
    settle_max_tokens: int = 1500


def _intent_goal(round_goal: str, intent: Node) -> str:
    """ReAct 프롬프트의 goal 슬롯에 넣을 '배경 목표 + 이번 의도 방향'."""
    p = intent.payload
    parts = [f"ROUND GOAL (background): {round_goal}",
             f"CURRENT DIRECTION (focus this turn): {p.get('summary', '')}"]
    if p.get("target"):
        parts.append(f"  target: {p['target']}")
    if p.get("why"):
        parts.append(f"  why: {p['why']}")
    return "\n".join(parts)


class IntentRunner:
    """워커 풀에 주입하는 run_intent 콜러블. run_intent(graph, wctx, intent)->IntentOutcome."""

    def __init__(self, llm, cfg: IntentRunnerConfig, *, settle_llm=None,
                 log: Optional[Callable[[str], None]] = None) -> None:
        self.llm = llm                      # 탈옥 모델(ReAct 행동 + 기본 정착)
        self.settle_llm = settle_llm or llm
        self.cfg = cfg
        self.log = log or (lambda m: None)

    def __call__(self, graph: ExplorationGraph, wctx, intent: Node) -> IntentOutcome:
        history = AttackHistory()
        wid = getattr(wctx, "wid", "?")          # 어느 워커가 이 의도를 돌리는지(로그 가시화)
        tag = f"[{wid}·intent#{intent.id}]"
        loop = ReActLoop(
            self.llm, wctx, history,
            system_prompt=self.cfg.system_prompt,
            goal=_intent_goal(self.cfg.round_goal, intent),
            flag_format=self.cfg.flag_format,
            time_limit_sec=self.cfg.intent_budget_sec,
            max_steps=self.cfg.max_steps,
            max_tokens=self.cfg.react_max_tokens,
            log=lambda m: self.log(f"{tag} {m}"))
        result = loop.run(foothold=getattr(wctx, "foothold", None))

        # 이 의도가 만든 스텝들의 전역 step_id (fact가 원본을 역참조)
        round_no = wctx.lane.script.round
        source_step_ids = [make_step_id(round_no, e.step) for e in history.entries]

        self._settle(graph, intent, history, source_step_ids, tag=tag)

        # 종료사유 → 의도 정착 상태. TIMEOUT만 EXHAUSTED(부분결과 보존), 나머지는 DONE.
        state = (IntentState.EXHAUSTED if result.end_reason == AttackEndReason.TIMEOUT
                 else IntentState.DONE)
        return IntentOutcome(state, reason=result.end_reason.value)

    def _settle(self, graph: ExplorationGraph, intent: Node, history: AttackHistory,
                source_step_ids: list[str], *, tag: str = "") -> None:
        """정착 호출(방식 B): 결론을 fact/finding으로 그래프에 쓴다. 실패해도 의도는 안 잃고
        히스토리 요약을 폴백 fact로 남긴다."""
        technique = str(intent.payload.get("technique", "")).strip()
        try:
            text = self.settle_llm.chat_text(
                SETTLE_SYSTEM,
                f"Exploration direction:\n{_intent_goal('', intent)}\n\n"
                f"What you observed:\n{history.render()}\n\n"
                "Summarize your conclusions as the specified JSON object.",
                max_tokens=self.cfg.settle_max_tokens,
                extra={"reasoning_effort": "none"})
            facts, finding = parse_settlement(text or "")
        except Exception as e:  # noqa: BLE001 — 정착 실패는 치명적 아님(폴백)
            self.log(f"{tag} 정착 실패({type(e).__name__}) → 폴백 fact")
            facts, finding = [], None

        if not facts:
            # 폴백: 기계적 요약이라도 남겨 의도가 빈손으로 끝나지 않게(음성 결론 포함)
            facts = [FactDraft(summary=f"의도 #{intent.id} 탐색 결과",
                               detail=history.summarize(), confidence="inferred")]

        fact_ids = [graph.add_fact(fd.to_payload(source_step_ids), intent_id=intent.id)
                    for fd in facts]
        if finding is not None:
            graph.add_finding(finding.to_payload(technique), proved_by=fact_ids)

        # 정착 결과 한 줄 — '의도대로 결론을 냈는지' 가시화
        first = facts[0].summary if facts else ""
        if len(first) > 100:
            first = first[:100] + "…"
        extra = f" + 발견({finding.severity}): {finding.summary}" if finding is not None else ""
        self.log(f"{tag} ⇒ 사실 {len(facts)}개: {first}{extra}")


__all__ = [
    "IntentRunner", "IntentRunnerConfig", "parse_settlement",
    "FactDraft", "FindingDraft", "SETTLE_SYSTEM",
]
