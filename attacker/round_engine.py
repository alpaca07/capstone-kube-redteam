"""라운드 엔진 — 플래너·워커 풀·실행 레인을 묶어 공격 턴 하나를 돌린다.

병렬 워커 구조의 최상위 조립. attack_turn_start 하나로:
  1) 플래너(정렬 모델)가 태세를 읽어 의도를 frontier에 뿌린다.
  2) 워커 풀(탈옥 모델 N)이 그 의도들을 claim해 ReAct로 돌리고(실행은 공유 레인에 직렬),
     결론을 fact/finding으로 그래프에 쓴다.
  3) 플래너가 쌓인 사실을 다시 읽어 다음 의도를 뿌린다 → 다음 웨이브. 플래너가 더 낼
     방향이 없거나(목표 달성/막다른 길) 라운드 시간 T가 소진되면 종료.
  4) 레인의 replay_script·플래그·그래프 사실로 AttackTurnResult를 조립.

스코프 분리(이번 세션 확정): 그래프=회차(라운드 넘어 지속, 공진화 기억) → 호출자가
주입. 실행 레인=라운드(대본은 라운드당 하나) → 여기서 라운드마다 새로 만든다.

동시성 모델: 플래너는 '웨이브 사이'에 돈다(웨이브 내 워커 추론은 병렬). 완전한 이벤트
구동(플래너 동시 실행)은 이후 개선. clock 주입 → 시간 로직 결정적 테스트.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

from common.messages import AttackEndReason, AttackTurnResult, AttackTurnStart

from .exec_lane import ExecutionLane
from .graph import ExplorationGraph
from .graph_fake import InMemoryGraph
from .intent_runner import IntentRunner, IntentRunnerConfig
from .planner import Planner
from .scope import ScopePolicy
from .worker_pool import WorkerPool


@dataclass
class RoundConfig:
    system_prompt: str                       # 탈옥 공격 시스템 프롬프트(워커 ReAct)
    session_id: str = "vmA"
    step_timeout: float = 60.0
    n_workers: int = 2
    intent_budget_sec: float = 120.0         # 의도 하나당 시간 예산
    intent_max_steps: int = 20
    react_max_tokens: Optional[int] = None
    planner_max_tokens: int = 3000
    max_waves: int = 6                        # 라운드당 플래너 웨이브 상한(안전장치)


def _foothold_dict(start: AttackTurnStart) -> Optional[dict]:
    if start.foothold is None:
        return None
    return {"attack_endpoint": start.foothold.attack_endpoint}


def _foothold_line(start: AttackTurnStart) -> str:
    """발판(진입점) 한 줄 — 자산 지형이 비어도 진입점은 항상 보이게."""
    if start.foothold is None:
        return ""
    return f"- foothold entry point: {start.foothold.attack_endpoint}"


def _asset_situation(asset_graph, *, foothold_line: str = "", touched=None,
                     limit: int = 40) -> str:
    """자산 그래프를 플래너가 겨냥할 '대상 지형'으로 렌더(계층: 부모→자식 들여쓰기).

    자산 그래프가 없거나 비면 발판 줄만(기존 동작과 호환). 식별된 자산(CPE 보유)은 ✓id 표시.
    touched(앵커된 자산 id 집합)를 주면 각 자산을 [explored]/[untouched]로 표시 → 플래너가
    아직 안 친 자산을 정확히 겨냥(사실·의도로 추론하던 걸 실제 앵커 기록으로 대체).
    순환(CONTAINS 사이클) 안전장치로 seen 집합을 둔다. 회차 범위 밖 자식은 안 돈다.
    """
    if asset_graph is None:
        return foothold_line
    assets = asset_graph.assets(limit=limit)
    if not assets:
        return foothold_line
    by_id = {a.id: a for a in assets}
    kids: dict[int, list] = {}
    child_ids: set[int] = set()
    for a in assets:
        ch = [c for c in asset_graph.children(a.id) if c.id in by_id]
        kids[a.id] = ch
        for c in ch:
            child_ids.add(c.id)
    lines: list[str] = [foothold_line] if foothold_line else []
    seen: set[int] = set()

    def _walk(a, depth: int) -> None:
        if a.id in seen:
            return
        seen.add(a.id)
        ident = " ✓id" if a.identified else ""
        mark = ""
        if touched is not None:                  # 앵커 기록으로 explored/untouched 표시
            mark = " [explored]" if a.id in touched else " [untouched]"
        lines.append(f"{'  ' * depth}- [{a.kind}] {a.name}{ident}{mark}")
        for c in kids.get(a.id, []):
            _walk(c, depth + 1)

    for a in assets:                     # 최상위(부모 없음)부터 계층대로
        if a.id not in child_ids:
            _walk(a, 0)
    for a in assets:                     # 부모가 범위 밖이라 안 걸린 고아도 빠짐없이
        _walk(a, 0)
    return "\n".join(lines)


def _prior_findings_block(graph: ExplorationGraph, prior_ids, asset_graph,
                          *, limit: int = 12) -> str:
    """지난 라운드 발견(스냅샷 id)을 'RE-VERIFY' 후보로 렌더. 앵커된 자산명을 붙인다.

    공진화 핵심: 누적 그래프가 R2 플래너에게 '이미 침해함→끝'으로 읽혀 재공격을 건너뛰는 걸
    막는다. 이 발견들은 지난 라운드 결과이므로 이번 라운드에 다시 통하는지 확인해야 한다.
    """
    if not prior_ids:
        return ""
    lines: list[str] = []
    for fid in sorted(prior_ids)[:limit]:
        n = graph.get_node(fid)
        if n is None:
            continue
        p = n.payload
        sev = f" [{p['severity']}]" if p.get("severity") else ""
        tech = f" ({p['technique']})" if p.get("technique") else ""
        tgt = ""
        if asset_graph is not None and n.anchors:
            names = [asset_graph.get_asset(aid).name for aid in n.anchors
                     if asset_graph.get_asset(aid) is not None]
            if names:
                tgt = " on " + ", ".join(names[:3])
        lines.append(f"- {p.get('summary', '')}{sev}{tech}{tgt}")
    return "\n".join(lines)


class AttackRound:
    """공격 턴 하나(멀티워커)를 돌려 AttackTurnResult를 조립한다."""

    def __init__(self, *, attacker_llm, planner_llm, runner, scope_policy: ScopePolicy,
                 cfg: RoundConfig, clock: Callable[[], float] = time.time,
                 log: Optional[Callable[[str], None]] = None) -> None:
        self.attacker_llm = attacker_llm
        self.planner_llm = planner_llm
        self.runner = runner
        self.scope = scope_policy
        self.cfg = cfg
        self.clock = clock
        self.log = log or (lambda m: None)

    def run(self, start: AttackTurnStart, *, episode: int, round: int,
            graph: Optional[ExplorationGraph] = None,
            asset_graph=None, kg_lookup=None) -> AttackTurnResult:
        t0 = self.clock()
        deadline = t0 + float(start.time_limit_sec)
        graph = graph if graph is not None else InMemoryGraph(episode=episode)

        # 대본은 라운드당 하나(레인). 그래프는 회차 스코프(주입).
        lane = ExecutionLane(
            self.runner, scope_policy=self.scope, session_id=self.cfg.session_id,
            episode=episode, round=round,
            step_timeout=self.cfg.step_timeout)

        # 의도 목표 수 = 워커 수. 워커를 늘리면 의도도 따라 늘어 병렬 포화. 단 억지 패딩은
        # 플래너 프롬프트에서 막는다(탐색 표면이 얇으면 목표보다 적게 내는 게 정상).
        planner = Planner(self.planner_llm, goal=start.goal,
                          max_tokens=self.cfg.planner_max_tokens,
                          target_intents=self.cfg.n_workers)
        intent_runner = IntentRunner(
            self.attacker_llm,
            IntentRunnerConfig(
                system_prompt=self.cfg.system_prompt, round_goal=start.goal,
                intent_budget_sec=self.cfg.intent_budget_sec,
                max_steps=self.cfg.intent_max_steps,
                react_max_tokens=(start.max_tokens or self.cfg.react_max_tokens)),
            asset_graph=asset_graph, log=self.log)

        foothold = _foothold_dict(start)
        foothold_line = _foothold_line(start)

        # 지난 라운드 발견 스냅샷: 그래프는 회차 스코프라 라운드 시작 시점에 '이미 있는'
        # 발견은 지난 라운드 것(R1은 새 그래프라 비어있음). 공진화 재검증 후보로 플래너에 준다.
        prior_finding_ids = ({n.id for n in graph.recent_findings(limit=10_000)}
                             if round > 1 else set())

        # 목표(goal) 노드 — 개막 의도의 루트. 그래프를 하나로 잇는다(의도 따로따로 방지).
        goal_id = graph.add_goal({"summary": start.goal})

        waves = 0
        planner_empty = False
        while waves < self.cfg.max_waves and self.clock() < deadline:
            # 자산 지형·지난 라운드 침해를 매 웨이브 새로 렌더(웨이브 중 자산이 더 쌓이므로).
            # touched=앵커된 자산 id → explored/untouched 표시로 미탐색 자산을 정확히 겨냥.
            touched = graph.anchored_asset_ids()
            assets_block = _asset_situation(asset_graph, foothold_line=foothold_line,
                                            touched=touched)
            # 자산 → KG 느슨 매칭 후보 기법(LLM 바인딩용). 콜백 없거나 히트 없으면 빈 블록.
            kg_block = ""
            if kg_lookup is not None and asset_graph is not None:
                try:
                    kg_block = kg_lookup(asset_graph) or ""
                except Exception as e:  # noqa: BLE001 — KG 조회 실패는 계획을 막지 않음(폴백)
                    self.log(f"[round r{round}] wave {waves+1}: KG 조회 실패({type(e).__name__}) → 생략")
            prior_block = _prior_findings_block(graph, prior_finding_ids, asset_graph)
            # 태세 요약 한 줄 — 자산 겨냥·재검증이 실제로 플래너에 들어가는지 저널에서 보이게.
            # (KNOWN ASSETS·PREVIOUSLY BREACHED 는 플래너 프롬프트라 저널엔 안 뜨므로 수치로 노출.)
            if asset_graph is not None:
                all_assets = asset_graph.assets(limit=200)
                n_untouched = sum(1 for a in all_assets if a.id not in touched)
                self.log(f"[round r{round}] wave {waves+1}: 태세 → 자산 {len(all_assets)}개"
                         f"(미탐색 {n_untouched}) · 지난라운드침해 {len(prior_finding_ids)}건")
            plan = planner.plan(graph, assets_block=assets_block, kg_block=kg_block,
                                prior_findings_block=prior_block, default_parent=goal_id,
                                timeout=max(5.0, deadline - self.clock()))   # 마감 넘겨 늘어지지 않게
            if not plan.added_ids:
                planner_empty = True        # 더 낼 방향 없음(목표 달성/막다른/계획 실패)
                self.log(f"[round r{round}] wave {waves+1}: 플래너 0개 → 종료 "
                         f"({plan.error or 'goal-reached/no-direction'})")
                break
            dd = f", 겹침 {plan.deduped}개 제거" if plan.deduped else ""
            self.log(f"[round r{round}] wave {waves+1}: 플래너가 의도 {len(plan.added_ids)}개 생성{dd}")
            for iid in plan.added_ids:          # 플래너가 무슨 방향을 냈는지 보여줌
                n = graph.get_node(iid)
                if n is not None:
                    p = n.payload
                    tgt = f" → {p['target']}" if p.get("target") else ""
                    tech = f" [{p['technique']}]" if p.get("technique") else ""
                    self.log(f"    · intent#{iid}: {p.get('summary','')}{tgt}{tech}")
            WorkerPool(graph, lane, intent_runner, n_workers=self.cfg.n_workers,
                       foothold=foothold, round_deadline=deadline,
                       clock=self.clock, log=self.log).run()
            waves += 1

        return self._assemble(lane, graph, start, t0, waves, planner_empty)

    def _assemble(self, lane: ExecutionLane, graph: ExplorationGraph,
                  start: AttackTurnStart, t0: float, waves: int,
                  planner_empty: bool) -> AttackTurnResult:
        # 종료사유: 시간 소진이면 TIMEOUT, 아니면 DEADEND(플래너 고갈).
        # 성공 판정은 공격자 자기보고가 아니라 심판이 접근기록(크라운)으로 내린다 — 플래그리스.
        if self.clock() >= t0 + float(start.time_limit_sec):
            end = AttackEndReason.TIMEOUT
        else:
            end = AttackEndReason.DEADEND

        return AttackTurnResult(
            end_reason=end, replay_script=lane.script,
            attack_summary=self._summary(graph, lane, waves),
            elapsed_sec=self.clock() - t0)

    def _summary(self, graph: ExplorationGraph, lane: ExecutionLane, waves: int) -> str:
        """VM C 기록용 자연어 요약(방어자엔 안 감). 그래프 사실·발견 집계."""
        facts = graph.recent_facts(limit=10_000)
        findings = graph.recent_findings(limit=10_000)
        lines = [f"{waves}개 웨이브 · 스텝 {len(lane.script.steps)}개 · "
                 f"사실 {len(facts)}개 · 발견 {len(findings)}개"]
        for f in findings[:5]:
            sev = f.payload.get("severity", "")
            tech = f.payload.get("technique", "")
            tag = f" [{tech}]" if tech else ""
            occ = f.payload.get("occurrences", 1)
            rep = f" (보고 {occ}회)" if occ and occ > 1 else ""
            lines.append(f"- 발견({sev}){tag}{rep}: {f.payload.get('summary', '')}")
        return "\n".join(lines)


__all__ = ["AttackRound", "RoundConfig"]
