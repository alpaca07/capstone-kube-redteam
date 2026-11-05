"""라운드 엔진 — 플래너·워커 풀·실행 레인을 묶어 공격 턴 하나를 돌린다.

병렬 워커 구조의 최상위 조립. attack_turn_start 하나로:
  1) 플래너(정렬 모델)가 태세를 읽어 의도를 frontier에 뿌린다.
  2) 워커 풀(탈옥 모델 N)이 그 의도들을 claim해 ReAct로 돌리고(실행은 공유 레인에 직렬),
     결론을 fact/finding으로 그래프에 쓴다.
  3) 플래너가 쌓인 사실을 다시 읽어 다음 의도를 뿌린다 → 다음 웨이브. 플래너가 더 낼
     방향이 없거나(목표 달성/막다른 길) 라운드 시간 T가 소진되면 종료.
  4) 레인의 replay_script·플래그·그래프 사실로 AttackTurnResult를 조립.

스코프 분리(이번 세션 확정): 그래프=에피소드(라운드 넘어 지속, 공진화 기억) → 호출자가
주입. 실행 레인=라운드(대본은 라운드당 하나) → 여기서 라운드마다 새로 만든다.

동시성 모델: 플래너는 '웨이브 사이'에 돈다(웨이브 내 워커 추론은 병렬). 완전한 이벤트
구동(플래너 동시 실행)은 이후 개선. clock 주입 → 시간 로직 결정적 테스트.
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

from common.messages import AttackEndReason, AttackTurnResult, AttackTurnStart, FlagObtained

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
    flag_value_id: str = "4"
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


def _assets_block(start: AttackTurnStart) -> str:
    """플래너 개막 태세에 넣을 발판(진입점) 정보 — 자산 그래프 전까진 발판만."""
    if start.foothold is None:
        return ""
    return f"- foothold entry point: {start.foothold.attack_endpoint}"


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
            graph: Optional[ExplorationGraph] = None) -> AttackTurnResult:
        t0 = self.clock()
        deadline = t0 + float(start.time_limit_sec)
        graph = graph if graph is not None else InMemoryGraph(episode=episode)

        # 대본은 라운드당 하나(레인). 그래프는 에피소드 스코프(주입).
        lane = ExecutionLane(
            self.runner, scope_policy=self.scope, session_id=self.cfg.session_id,
            episode=episode, round=round, flag_value_id=self.cfg.flag_value_id,
            step_timeout=self.cfg.step_timeout)

        planner = Planner(self.planner_llm, goal=start.goal,
                          max_tokens=self.cfg.planner_max_tokens)
        intent_runner = IntentRunner(
            self.attacker_llm,
            IntentRunnerConfig(
                system_prompt=self.cfg.system_prompt, round_goal=start.goal,
                flag_format=start.flag_format,
                intent_budget_sec=self.cfg.intent_budget_sec,
                max_steps=self.cfg.intent_max_steps,
                react_max_tokens=(start.max_tokens or self.cfg.react_max_tokens)),
            log=self.log)

        foothold = _foothold_dict(start)
        assets_block = _assets_block(start)

        waves = 0
        planner_empty = False
        while waves < self.cfg.max_waves and self.clock() < deadline:
            plan = planner.plan(graph, assets_block=assets_block)
            if not plan.added_ids:
                planner_empty = True        # 더 낼 방향 없음(목표 달성/막다른/계획 실패)
                self.log(f"[round r{round}] wave {waves+1}: 플래너 0개 → 종료 "
                         f"({plan.error or 'goal-reached/no-direction'})")
                break
            self.log(f"[round r{round}] wave {waves+1}: 의도 {len(plan.added_ids)}개 → 풀 가동")
            WorkerPool(graph, lane, intent_runner, n_workers=self.cfg.n_workers,
                       foothold=foothold, round_deadline=deadline,
                       clock=self.clock, log=self.log).run()
            waves += 1

        return self._assemble(lane, graph, start, t0, waves, planner_empty)

    def _assemble(self, lane: ExecutionLane, graph: ExplorationGraph,
                  start: AttackTurnStart, t0: float, waves: int,
                  planner_empty: bool) -> AttackTurnResult:
        # 플래그: 레인이 (값, step_id)로 모았고, 값 중복은 한 번만(god-view는 값으로 식별)
        flags: list[FlagObtained] = []
        seen: set[str] = set()
        for value, sid in lane.flags_found:
            if value in seen:
                continue
            seen.add(value)
            step_no = int(sid.split(".")[-1]) if "." in sid else 0
            flags.append(FlagObtained(flag_id=self.cfg.flag_value_id, value=value, step=step_no))

        # 종료사유: 플래그 있으면 FLAG, 시간 소진이면 TIMEOUT, 아니면 DEADEND(플래너 고갈)
        if flags:
            end = AttackEndReason.FLAG
        elif self.clock() >= t0 + float(start.time_limit_sec):
            end = AttackEndReason.TIMEOUT
        else:
            end = AttackEndReason.DEADEND

        return AttackTurnResult(
            end_reason=end, flags_obtained=flags, replay_script=lane.script,
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
            lines.append(f"- 발견({sev}){tag}: {f.payload.get('summary', '')}")
        return "\n".join(lines)


__all__ = ["AttackRound", "RoundConfig"]
