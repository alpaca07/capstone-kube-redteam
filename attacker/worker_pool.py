"""워커 풀 엔진 — 워커 N이 frontier에서 의도를 집어 실행·정착하는 라운드 루프.

ARTEX의 폐곡선을 차용: 플래너가 frontier에 의도를 넣고, 워커 N(스레드)이 각자
claim_next로 하나씩 집어 실행하고, 결과(fact/finding)를 그래프에 쓰고, 의도를
종료상태로 정착시킨 뒤 다음을 집는다. 실행 중 새 의도가 생기면(플래너 이벤트) 자연히
집어간다. frontier가 비고 돌고 있는 의도도 없으면 라운드 종료.

이 엔진은 '동시성·claim 루프·종료 판정'만 책임진다. '의도 하나를 어떻게 실행하나'
(ReAct 추론 + fact/finding 쓰기)는 run_intent 콜러블로 주입 → LLM 없이 fake로 전
동시성 로직을 테스트한다(실제 ReAct 연결은 다음 조각).

핵심 설계(이번 세션 확정):
  · 추론 병렬(워커 스레드) / 실행 직렬([[ExecutionLane]]이 락으로 보장) — 여기선 각 워커가
    자기 WorkerContext로 레인에 행동을 흘린다.
  · claim은 원자적([[ExplorationGraph.claim_next]]) — 두 워커가 같은 의도 못 집음.
  · 라운드 데드라인(시간 T): 넘으면 새 claim 중단, 돌고 있는 의도는 끝까지 둔다(drain).
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from .exec_lane import ExecutionLane, WorkerContext
from .graph import ExplorationGraph, IntentState, Node


@dataclass
class IntentOutcome:
    """run_intent이 의도 하나를 돌린 결과 — 엔진이 이걸로 의도를 정착시킨다."""
    state: IntentState = IntentState.DONE   # DONE / BLOCKED / EXHAUSTED / STOPPED
    reason: str = ""


# run_intent(graph, worker_ctx, intent) -> IntentOutcome
#   graph: fact/finding 쓰기·태세 읽기, worker_ctx: 행동 실행(공유 레인), intent: 할 일
RunIntent = Callable[[ExplorationGraph, WorkerContext, Node], IntentOutcome]


@dataclass
class RoundSummary:
    claimed: int = 0
    done: int = 0
    blocked: int = 0
    exhausted: int = 0
    stopped: int = 0
    remaining_open: int = 0          # 데드라인 등으로 끝내 claim 안 된 열린 의도
    errors: list[str] = field(default_factory=list)


_STATE_FIELD = {
    IntentState.DONE: "done",
    IntentState.BLOCKED: "blocked",
    IntentState.EXHAUSTED: "exhausted",
    IntentState.STOPPED: "stopped",
}


class WorkerPool:
    """한 라운드를 돈다: 워커 N 스레드가 frontier를 비울 때까지(또는 데드라인까지) 집어 실행."""

    def __init__(self, graph: ExplorationGraph, lane: ExecutionLane,
                 run_intent: RunIntent, *, n_workers: int = 2,
                 foothold: Optional[dict] = None, target: Optional[str] = None,
                 round_deadline: Optional[float] = None,
                 idle_poll: float = 0.02,
                 clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep,
                 log: Optional[Callable[[str], None]] = None) -> None:
        self.graph = graph
        self.lane = lane
        self.run_intent = run_intent
        self.n_workers = n_workers
        self.foothold = foothold
        self.target = target
        self.round_deadline = round_deadline
        self.idle_poll = idle_poll
        self.clock = clock
        self.sleep = sleep
        self.log = log or (lambda m: None)
        self._summary = RoundSummary()
        self._sum_lock = threading.Lock()

    def _deadline_passed(self) -> bool:
        return self.round_deadline is not None and self.clock() >= self.round_deadline

    def _bump(self, field_name: str, n: int = 1) -> None:
        with self._sum_lock:
            setattr(self._summary, field_name, getattr(self._summary, field_name) + n)

    def _record_error(self, msg: str) -> None:
        with self._sum_lock:
            self._summary.errors.append(msg)

    def _worker_loop(self, wid: str) -> None:
        wctx = WorkerContext(self.lane, wid, foothold=self.foothold, target=self.target)
        while True:
            if self._deadline_passed():
                self.log(f"[{wid}] 라운드 데드라인 → claim 중단")
                return
            intent = self.graph.claim_next(wid)
            if intent is None:
                # 집을 게 없음. 다른 워커가 아직 돌고 있거나 frontier가 남아 있으면
                # (그들이 새 의도를 낳을 수 있으므로) 잠깐 기다렸다 재시도.
                if not self.graph.running_intents() and not self.graph.frontier():
                    return
                self.sleep(self.idle_poll)
                continue

            self._bump("claimed")
            try:
                outcome = self.run_intent(self.graph, wctx, intent)
            except Exception as e:  # noqa: BLE001 — 한 의도의 실패가 풀을 죽이지 않게
                outcome = IntentOutcome(IntentState.BLOCKED, reason=f"run_intent error: {e}")
                self._record_error(f"{wid} intent#{intent.id}: {type(e).__name__}: {e}")

            self.graph.settle_intent(intent.id, outcome.state, outcome.reason)
            self._bump(_STATE_FIELD.get(outcome.state, "done"))

    def run(self) -> RoundSummary:
        threads = [threading.Thread(target=self._worker_loop, args=(f"work{i+1}",),
                                    name=f"work{i+1}")
                   for i in range(self.n_workers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # 데드라인 등으로 끝내 claim 안 된 열린 의도 수 집계
        self._summary.remaining_open = len(self.graph.frontier(limit=10_000))
        return self._summary


__all__ = ["WorkerPool", "IntentOutcome", "RoundSummary", "RunIntent"]
