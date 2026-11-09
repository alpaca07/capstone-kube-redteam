"""의도 실행기(진짜 run_intent) 테스트 — ReAct 스코프·정착 호출(fact/finding 쓰기)·
종료사유 매핑·정착 실패 폴백, 그리고 플래너→풀→의도실행기 풀스택(LLM만 fake).

    python3 tests/test_attacker_intent_runner.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.exec_lane import ExecutionLane  # noqa: E402
from attacker.execute_action import CommandResult  # noqa: E402
from attacker.graph import IntentState, NodeKind, Rel  # noqa: E402
from attacker.graph_fake import InMemoryGraph  # noqa: E402
from attacker.intent_runner import (  # noqa: E402
    IntentRunner, IntentRunnerConfig, parse_settlement,
)
from attacker.scope import default_policy  # noqa: E402
from attacker.worker_pool import WorkerPool  # noqa: E402


class _R:
    def __init__(self, stdout="ok"):
        self.stdout = stdout

    def run(self, tool, args, *, stdin=None, timeout=None):
        return CommandResult(0, self.stdout, "")


def _lane(runner=None, round=1):
    return ExecutionLane(runner or _R(), scope_policy=default_policy(),
                         session_id="s", episode=1, round=round)


class _ScriptLLM:
    """ReAct 행동(chat_text_meta)과 정착(chat_text)을 각각 프로그래밍.

    react: 순서대로 내놓을 행동 JSON 문자열들(끝나면 give_up).
    settle: 정착 호출이 돌려줄 JSON 문자열.
    """
    def __init__(self, react, settle):
        self._react = list(react)
        self._settle = settle
        self.settle_calls = 0

    def chat_text_meta(self, system, user, **kw):
        if self._react:
            return self._react.pop(0), "stop"
        return '{"thought":"done","action":{"tool":"give_up","args":[]}}', "stop"

    def chat_text(self, system, user, **kw):   # 정착 호출
        self.settle_calls += 1
        return self._settle


_ACT_GET = '{"thought":"probe","action":{"tool":"kubectl","args":["get","po"]}}'
_SETTLE_ONE_FACT = ('{"facts":[{"summary":"postgres reachable from foothold",'
                    '"evidence":"nc 5432 open","confidence":"observed"}],"finding":null}')


# ── 정착 파싱: facts + finding ──
def test_parse_settlement_facts_and_finding():
    facts, finding = parse_settlement(
        '{"facts":[{"summary":"creds found","confidence":"observed"}],'
        '"finding":{"summary":"PII read","severity":"high","evidence":"row dump"}}')
    assert len(facts) == 1 and facts[0].confidence == "observed"
    assert finding is not None and finding.severity == "high"


def test_parse_settlement_null_finding():
    facts, finding = parse_settlement('{"facts":[{"summary":"port closed"}],"finding":null}')
    assert len(facts) == 1 and finding is None


def test_parse_settlement_drops_empty_summary():
    facts, _ = parse_settlement('{"facts":[{"summary":""},{"summary":"real"}]}')
    assert len(facts) == 1 and facts[0].summary == "real"


# ── 한 의도 실행: ReAct 스텝 실행 + 정착 fact가 intent에 yields로 연결 ──
def test_run_one_intent_writes_fact_linked():
    g = InMemoryGraph()
    iid = g.add_intent({"summary": "probe postgres", "technique": "T1046"})
    g.claim_next("w")                      # running 상태로(정착이 running intent에 연결)
    intent = g.get_node(iid)

    llm = _ScriptLLM([_ACT_GET, _ACT_GET], _SETTLE_ONE_FACT)
    lane = _lane()
    from attacker.exec_lane import WorkerContext
    wctx = WorkerContext(lane, "w")
    runner = IntentRunner(llm, IntentRunnerConfig(system_prompt="sys", round_goal="read PII"))
    outcome = runner(g, wctx, intent)

    assert outcome.state == IntentState.DONE
    assert llm.settle_calls == 1
    # 레인에 ReAct 스텝 2개 기록
    assert len(lane.script.steps) == 2
    # 정착 fact 1개가 intent→YIELDS→fact로 연결, source_step_ids는 이 의도 스텝들
    facts = g.recent_facts()
    assert len(facts) == 1
    assert facts[0].payload["summary"].startswith("postgres reachable")
    assert facts[0].payload["source_step_ids"] == ["1.1", "1.2"]
    yields = g.edges_from(iid, Rel.YIELDS)
    assert len(yields) == 1 and yields[0].dst_id == facts[0].id


# ── 기계적 침해 트리거: 정착 LLM 이 finding=null 이어도 출력에 값이 있으면 침해 기록(④ 보강) ──
def test_mechanical_finding_when_settle_returns_null():
    from attacker.exec_lane import WorkerContext
    g = InMemoryGraph()
    iid = g.add_intent({"summary": "probe db", "target": "db"})
    g.claim_next("w")
    # 워커 출력에 크레덴셜 '값'이 나옴, 정착 LLM 은 finding=null(놓침)
    llm = _ScriptLLM([_ACT_GET], '{"facts":[{"summary":"fetched"}],"finding":null}')
    lane = _lane(_R("connected: db password=devpass123 host=pg"))
    runner = IntentRunner(llm, IntentRunnerConfig(system_prompt="s", round_goal="g"))
    runner(g, WorkerContext(lane, "w"), g.get_node(iid))
    findings = g.recent_findings()
    assert findings, "출력에 크레덴셜 값이 있는데 finding 이 기록 안 됨"
    assert (findings[0].payload.get("technique") or "") == "T1552"


# ── 거짓양성 방지: 값 없이 막히기만 하면(403 등) 기계적 트리거는 finding 안 만듦 ──
def test_no_mechanical_finding_without_value():
    from attacker.exec_lane import WorkerContext
    g = InMemoryGraph()
    iid = g.add_intent({"summary": "probe db", "target": "db"})
    g.claim_next("w")
    llm = _ScriptLLM([_ACT_GET], '{"facts":[{"summary":"blocked"}],"finding":null}')
    lane = _lane(_R("HTTP/1.1 403 Forbidden"))        # 값 없음(막힘)
    runner = IntentRunner(llm, IntentRunnerConfig(system_prompt="s", round_goal="g"))
    runner(g, WorkerContext(lane, "w"), g.get_node(iid))
    assert not g.recent_findings(), "값이 없는데 finding 이 잘못 생성됨(거짓양성)"


# ── finding이 나오면 finding 노드 + PROVES 엣지 + 기법 태그 ──
def test_finding_own_technique_wins_over_intent():
    # 실 런 사례: 의도는 T1046(서비스 탐색)인데 실제 달성은 크레덴셜 탈취(T1552).
    # finding이 자기 기법을 내면 그게 이겨야(채점 조인이 '달성한 것' 기준이라).
    g = InMemoryGraph()
    iid = g.add_intent({"summary": "enumerate services", "technique": "T1046"})
    g.claim_next("w")
    intent = g.get_node(iid)
    settle = ('{"facts":[{"summary":"admin dashboard exposes db creds"}],'
              '"finding":{"summary":"retrieved postgres credentials","severity":"high",'
              '"evidence":"decoded secret","technique":"T1552"}}')
    llm = _ScriptLLM([_ACT_GET], settle)
    lane = _lane()
    from attacker.exec_lane import WorkerContext
    runner = IntentRunner(llm, IntentRunnerConfig(system_prompt="s", round_goal="g"))
    runner(g, WorkerContext(lane, "w"), intent)

    findings = [n for n in [g.get_node(i) for i in range(1, 20) if g.get_node(i)]
                if n.kind == NodeKind.FINDING]
    assert len(findings) == 1
    assert findings[0].payload["technique"] == "T1552"   # 의도의 T1046 아니라 달성한 T1552
    assert findings[0].payload["severity"] == "high"


def test_finding_technique_falls_back_to_intent_when_absent():
    # 정착이 finding에 technique를 안 주면 의도 기법으로 폴백
    g = InMemoryGraph()
    iid = g.add_intent({"summary": "dump PII", "technique": "T1078"})
    g.claim_next("w")
    intent = g.get_node(iid)
    settle = ('{"facts":[{"summary":"authed to db"}],'
              '"finding":{"summary":"read customers table","severity":"critical","evidence":"100 rows"}}')
    llm = _ScriptLLM([_ACT_GET], settle)
    lane = _lane()
    from attacker.exec_lane import WorkerContext
    runner = IntentRunner(llm, IntentRunnerConfig(system_prompt="s", round_goal="g"))
    runner(g, WorkerContext(lane, "w"), intent)

    findings = [n for n in [g.get_node(i) for i in range(1, 20) if g.get_node(i)]
                if n.kind == NodeKind.FINDING]
    assert len(findings) == 1
    f = findings[0]
    assert f.payload["severity"] == "critical"
    assert f.payload["technique"] == "T1078"          # finding 기법 없음 → 의도 기법 폴백
    # fact → PROVES → finding
    fact = g.recent_facts()[0]
    proves = g.edges_from(fact.id, Rel.PROVES)
    assert len(proves) == 1 and proves[0].dst_id == f.id


# ── 종료사유 매핑: 타임아웃→EXHAUSTED ──
def test_timeout_maps_to_exhausted():
    g = InMemoryGraph()
    iid = g.add_intent({"summary": "slow"})
    g.claim_next("w")
    intent = g.get_node(iid)
    # intent_budget_sec=0 → ReAct가 첫 스텝 전에 예산소진(TIMEOUT)
    llm = _ScriptLLM([_ACT_GET], _SETTLE_ONE_FACT)
    lane = _lane()
    from attacker.exec_lane import WorkerContext
    runner = IntentRunner(llm, IntentRunnerConfig(
        system_prompt="s", round_goal="g", intent_budget_sec=0.0))
    outcome = runner(g, WorkerContext(lane, "w"), intent)
    assert outcome.state == IntentState.EXHAUSTED
    assert outcome.reason == "timeout"


class _RecLLM:
    """ReAct·정착 호출에 넘어온 timeout 을 기록 — 라운드 마감 클램프 검증용."""
    def __init__(self):
        self.react_timeouts = []
        self.settle_timeout = "unset"
        self._done = False

    def chat_text_meta(self, system, user, *, timeout=None, **kw):
        self.react_timeouts.append(timeout)
        if not self._done:
            self._done = True
            return '{"thought":"p","action":{"tool":"get","args":["x"]}}', "stop"
        return '{"thought":"d","action":{"tool":"give_up","args":[]}}', "stop"

    def chat_text(self, system, user, *, timeout=None, **kw):
        self.settle_timeout = timeout
        return '{"facts":[{"summary":"o"}],"finding":null}'


# ── 라운드 마감 클램프: 마감이 임박하면 ReAct 예산·정착 호출이 남은 시간으로 줄어든다 ──
def test_intent_budget_and_settle_clamped_to_round_deadline():
    import time
    from attacker.exec_lane import WorkerContext

    # (1) 먼 마감 → 예산 거의 full(120s 근처)
    g = InMemoryGraph(); g.add_intent({"summary": "x", "target": "t"}); g.claim_next("w")
    far = _RecLLM()
    IntentRunner(far, IntentRunnerConfig(system_prompt="s", round_goal="g",
                 intent_budget_sec=120.0))(
        g, WorkerContext(_lane(), "w", round_deadline=time.time() + 1000, clock=time.time),
        g.get_node(1))
    assert far.react_timeouts[0] > 60, far.react_timeouts        # 클램프 안 됨(full)

    # (2) 임박 마감(10s 남음) → ReAct 예산은 작게 클램프, 정착은 고정 여유 유지
    #     (정착을 마감에 쥐어짜면 finding 생성이 타임아웃 → 침해0 → ④ 소실하므로)
    from attacker.intent_runner import _SETTLE_MAX
    g2 = InMemoryGraph(); g2.add_intent({"summary": "x", "target": "t"}); g2.claim_next("w")
    near = _RecLLM()
    IntentRunner(near, IntentRunnerConfig(system_prompt="s", round_goal="g",
                 intent_budget_sec=120.0))(
        g2, WorkerContext(_lane(), "w", round_deadline=time.time() + 10, clock=time.time),
        g2.get_node(1))
    assert near.react_timeouts[0] < 15, near.react_timeouts      # ReAct 예산은 남은시간으로
    assert near.settle_timeout == _SETTLE_MAX, near.settle_timeout  # 정착은 고정 여유(안 쥐어짜임)

    # (3) 마감 정보 없으면(기존 동작) full 예산
    g3 = InMemoryGraph(); g3.add_intent({"summary": "x", "target": "t"}); g3.claim_next("w")
    none = _RecLLM()
    IntentRunner(none, IntentRunnerConfig(system_prompt="s", round_goal="g",
                 intent_budget_sec=120.0))(g3, WorkerContext(_lane(), "w"), g3.get_node(1))
    assert none.react_timeouts[0] > 60, none.react_timeouts      # 클램프 미적용


# ── 정착 실패 폴백: 깨진 JSON이어도 의도는 안 잃고 폴백 fact 남김 ──
def test_settlement_failure_falls_back_to_summary_fact():
    g = InMemoryGraph()
    iid = g.add_intent({"summary": "x"})
    g.claim_next("w")
    intent = g.get_node(iid)
    llm = _ScriptLLM([_ACT_GET], "I cannot produce JSON, sorry.")  # 정착 파싱 실패
    lane = _lane()
    from attacker.exec_lane import WorkerContext
    runner = IntentRunner(llm, IntentRunnerConfig(system_prompt="s", round_goal="g"))
    outcome = runner(g, WorkerContext(lane, "w"), intent)
    assert outcome.state == IntentState.DONE          # 의도는 완료로
    facts = g.recent_facts()
    assert len(facts) == 1                             # 폴백 fact 하나는 남음
    assert facts[0].payload["confidence"] == "inferred"


# ── ★ 풀스택: 플래너→풀→의도실행기 (LLM만 fake, 나머지 전부 실제) ──
def test_full_stack_planner_pool_runner():
    from attacker.planner import Planner

    g = InMemoryGraph()

    # 플래너 LLM: 의도 2개 생성
    class _PlanLLM:
        def chat_text(self, system, user, **kw):
            return ('{"intents":[{"summary":"probe pg","target":"postgres","technique":"T1046"},'
                    '{"summary":"enum SA","target":"admin","technique":"T1078"}]}')
    Planner(_PlanLLM(), goal="read PII").plan(g)
    assert len(g.frontier()) == 2

    # 워커 LLM: 각 워커 호출마다 새 _ScriptLLM이 필요하므로, 의도실행기가 공유하는 단일 LLM이
    # 스레드로 불려도 되게 '매 호출 give_up + 고정 정착'하는 간단 LLM을 쓴다.
    class _WorkLLM:
        def chat_text_meta(self, system, user, **kw):
            # 한 번 정찰 후 give_up 하도록: user에 아직 관측 없으면 kubectl, 있으면 give_up
            if "아직 행동 없음" in user or "(none" in user:
                return _ACT_GET, "stop"
            return '{"thought":"done","action":{"tool":"give_up","args":[]}}', "stop"
        def chat_text(self, system, user, **kw):
            return _SETTLE_ONE_FACT

    lane = _lane()
    runner = IntentRunner(_WorkLLM(), IntentRunnerConfig(
        system_prompt="s", round_goal="read PII", max_steps=4))
    summary = WorkerPool(g, lane, runner, n_workers=2).run()

    assert summary.claimed == 2 and summary.done == 2
    # 두 의도가 각각 fact를 그래프에 남김
    assert len(g.recent_facts()) == 2
    # 모든 의도가 종료상태(open 없음)
    assert g.frontier() == []
    # 레인 대본에 스텝이 쌓이고 step 번호 유일
    nums = sorted(s.step for s in lane.script.steps)
    assert nums == list(range(1, len(nums) + 1))


def _run() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  \033[32m✓\033[0m {t.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  \033[31m✗\033[0m {t.__name__}: {type(e).__name__}: {e}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed  (총 {len(tests)})")
    return 1 if failed else 0


if __name__ == "__main__":
    print("── 의도 실행기 테스트 ──")
    sys.exit(_run())
