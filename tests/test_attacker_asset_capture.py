"""자산 포집·앵커 배선 테스트 — 의도실행기가 관측 자산을 자산 그래프에 쓰고 의도를 앵커.

    python3 tests/test_attacker_asset_capture.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.assets_fake import InMemoryAssetGraph  # noqa: E402
from attacker.exec_lane import ExecutionLane, WorkerContext  # noqa: E402
from attacker.execute_action import CommandResult  # noqa: E402
from attacker.graph_fake import InMemoryGraph  # noqa: E402
from attacker.intent_runner import IntentRunner, IntentRunnerConfig  # noqa: E402
from attacker.scope import default_policy  # noqa: E402


class _R:
    def __init__(self, stdout="ok"):
        self.stdout = stdout

    def run(self, tool, args, *, stdin=None, timeout=None):
        return CommandResult(0, self.stdout, "")


class _LLM:
    """ReAct: 지정 명령 1회 후 give_up. 정착: 고정."""
    def __init__(self, action, settle):
        self._action = action
        self._settle = settle
        self._done = False

    def chat_text_meta(self, system, user, **kw):
        if not self._done:
            self._done = True
            return self._action, "stop"
        return '{"thought":"done","action":{"tool":"give_up","args":[]}}', "stop"

    def chat_text(self, system, user, **kw):
        return self._settle


# ── anchor_to: 의도 노드 anchors에 자산 id 채움 ──
def test_anchor_to_fills_anchors():
    g = InMemoryGraph()
    i = g.add_intent({"summary": "x"})
    g.anchor_to(i, [10, 11])
    assert g.get_node(i).anchors == [10, 11]
    g.anchor_to(i, [11, 12])                 # 중복 11은 안 넣음
    assert g.get_node(i).anchors == [10, 11, 12]


# ── 의도실행기가 관측 자산을 포집해 자산 그래프에 쓰고 의도를 앵커 ──
def test_runner_captures_and_anchors():
    g = InMemoryGraph()
    ag = InMemoryAssetGraph()
    iid = g.add_intent({"summary": "probe pg", "target": "postgres.database.svc.cluster.local"})
    g.claim_next("w")
    intent = g.get_node(iid)

    # 워커가 postgres DNS·웹서비스를 관측하는 명령
    action = ('{"thought":"p","action":{"tool":"sh","args":["-c",'
              '"wget -qO- http://10.43.183.240:80/ ; nslookup postgres.database.svc.cluster.local"]}}')
    llm = _LLM(action, '{"facts":[{"summary":"observed"}],"finding":null}')
    lane = ExecutionLane(_R("resolved"), scope_policy=default_policy(),
                         session_id="s", episode=1, round=1)
    runner = IntentRunner(llm, IntentRunnerConfig(system_prompt="s", round_goal="g"),
                          asset_graph=ag)
    runner(g, WorkerContext(lane, "w"), intent)

    names = {a.name for a in ag.assets()}
    # target + 관측된 자산들이 자산 그래프에 들어감
    assert "postgres.database.svc.cluster.local" in names
    assert "10.43.183.240:80" in names
    # 전부 미식별(CPE 없음)
    assert all(not a.identified for a in ag.assets())
    # 의도가 그 자산들에 앵커됨(anchors 채워짐)
    anchored = set(g.get_node(iid).anchors)
    assert anchored, "의도 anchors가 비어있음(앵커 안 됨)"
    # 앵커된 id가 실제 자산 노드
    for aid in anchored:
        assert ag.get_asset(aid) is not None


# ── 앵커는 '겨냥한 자산(intent_target)'에만 — 발견 자산은 [untouched]로 남는다(③ 신호) ──
def test_anchors_only_intent_target_not_discovered():
    g = InMemoryGraph()
    ag = InMemoryAssetGraph()
    iid = g.add_intent({"summary": "probe pg", "target": "postgres.database.svc.cluster.local"})
    g.claim_next("w")
    # 출력/명령에 겨냥 자산 + 우연히 발견한 다른 자산(IP:포트)이 함께 관측됨
    action = ('{"thought":"p","action":{"tool":"sh","args":["-c",'
              '"wget -qO- http://10.43.183.240:80/ ; nslookup postgres.database.svc.cluster.local"]}}')
    llm = _LLM(action, '{"facts":[{"summary":"o"}],"finding":null}')
    lane = ExecutionLane(_R("resolved"), scope_policy=default_policy(),
                         session_id="s", episode=1, round=1)
    runner = IntentRunner(llm, IntentRunnerConfig(system_prompt="s", round_goal="g"),
                          asset_graph=ag)
    runner(g, WorkerContext(lane, "w"), g.get_node(iid))

    by_name = {a.name: a.id for a in ag.assets()}
    anchored = g.anchored_asset_ids()
    # 둘 다 자산 그래프엔 들어감(KNOWN ASSETS에 보임)
    assert "postgres.database.svc.cluster.local" in by_name and "10.43.183.240:80" in by_name
    # 그러나 앵커(=explored)는 겨냥 자산에만
    assert by_name["postgres.database.svc.cluster.local"] in anchored
    assert by_name["10.43.183.240:80"] not in anchored   # 발견 자산 → [untouched] 유지


# ── 자산 그래프 없으면 조용히 건너뜀(앵커 없음, 에러 없음) ──
def test_no_asset_graph_skips():
    g = InMemoryGraph()
    iid = g.add_intent({"summary": "x", "target": "postgres.svc"})
    g.claim_next("w")
    llm = _LLM('{"thought":"p","action":{"tool":"get","args":["x"]}}',
               '{"facts":[{"summary":"o"}],"finding":null}')
    lane = ExecutionLane(_R(), scope_policy=default_policy(), session_id="s", episode=1, round=1)
    runner = IntentRunner(llm, IntentRunnerConfig(system_prompt="s", round_goal="g"))  # asset_graph 없음
    out = runner(g, WorkerContext(lane, "w"), g.get_node(iid))
    assert out is not None                   # 정상 완료
    assert g.get_node(iid).anchors == []     # 앵커 없음


# ── 계층(CONTAINS)이 포집 시 걸린다: IP:port 서비스가 그 호스트의 자식 ──
def test_capture_wires_contains_hierarchy():
    g = InMemoryGraph()
    ag = InMemoryAssetGraph()
    iid = g.add_intent({"summary": "probe db", "target": "db"})
    g.claim_next("w")
    action = ('{"thought":"p","action":{"tool":"sh","args":["-c",'
              '"nc -zv 10.43.214.23:5432 ; wget http://admin-dashboard/secret"]}}')
    llm = _LLM(action, '{"facts":[{"summary":"o"}],"finding":null}')
    lane = ExecutionLane(_R(), scope_policy=default_policy(), session_id="s", episode=1, round=1)
    IntentRunner(llm, IntentRunnerConfig(system_prompt="s", round_goal="g"),
                 asset_graph=ag)(g, WorkerContext(lane, "w"), g.get_node(iid))

    name_to_id = {a.name: a.id for a in ag.assets()}
    # 호스트(10.43.214.23) ⊃ 서비스(10.43.214.23:5432)
    host, svc = name_to_id.get("10.43.214.23"), name_to_id.get("10.43.214.23:5432")
    assert host and svc and (host, svc) in ag.contains_edges()
    # 서비스(admin-dashboard) ⊃ 엔드포인트(admin-dashboard/secret)
    adm, ep = name_to_id.get("admin-dashboard"), name_to_id.get("admin-dashboard/secret")
    assert adm and ep and (adm, ep) in ag.contains_edges()


# ── 발견도 자산에 앵커 ──
def test_finding_anchored_to_assets():
    from attacker.graph import NodeKind
    g = InMemoryGraph()
    ag = InMemoryAssetGraph()
    iid = g.add_intent({"summary": "grab", "target": "admin-dashboard", "technique": "T1552"})
    g.claim_next("w")
    action = '{"thought":"p","action":{"tool":"sh","args":["-c","wget http://admin-dashboard/secret"]}}'
    settle = ('{"facts":[{"summary":"creds"}],'
              '"finding":{"summary":"got creds","severity":"high","technique":"T1552"}}')
    llm = _LLM(action, settle)
    lane = ExecutionLane(_R("creds=x"), scope_policy=default_policy(),
                         session_id="s", episode=1, round=1)
    IntentRunner(llm, IntentRunnerConfig(system_prompt="s", round_goal="g"),
                 asset_graph=ag)(g, WorkerContext(lane, "w"), g.get_node(iid))
    findings = [n for n in [g.get_node(i) for i in range(1, 30) if g.get_node(i)]
                if n.kind == NodeKind.FINDING]
    assert findings and findings[0].anchors, "발견이 자산에 앵커 안 됨"


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
    print("── 자산 포집·앵커 테스트 ──")
    sys.exit(_run())
