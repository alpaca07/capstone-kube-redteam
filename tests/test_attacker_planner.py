"""플래너 테스트 — 태세 렌더링·의도 파싱(느슨)·중복방지 컨텍스트·목표달성 신호·그래프 반영.

LLM은 fake로 주입. 실제 정렬 모델 호출은 안 한다(로직만 검증).

    python3 tests/test_attacker_planner.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.assets_fake import InMemoryAssetGraph  # noqa: E402
from attacker.graph import IntentState, NodeKind, Rel  # noqa: E402
from attacker.graph_fake import InMemoryGraph  # noqa: E402
from attacker.planner import (  # noqa: E402
    Planner, build_situation, parse_intents,
)


class _FakeLLM:
    """미리 심은 응답을 순서대로 돌려주고, 받은 (system,user,kw)를 기록.
    replies 항목은 평문 텍스트(finish=None) 또는 (텍스트, finish_reason) 튜플 —
    사고(thinking) overflow 재시도 진단(finish=='length')을 테스트하려면 후자로 심는다."""

    def __init__(self, replies):
        self._replies = list(replies)
        self.calls: list[tuple[str, str, dict]] = []

    def _pop(self, system, user, kw) -> tuple[str, "Optional[str]"]:
        self.calls.append((system, user, kw))
        if not self._replies:
            return '{"intents": []}', None
        r = self._replies.pop(0)
        return r if isinstance(r, tuple) else (r, None)

    def chat_text(self, system, user, **kw):
        return self._pop(system, user, kw)[0]

    def chat_text_meta(self, system, user, **kw):
        return self._pop(system, user, kw)


_TWO_INTENTS = ('{"intents": ['
                '{"summary": "probe postgres reachability", "target": "postgres.database", '
                '"why": "path to PII", "technique": "T1046"},'
                '{"summary": "enumerate admin-dashboard SA", "target": "admin-dashboard", '
                '"why": "priv path", "technique": "T1078"}]}')


# ── 파싱: 정상 ──
def test_parse_two_intents():
    its = parse_intents(_TWO_INTENTS)
    assert len(its) == 2
    assert its[0].summary.startswith("probe postgres")
    assert its[0].technique == "T1046"


# ── 파싱: 느슨(펜스·잡설·트레일링콤마 흡수) ──
def test_parse_lenient_fenced_with_prose():
    msg = ('여기 계획입니다:\n```json\n'
           '{"intents": [{"summary": "check wiki config leak", "target": "internal-wiki",}]}\n'
           '```\n이상입니다.')
    its = parse_intents(msg)
    assert len(its) == 1 and its[0].target == "internal-wiki"


# ── 파싱: summary 없는 항목은 버린다 ──
def test_parse_drops_empty_summary():
    its = parse_intents('{"intents": [{"summary": ""}, {"summary": "real one"}]}')
    assert len(its) == 1 and its[0].summary == "real one"


# ── 파싱: JSON이 전혀 없으면(정렬모델 거부·추론만 하다 잘림 등) 에러 신호 ──
def test_parse_garbage_signals_error():
    from common.llm_json import LLMJsonError
    try:
        parse_intents("I cannot output JSON, here is some prose only.")
        assert False, "should have raised"
    except LLMJsonError:
        pass


# ── 태세: 최근 사실 + 진행 중 의도를 보여준다(중복 방지 컨텍스트) ──
def test_situation_shows_facts_and_inflight():
    g = InMemoryGraph()
    i = g.add_intent({"summary": "running one"})
    g.claim_next("w")                       # running 상태로
    g.add_intent({"summary": "open one"})   # frontier에 대기
    g.add_fact({"summary": "leaked connstr", "confidence": "observed"})
    s = build_situation(g, goal="read PII")
    assert "GOAL: read PII" in s
    assert "leaked connstr" in s and "(observed)" in s
    assert "running one" in s and "open one" in s
    assert "do not duplicate" in s


# ── 태세: 개막(사실·의도 없음) 문구 ──
def test_situation_opening_phrasing():
    g = InMemoryGraph()
    s = build_situation(g, goal="x")
    assert "none yet — this is the opening" in s
    assert "INTENTS ALREADY IN FLIGHT: (none)" in s


# ── 태세: 자산 지형(KNOWN ASSETS) + 지난 라운드 침해(PREVIOUSLY BREACHED) 섹션 ──
def test_situation_shows_assets_and_prior_breaches():
    g = InMemoryGraph()
    s = build_situation(g, goal="read PII",
                        assets_block="- [service] postgres.database.svc.cluster.local",
                        prior_findings_block="- dumped crown creds [high] (T1552) on postgres")
    assert "KNOWN ASSETS:" in s and "postgres.database.svc.cluster.local" in s
    assert "PREVIOUSLY BREACHED" in s and "re-verify" in s
    assert "dumped crown creds" in s and "T1552" in s


# ── 빈 블록이면 해당 섹션은 아예 안 뜬다(개막·R1 호환) ──
def test_situation_omits_empty_blocks():
    g = InMemoryGraph()
    s = build_situation(g, goal="x")       # 둘 다 기본 빈 문자열
    assert "KNOWN ASSETS" not in s
    assert "PREVIOUSLY BREACHED" not in s


# ── 태세: 의도 목표 수(=워커 수)가 들어가고 억지 패딩 금지 취지가 붙는다 ──
def test_situation_includes_target_intents():
    g = InMemoryGraph()
    s = build_situation(g, goal="x", target_intents=4)
    assert "TARGET INTENTS" in s and "up to 4" in s
    assert "4 parallel workers" in s
    assert "Do NOT" in s and "pad" in s            # 패딩 금지 문구


# ── 태세: target_intents 없으면 TARGET 줄은 안 뜬다(기존 호환) ──
def test_situation_omits_target_when_unset():
    g = InMemoryGraph()
    assert "TARGET INTENTS" not in build_situation(g, goal="x")


# ── plan: Planner 가 target_intents 를 프롬프트에 실어 보낸다(워커 수 연동) ──
def test_plan_passes_target_intents_to_prompt():
    g = InMemoryGraph()
    llm = _FakeLLM([_TWO_INTENTS])
    Planner(llm, goal="x", target_intents=5).plan(g)
    assert "up to 5" in llm.calls[0][1]            # LLM 이 본 user 프롬프트에 목표 수


# ── 플래너 시스템 프롬프트: 공진화 재검증 규칙이 박혀 있어야 ──
def test_planner_system_prompt_has_reverify_rule():
    from attacker.planner import PLANNER_SYSTEM
    # 지난 라운드 침해를 '끝'이 아니라 재검증 대상으로
    assert "PREVIOUSLY BREACHED" in PLANNER_SYSTEM and "RE-VERIFY" in PLANNER_SYSTEM
    # 목표 달성은 이번 라운드 사실로만 판단
    assert "THIS round" in PLANNER_SYSTEM
    # 미탐색 자산 우선 겨냥
    assert "unexplored surface" in PLANNER_SYSTEM


# ── plan: 의도를 frontier에 추가하고 id를 돌려준다 ──
def test_plan_adds_intents_to_frontier():
    g = InMemoryGraph()
    p = Planner(_FakeLLM([_TWO_INTENTS]), goal="read PII")
    res = p.plan(g)
    assert res.proposed == 2 and len(res.added_ids) == 2
    fr = g.frontier()
    assert len(fr) == 2
    assert all(n.kind == NodeKind.INTENT and n.state == IntentState.OPEN.value for n in fr)
    # 기법 태그가 payload에 실린다(채점 조인용)
    assert g.get_node(res.added_ids[0]).payload["technique"] == "T1046"


# ── plan: 미활용 발견 → 후속 의도(ENABLES) ──
def test_plan_enables_links_finding_to_followup():
    from attacker.graph import Rel
    g = InMemoryGraph()
    g.add_goal({"title": "crown"})
    fact = g.add_fact({"text": "tomcat manager accepts manager:manager"})
    find = g.add_finding({"summary": "credential retrieved: manager:manager",
                          "technique": "T1552"}, proved_by=[fact])
    assert any(n.id == find for n in g.unexploited_findings())    # 활용 전엔 뜸

    reply = ('{"intents": [{"summary": "deploy webshell via tomcat manager", '
             '"target": "waf.corp-dmz", "why": "RCE pivot", "technique": "T1505", '
             '"enables": [%d]}]}' % find)
    llm = _FakeLLM([reply])
    res = Planner(llm, goal="crown").plan(
        g, unexploited_block=f"F{find}: credential retrieved: manager:manager (T1552)")
    assert res.added_ids, "후속 의도가 추가돼야"
    follow = res.added_ids[0]

    assert any(e.src_id == find and e.rel == Rel.ENABLES and e.dst_id == follow
               for e in g._edges), "finding—ENABLES→후속 의도 엣지가 걸려야"
    assert not any(n.id == find for n in g.unexploited_findings())  # 활용 후엔 빠짐
    assert "UNUSED FINDINGS" in llm.calls[0][1]                     # 태세에 블록이 들어감


# ── plan: 파싱 실패 시 재시도 후 0개 추가 + 에러 보고 ──
def test_plan_parse_fail_retries_then_reports():
    llm = _FakeLLM(["not json", "still not json"])  # retries=1 → 2번 시도 다 실패
    g = InMemoryGraph()
    res = Planner(llm, goal="x", retries=1).plan(g)
    assert res.added_ids == [] and res.error
    assert len(llm.calls) == 2                      # 재시도 1회 포함 2번 호출
    assert g.frontier() == []


# ── plan: 재시도로 복구(1번 실패 후 2번째 성공) ──
def test_plan_recovers_on_retry():
    llm = _FakeLLM(["garbage", _TWO_INTENTS])
    g = InMemoryGraph()
    res = Planner(llm, goal="x", retries=1).plan(g)
    assert res.proposed == 2 and len(g.frontier()) == 2


# ── plan: 사고(thinking) overflow — 빈 content+finish=='length' → cap 축소+/no_think 로 복구 ──
# 실제 사고(VM-A 2026-11-17 로그): 자산이 늘어난 라운드부터 reasoning_effort='none' 이 간헐적으로
# 안 먹혀 <think> 가 max_tokens(3000)를 다 먹고 content 가 '{' 만 연 채 끊김(finish='length') →
# "JSON 객체가 닫히지 않음" 이 재시도까지 포함해 라운드 내내 재현(r7~r10 4라운드 연속 플래너 0개).
def test_plan_recovers_from_thinking_overflow_truncation():
    llm = _FakeLLM([
        ("", "length"),       # 사고 overflow — <think> 가 상한을 다 먹어 content 완전히 빈 채 잘림
        (_TWO_INTENTS, None),  # /no_think 폴백 후 정상 완료
    ])
    g = InMemoryGraph()
    res = Planner(llm, goal="x", retries=1).plan(g)
    assert res.proposed == 2 and len(g.frontier()) == 2
    assert "/no_think" in llm.calls[1][1]            # 2차 호출 프롬프트에 폴백 스위치가 들어감
    assert llm.calls[1][2].get("max_tokens") == 512  # cap 을 줄여 재시도 낭비를 줄임


# ── plan: 내용 있는 잘림(장황함)은 cap 유지 + '짧게' 나그만 ──
def test_plan_length_truncation_with_content_keeps_cap():
    llm = _FakeLLM([
        ('{"intents": [{"summary": "deploy webshell", "target": "x", "why": "y"', "length"),
        (_TWO_INTENTS, None),
    ])
    g = InMemoryGraph()
    res = Planner(llm, goal="x", retries=1, max_tokens=3000).plan(g)
    assert res.proposed == 2
    assert llm.calls[1][2].get("max_tokens") == 3000  # overflow 아니므로 cap 유지(안 줄임)
    assert "너무 길어 잘렸다" in llm.calls[1][1]


# ── plan: 빈 intents = 목표달성/막다른 신호(에러 아님) ──
def test_plan_empty_is_goal_reached_signal():
    g = InMemoryGraph()
    res = Planner(_FakeLLM(['{"intents": []}']), goal="x").plan(g)
    assert res.proposed == 0 and not res.error
    assert res.goal_reached_signal is True
    assert g.frontier() == []


# ── plan: 같은 배치 안 같은 자산(target) 겨냥 중복은 떨군다(대소문자 무시) ──
def test_plan_dedups_same_target_in_batch():
    g = InMemoryGraph()
    two_same = ('{"intents":[{"summary":"a","target":"postgres"},'
                '{"summary":"b","target":"Postgres"}]}')     # 대소문자만 다름 → 같은 자산
    res = Planner(_FakeLLM([two_same]), goal="x").plan(g)
    assert len(res.added_ids) == 1 and res.deduped == 1       # 하나만 추가, 하나 겹침 제거
    assert len(g.frontier()) == 1


# ── plan: 이미 떠 있는(open) 의도와 같은 자산 겨냥은 떨군다(워커 동시 중복 방지) ──
def test_plan_dedups_against_inflight_intent():
    g = InMemoryGraph()
    g.add_intent({"summary": "running probe", "target": "postgres"})   # open 상태로 frontier에
    proposal = ('{"intents":[{"summary":"dup","target":"postgres"},'
                '{"summary":"new","target":"redis"}]}')
    res = Planner(_FakeLLM([proposal]), goal="x").plan(g)
    assert res.deduped == 1 and len(res.added_ids) == 1       # postgres 중복 → redis만 추가
    targets = {g.get_node(i).payload.get("target") for i in res.added_ids}
    assert targets == {"redis"}


# ── plan: 빈 target 의도는 안 떨군다(자산 식별 불가 → 겹침 판정 대상 아님) ──
def test_plan_keeps_empty_target_intents():
    g = InMemoryGraph()
    res = Planner(_FakeLLM(['{"intents":[{"summary":"a"},{"summary":"b"}]}']), goal="x").plan(g)
    assert len(res.added_ids) == 2 and res.deduped == 0       # 둘 다 추가


# ── plan: 서로 다른 자산이면 제거 없음(오탐 없음) ──
def test_plan_distinct_targets_no_dedup():
    g = InMemoryGraph()
    res = Planner(_FakeLLM([_TWO_INTENTS]), goal="x").plan(g)   # postgres.database vs admin-dashboard
    assert len(res.added_ids) == 2 and res.deduped == 0


# ── 1차 select_knowledge: 원시 KG 후보 → 선별(적용성) ──
def test_select_knowledge_returns_selections():
    from attacker.planner import parse_selection
    g = InMemoryGraph()
    sel_json = ('{"selected":[{"technique":"T1552.001","assets":["internal-wiki"],'
                '"why":"runbook creds","applicability":"high"}]}')
    res = Planner(_FakeLLM([sel_json]), goal="x").select_knowledge(
        g, assets_block="- internal-wiki", kg_block="- T1552.001 (conf 0.9; via CVE-x)")
    assert len(res.selected) == 1 and res.selected[0].technique == "T1552.001"
    assert "T1552.001" in res.render() and "high" in res.render()
    # 파서 단위: 기법 없는 선별은 버린다
    assert len(parse_selection('{"selected":[{"technique":""},{"technique":"T1078"}]}')) == 1


# ── 1차: kg_block 비면 LLM 호출 없이 빈 선별(KG 미연결/후보0 → 2차 폴백) ──
def test_select_knowledge_empty_kg_skips_llm():
    g = InMemoryGraph()
    llm = _FakeLLM(["SHOULD-NOT-BE-CALLED"])
    res = Planner(llm, goal="x").select_knowledge(g, assets_block="- a", kg_block="")
    assert res.selected == [] and res.error == "" and len(llm.calls) == 0


# ── 2차 plan: 의도에 plan(단계 배열) + SELECTED 프로비넌스(의도→KG 기법) ──
def test_plan_carries_plan_steps_and_selected_provenance():
    g = InMemoryGraph()
    intents_json = ('{"intents":[{"summary":"grab token","target":"admin-dashboard",'
                    '"technique":"T1552.001","plan":["fetch secret endpoint","extract token",'
                    '"call k8s api"],"from":[]}]}')
    res = Planner(_FakeLLM([intents_json]), goal="x").plan(
        g, selected_block="- T1552.001 [high] on admin-dashboard: creds")
    assert len(res.added_ids) == 1
    node = g.get_node(res.added_ids[0])
    assert node.payload["plan"] == ["fetch secret endpoint", "extract token", "call k8s api"]
    # SELECTED 프로비넌스: InMemory 는 payload 에 선택 기법 기록
    assert "T1552.001" in node.payload.get("selected_techniques", [])


# ── 태세: 2차엔 1차 선별이 SELECTED KNOWLEDGE 섹션으로 들어간다 ──
def test_situation_shows_selected_knowledge():
    g = InMemoryGraph()
    s = build_situation(g, goal="x", selected_block="- T1552.001 [high] on wiki: creds")
    assert "SELECTED KNOWLEDGE" in s and "T1552.001" in s


# ── plan: spawned_by 주면 SPAWNS 엣지로 계층 연결 ──
def test_plan_spawned_by_links_edge():
    g = InMemoryGraph()
    parent = g.add_intent({"summary": "parent"})
    res = Planner(_FakeLLM([_TWO_INTENTS]), goal="x").plan(g, spawned_by=parent)
    for child in res.added_ids:
        edges = g.edges_from(parent, Rel.SPAWNS)
        assert any(e.dst_id == child for e in edges)


# ── promote_closures: 승인된 후보만 자산에 폐쇄, 거부도 promoted 플래그로 재심사 방지 ──
def test_promote_closures_approves_and_marks():
    g = InMemoryGraph()
    ag = InMemoryAssetGraph()
    a_solr = ag.add_asset("endpoint", "solr/demo")
    a_api = ag.add_asset("endpoint", "api/customers")
    g.add_goal({"summary": "pii"})
    iid_solr = g.add_intent({"summary": "query solr demo"}, anchors=[a_solr])
    iid_api = g.add_intent({"summary": "query api"}, anchors=[a_api])
    # 둘 다 closure_candidate — 플래너가 solr 는 승격·api 는 거부
    f_solr = g.add_fact({"summary": "solr demo has no PII fields",
                         "closure_candidate": True,
                         "evidence": "luke schema shows only product_name"},
                        intent_id=iid_solr, anchors=[a_solr])
    f_api = g.add_fact({"summary": "api timed out",
                        "closure_candidate": True,
                        "evidence": "curl: timeout"},
                       intent_id=iid_api, anchors=[a_api])

    reply = ('{"closures": [{"fact_id": %d, "reason": "schema read; no PII fields"}]}'
             % f_solr)
    llm = _FakeLLM([reply])
    p = Planner(llm, goal="pii")
    res = p.promote_closures(g, ag, round=5)

    assert res.reviewed == 2 and res.rejected == 1 and res.closed_ids == [a_solr]
    assert ag.get_asset(a_solr).is_closed and ag.get_asset(a_solr).closed_at_round == 5
    assert "no PII fields" in ag.get_asset(a_solr).closure_reason
    assert ag.get_asset(a_api).is_closed is False
    # 두 후보 모두 재심사 방지(promoted 플래그)
    assert g.get_node(f_solr).payload.get("promoted") == 5
    assert g.get_node(f_api).payload.get("promoted") == 5


# ── promote_closures: 심사 완료된 후보는 두 번 호출해도 자산에 영향 없음(멱등) ──
def test_promote_closures_skips_already_promoted():
    g = InMemoryGraph()
    ag = InMemoryAssetGraph()
    a = ag.add_asset("endpoint", "x")
    f = g.add_fact({"summary": "empty", "closure_candidate": True,
                    "evidence": "read success, no target", "promoted": 1},
                   anchors=[a])
    llm = _FakeLLM([])      # LLM 호출 안 돼야 함 — 후보 없음
    res = Planner(llm, goal="g").promote_closures(g, ag, round=2)
    assert res.reviewed == 0 and res.closed_ids == []
    assert len(llm.calls) == 0            # 후보 0 → LLM 아예 안 부름


# ── promote_closures: asset_graph 없음·round 0 은 즉시 반환(안전장치) ──
def test_promote_closures_noop_guards():
    g = InMemoryGraph()
    llm = _FakeLLM([])
    assert Planner(llm, goal="g").promote_closures(g, None, round=2).reviewed == 0
    assert Planner(llm, goal="g").promote_closures(g, InMemoryAssetGraph(),
                                                   round=0).reviewed == 0
    assert len(llm.calls) == 0


# ── promote_closures: 심사 실패(JSON 깨짐)는 promoted 안 찍고 라운드 계속 ──
def test_promote_closures_parse_failure_leaves_candidates():
    g = InMemoryGraph()
    ag = InMemoryAssetGraph()
    a = ag.add_asset("endpoint", "x")
    f = g.add_fact({"summary": "empty", "closure_candidate": True,
                    "evidence": "read success"},
                   anchors=[a])
    llm = _FakeLLM(["garbage"])
    res = Planner(llm, goal="g", retries=0).promote_closures(g, ag, round=3)
    assert res.error and res.closed_ids == []
    # 파싱 실패엔 재심사 가능해야 — promoted 안 찍힘
    assert "promoted" not in g.get_node(f).payload


# ── promote_closures: 승격된 LLM 출력의 fact_id 가 후보 밖이면 무시(안전장치) ──
def test_promote_closures_ignores_unknown_fact_ids():
    g = InMemoryGraph()
    ag = InMemoryAssetGraph()
    a = ag.add_asset("endpoint", "x")
    f = g.add_fact({"summary": "empty", "closure_candidate": True,
                    "evidence": "read success"},
                   anchors=[a])
    llm = _FakeLLM(['{"closures":[{"fact_id":9999,"reason":"made up"},'
                    '{"fact_id":%d,"reason":"real"}]}' % f])
    res = Planner(llm, goal="g").promote_closures(g, ag, round=3)
    assert res.closed_ids == [a]           # 가짜 id 는 조용히 무시


# ── 유령 target 가드: KNOWN ASSETS 에 없는 FQDN 은 드롭, 느슨한 서술형은 통과 ──
def test_plan_drops_hallucinated_fqdn_target():
    reply = ('{"intents":[{"summary":"a","target":"postgres.prod.svc.cluster.local","technique":"T1"},'
             '{"summary":"b","target":"waf.corp-dmz.svc.cluster.local","technique":"T2"},'
             '{"summary":"c","target":"DB service","technique":"T3"}]}')
    llm = _FakeLLM([reply])
    g = InMemoryGraph()
    known = {"waf.corp-dmz.svc.cluster.local", "cluster-network"}   # prod.svc 는 존재 X
    res = Planner(llm, goal="g").plan(g, known_asset_names=known)
    # 두 번째(실존 FQDN), 세 번째(서술형) 통과 · 첫 번째 유령만 드롭
    assert res.proposed == 3 and res.dropped_ghost == 1 and len(res.added_ids) == 2
    added = [g.get_node(i).payload["target"] for i in res.added_ids]
    assert "postgres.prod.svc.cluster.local" not in added
    assert "waf.corp-dmz.svc.cluster.local" in added and "DB service" in added


def test_plan_no_guard_when_known_assets_absent():
    # known_asset_names=None 이면 가드 생략(기존 호출 호환)
    reply = ('{"intents":[{"summary":"a","target":"made.up.svc"}]}')
    g = InMemoryGraph()
    res = Planner(_FakeLLM([reply]), goal="g").plan(g)
    assert len(res.added_ids) == 1 and res.dropped_ghost == 0


# ── dedup 확장: 같은 라운드 완료(done/exhausted) 의도도 inflight 에 포함 → 재생성 차단 ──
def test_plan_dedup_blocks_same_round_completed_intent():
    from attacker.graph import IntentState
    g = InMemoryGraph()
    g.set_round(5)
    # R5 에 이미 완료된 의도 하나(웨이브 1 결과라고 가정)
    iid = g.add_intent({"summary": "probe waf", "target": "waf.corp-dmz.svc.cluster.local"})
    g.claim_next("w"); g.settle_intent(iid, IntentState.DONE)
    # 웨이브 2 플래너가 같은 의도 재생성 시도 → 차단
    reply = ('{"intents":[{"summary":"probe waf","target":"waf.corp-dmz.svc.cluster.local"}]}')
    res = Planner(_FakeLLM([reply]), goal="g").plan(g)
    assert res.proposed == 1 and res.deduped == 1 and res.added_ids == []


def test_plan_dedup_same_summary_different_target_still_blocks():
    # 요약 완전 일치 → target 달라도 중복으로 본다(스크린샷의 '완전 복제' 케이스 커버)
    from attacker.graph import IntentState
    g = InMemoryGraph()
    g.set_round(3)
    iid = g.add_intent({"summary": "Verify DNS exfiltration channel", "target": "a.svc"})
    g.claim_next("w"); g.settle_intent(iid, IntentState.DONE)
    reply = ('{"intents":[{"summary":"Verify DNS exfiltration channel","target":"b.svc"}]}')
    res = Planner(_FakeLLM([reply]), goal="g").plan(g)
    assert res.deduped == 1 and res.added_ids == []


# ── attempts_block 이 플래너 태세에 'APPROACHES ALREADY TRIED' 로 들어감 ──
def test_build_situation_renders_attempts_block():
    g = InMemoryGraph()
    s = build_situation(g, goal="g",
                        attempts_block="- R2 [exhausted] T1190 on waf: Re-establish RCE")
    assert "APPROACHES ALREADY TRIED" in s
    assert "Re-establish RCE" in s


# ── 이벤트 구동 폐곡선(통합): 플래너→풀→플래너 재계획으로 그래프가 자란다 ──
def test_event_driven_loop_with_pool():
    from attacker.exec_lane import ExecutionLane
    from attacker.execute_action import CommandResult
    from attacker.worker_pool import IntentOutcome, WorkerPool
    from attacker.scope import default_policy
    from attacker.actions import AttackAction

    class _R:
        def run(self, tool, args, *, stdin=None, timeout=None):
            return CommandResult(0, "ok", "")

    g = InMemoryGraph()
    # 1라운드 플래너: 의도 2개 생성
    p = Planner(_FakeLLM([_TWO_INTENTS]), goal="read PII")
    p.plan(g)
    assert len(g.frontier()) == 2

    # 워커 풀: 각 의도를 돌려 fact 하나씩 쓰고 done
    def run_intent(graph, wctx, intent):
        obs = wctx.execute(AttackAction(thought="t", tool="get", args=[f"i{intent.id}"]))
        graph.add_fact({"summary": f"result of {intent.id}",
                        "source_step_ids": [obs.step_id]}, intent_id=intent.id)
        return IntentOutcome(IntentState.DONE)

    lane = ExecutionLane(_R(), scope_policy=default_policy(),
                         session_id="s", episode=1, round=1)
    summary = WorkerPool(g, lane, run_intent, n_workers=2).run()
    assert summary.done == 2
    assert len(g.recent_facts()) == 2          # 워커가 쓴 사실이 그래프에 쌓임

    # 2라운드 플래너: 쌓인 사실을 보고 추가 의도 1개 → frontier 다시 참
    p2 = Planner(_FakeLLM(['{"intents": [{"summary": "follow-up probe", "target": "x"}]}']),
                 goal="read PII")
    res2 = p2.plan(g)
    # 플래너가 받은 태세에 1라운드 사실이 들어가 있어야(이벤트 구동)
    seen_user = p2.llm.calls[0][1]
    assert "result of" in seen_user
    assert res2.proposed == 1 and len(g.frontier()) == 1


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
    print("── 플래너 테스트 ──")
    sys.exit(_run())
