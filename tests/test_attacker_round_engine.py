"""라운드 엔진 테스트 — 플래너 웨이브 루프·AttackTurnResult 조립·종료사유·
회차 그래프 지속·데드라인. LLM만 fake, 나머지 전부 실제 경로.

    python3 tests/test_attacker_round_engine.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.execute_action import CommandResult  # noqa: E402
from attacker.graph_fake import InMemoryGraph  # noqa: E402
from attacker.round_engine import AttackRound, RoundConfig  # noqa: E402
from attacker.scope import default_policy  # noqa: E402
from common.messages import AttackEndReason, AttackTurnStart, Foothold  # noqa: E402


class _R:
    def __init__(self, stdout="ok"):
        self.stdout = stdout

    def run(self, tool, args, *, stdin=None, timeout=None):
        return CommandResult(0, self.stdout, "")


class _PlanLLM:
    """웨이브별 응답을 순서대로. 끝나면 빈 intents(종료 신호)."""
    def __init__(self, waves):
        self._waves = list(waves)
        self.calls = 0

    def chat_text(self, system, user, **kw):
        self.calls += 1
        if self._waves:
            return self._waves.pop(0)
        return '{"intents": []}'


class _WorkLLM:
    """워커: 관측 없으면 한 번 정찰, 있으면 give_up. 정착은 고정 fact."""
    def __init__(self, settle='{"facts":[{"summary":"observed something"}],"finding":null}'):
        self._settle = settle

    def chat_text_meta(self, system, user, **kw):
        if "아직 행동 없음" in user:
            return '{"thought":"probe","action":{"tool":"kubectl","args":["get","po"]}}', "stop"
        return '{"thought":"done","action":{"tool":"give_up","args":[]}}', "stop"

    def chat_text(self, system, user, **kw):
        return self._settle


def _start(goal="read customer PII", t=300.0):
    return AttackTurnStart(goal=goal,
                           time_limit_sec=int(t),
                           foothold=Foothold(attack_endpoint="10.0.0.5:8080"))


def _cfg(**kw):
    kw.setdefault("n_workers", 2)
    return RoundConfig(system_prompt="attacker-sys", **kw)


_TWO = ('{"intents":[{"summary":"probe pg","target":"postgres","technique":"T1046"},'
        '{"summary":"enum SA","target":"admin","technique":"T1078"}]}')


# ── 한 웨이브 후 플래너 고갈 → 라운드 종료, 결과 조립 ──
def test_single_wave_then_planner_empty():
    plan = _PlanLLM([_TWO])          # 1웨이브만 의도, 그 뒤 빈 → 종료
    rnd = AttackRound(attacker_llm=_WorkLLM(), planner_llm=plan, runner=_R(),
                      scope_policy=default_policy(), cfg=_cfg())
    g = InMemoryGraph(episode=1)
    res = rnd.run(_start(), episode=1, round=1, graph=g)
    # 의도 2개 처리 → 사실 2개, 대본 스텝 ≥2
    assert len(g.recent_facts()) == 2
    assert len(res.replay_script.steps) >= 2
    assert plan.calls == 2           # 1웨이브 계획 + 종료 확인 계획
    assert res.end_reason == AttackEndReason.DEADEND   # 플래그 없음·시간 안 소진
    assert "웨이브" in res.attack_summary


# ── 여러 웨이브: 플래너가 두 번 의도 내고 세 번째 빈 → 2웨이브 ──
def test_multiple_waves_accumulate():
    plan = _PlanLLM([_TWO,
                     '{"intents":[{"summary":"follow up","target":"x"}]}'])
    rnd = AttackRound(attacker_llm=_WorkLLM(), planner_llm=plan, runner=_R(),
                      scope_policy=default_policy(), cfg=_cfg())
    g = InMemoryGraph(episode=1)
    res = rnd.run(_start(), episode=1, round=1, graph=g)
    # 웨이브1 의도2 + 웨이브2 의도1 = 사실 3개
    assert len(g.recent_facts()) == 3
    # 2웨이브 돌았음(요약에 반영)
    assert res.attack_summary.startswith("2개 웨이브")


# ── 플래그리스: 공격자는 성공을 자기보고하지 않는다 — 시간 안 소진이면 플래너 고갈로 DEADEND ──
def test_planner_exhaustion_ends_deadend():
    # 워커가 정찰만 하고 플래너가 고갈되면, 공격자는 FLAG 를 못 "보고"하고 DEADEND 로 끝난다.
    # (최종 침해 판정은 심판이 접근기록=크라운으로 내린다 — 공격자 결과엔 성공 플래그가 없다.)
    class _ProbeWork(_WorkLLM):
        def chat_text_meta(self, system, user, **kw):
            if "아직 행동 없음" in user:
                return '{"thought":"p","action":{"tool":"cat","args":["/etc/passwd"]}}', "stop"
            return '{"thought":"done","action":{"tool":"give_up","args":[]}}', "stop"

    plan = _PlanLLM(['{"intents":[{"summary":"grab secret","target":"db"}]}'])
    rnd = AttackRound(attacker_llm=_ProbeWork(), planner_llm=plan,
                      runner=_R(stdout="here: s0me-secret-value"),
                      scope_policy=default_policy(), cfg=_cfg(n_workers=1))
    g = InMemoryGraph(episode=1)
    res = rnd.run(_start(), episode=1, round=1, graph=g)
    assert res.end_reason == AttackEndReason.DEADEND
    assert res.replay_script is not None and len(res.replay_script.steps) >= 1


# ── 회차 그래프 지속: 같은 그래프로 2라운드 → 사실 누적, 대본은 라운드별 ──
def test_graph_persists_across_rounds():
    rnd = AttackRound(attacker_llm=_WorkLLM(), planner_llm=_PlanLLM([_TWO, _TWO]),
                      runner=_R(), scope_policy=default_policy(), cfg=_cfg())
    g = InMemoryGraph(episode=1)
    r1 = rnd.run(_start(), episode=1, round=1, graph=g)
    facts_after_r1 = len(g.recent_facts())
    # 2라운드: 같은 그래프(회차 지속) — 새 플래너 LLM 필요하므로 새 엔진
    rnd2 = AttackRound(attacker_llm=_WorkLLM(), planner_llm=_PlanLLM([_TWO]),
                       runner=_R(), scope_policy=default_policy(), cfg=_cfg())
    r2 = rnd2.run(_start(), episode=1, round=2, graph=g)
    assert len(g.recent_facts()) > facts_after_r1           # 사실 누적(회차 기억)
    # 대본은 라운드별로 분리(각자 자기 라운드 번호)
    assert r1.replay_script.round == 1 and r2.replay_script.round == 2
    assert all(s.step_id.startswith("1.") for s in r1.replay_script.steps)
    assert all(s.step_id.startswith("2.") for s in r2.replay_script.steps)


# ── 데드라인: 시간 0이면 웨이브 안 돌고 TIMEOUT로 즉시 종료 ──
def test_deadline_zero_timeouts_immediately():
    # 가짜 시계: 호출 때마다 0 유지하되, 데드라인=t0+0 이라 while 조건 바로 거짓
    plan = _PlanLLM([_TWO])
    rnd = AttackRound(attacker_llm=_WorkLLM(), planner_llm=plan, runner=_R(),
                      scope_policy=default_policy(), cfg=_cfg(),
                      clock=lambda: 100.0)      # 고정 시계 → deadline=100, clock()>=100 즉시참
    g = InMemoryGraph(episode=1)
    res = rnd.run(_start(t=0.0), episode=1, round=1, graph=g)
    assert plan.calls == 0                      # 웨이브 자체를 안 돌림
    assert res.end_reason == AttackEndReason.TIMEOUT
    assert len(res.replay_script.steps) == 0


# ── max_waves 안전장치: 플래너가 계속 의도를 내도 상한에서 멈춤 ──
def test_max_waves_cap():
    # 플래너가 무한정 의도를 냄(항상 비지 않음)
    class _InfPlan:
        calls = 0
        def chat_text(self, system, user, **kw):
            type(self).calls += 1
            return '{"intents":[{"summary":"more","target":"x"}]}'
    plan = _InfPlan()
    rnd = AttackRound(attacker_llm=_WorkLLM(), planner_llm=plan, runner=_R(),
                      scope_policy=default_policy(), cfg=_cfg(max_waves=3))
    g = InMemoryGraph(episode=1)
    rnd.run(_start(), episode=1, round=1, graph=g)
    assert plan.calls == 3                       # 상한 3웨이브에서 멈춤


# ── _asset_situation: 자산 그래프를 계층(부모→자식)으로 렌더, 식별표시, 발판 줄 ──
def test_asset_situation_renders_hierarchy():
    from attacker.assets_fake import InMemoryAssetGraph
    from attacker.round_engine import _asset_situation
    ag = InMemoryAssetGraph(episode=1)
    host = ag.add_asset("host", "10.43.214.23")
    ag.add_asset("service", "10.43.214.23:5432", parent=host, cpe="cpe:/a:postgresql")
    s = _asset_situation(ag, foothold_line="- foothold entry point: 10.0.0.5:8080")
    assert "foothold entry point" in s
    assert "- [host] 10.43.214.23" in s
    assert "  - [service] 10.43.214.23:5432 ✓id" in s   # 자식 들여쓰기 + 식별표시


# ── _asset_situation: touched 주면 explored/untouched 표시 ──
def test_asset_situation_marks_explored_untouched():
    from attacker.assets_fake import InMemoryAssetGraph
    from attacker.round_engine import _asset_situation
    ag = InMemoryAssetGraph(episode=1)
    hit = ag.add_asset("service", "internal-wiki")
    miss = ag.add_asset("service", "payments-api")
    s = _asset_situation(ag, touched={hit})
    assert "- [service] internal-wiki [explored]" in s
    assert "- [service] payments-api [untouched]" in s
    # touched 미지정이면 표시 없음(기존 호출 호환)
    s2 = _asset_situation(ag)
    assert "[explored]" not in s2 and "[untouched]" not in s2


# ── R2 통합: 앵커된 자산은 explored, 안 친 자산은 untouched 로 플래너 태세에 뜬다 ──
def test_round2_marks_touched_assets_in_situation():
    from attacker.assets_fake import InMemoryAssetGraph
    captured = {}

    class _CapPlan:
        def chat_text(self, system, user, **kw):
            captured["user"] = user
            return '{"intents": []}'

    g = InMemoryGraph(episode=1)
    ag = InMemoryAssetGraph(episode=1)
    probed = ag.add_asset("service", "internal-wiki")
    ag.add_asset("service", "payments-api")           # 안 친 자산
    # 지난 라운드 의도가 internal-wiki 를 앵커(= 탐색됨)
    iid = g.add_intent({"summary": "probe wiki"})
    g.anchor_to(iid, [probed])
    rnd = AttackRound(attacker_llm=_WorkLLM(), planner_llm=_CapPlan(), runner=_R(),
                      scope_policy=default_policy(), cfg=_cfg())
    rnd.run(_start(), episode=1, round=2, graph=g, asset_graph=ag)
    u = captured["user"]
    assert "internal-wiki [explored]" in u
    assert "payments-api [untouched]" in u


# ── KG 가시성: 태세 로그에 KG 연결/후보 수가 찍힌다(1차 플래너 KG 사용 여부 노출) ──
def test_kg_visibility_in_situation_log():
    from attacker.assets_fake import InMemoryAssetGraph

    class _P:                                   # 빈 의도 반환(웨이브 1회로 종료)
        def chat_text(self, system, user, **kw):
            return '{"intents": []}'

    # (1) kg_lookup 미연결 → "KG미연결"
    logs1: list = []
    g1 = InMemoryGraph(episode=1); ag1 = InMemoryAssetGraph(episode=1)
    ag1.add_asset("service", "internal-wiki")
    AttackRound(attacker_llm=_WorkLLM(), planner_llm=_P(), runner=_R(),
                scope_policy=default_policy(), cfg=_cfg(), log=logs1.append
                ).run(_start(), episode=1, round=1, graph=g1, asset_graph=ag1, kg_lookup=None)
    assert any("KG미연결" in m for m in logs1), logs1

    # (2) kg_lookup 이 후보 2줄 반환 → "KG후보 2개"
    logs2: list = []
    g2 = InMemoryGraph(episode=1); ag2 = InMemoryAssetGraph(episode=1)
    ag2.add_asset("service", "internal-wiki")
    kg2 = lambda _ag: ("- T1552 creds (conf 0.80; matches: wiki; via CVE-1)\n"
                       "- T1078 valid-acct (conf 0.60; matches: sa; via CVE-2)")
    AttackRound(attacker_llm=_WorkLLM(), planner_llm=_P(), runner=_R(),
                scope_policy=default_policy(), cfg=_cfg(), log=logs2.append
                ).run(_start(), episode=1, round=1, graph=g2, asset_graph=ag2, kg_lookup=kg2)
    assert any("KG후보 2개" in m for m in logs2), logs2


# ── KG→플래너 도달: kg_lookup 후보가 플래너 user 프롬프트의 RELEVANT KNOWLEDGE 로 들어간다 ──
# (기존 test_kg_visibility 는 저널 로그만 확인 — 후보 '내용'이 실제 계획 입력까지 가는지는 여기서)
def test_kg_candidates_reach_planner_prompt():
    from attacker.assets_fake import InMemoryAssetGraph
    captured = {}

    class _CapPlan:
        def chat_text(self, system, user, **kw):
            captured["user"] = user
            return '{"intents": []}'          # 1웨이브로 종료

    g = InMemoryGraph(episode=1)
    ag = InMemoryAssetGraph(episode=1)
    ag.add_asset("service", "gitlab.frontend.svc")
    # knowledge.query.render_kg_candidates 가 내는 모양 그대로(직접 매핑 0.95)
    kg = lambda _ag: (
        "- T1190 Exploit Public-Facing Application (conf 0.95; matches: gitlab; via CVE-2021-22205)\n"
        "- T1059 Command and Scripting Interpreter (conf 0.95; matches: gitlab; via CVE-2021-22205)")
    AttackRound(attacker_llm=_WorkLLM(), planner_llm=_CapPlan(), runner=_R(),
                scope_policy=default_policy(), cfg=_cfg()
                ).run(_start(), episode=1, round=1, graph=g, asset_graph=ag, kg_lookup=kg)
    u = captured["user"]
    assert "RELEVANT KNOWLEDGE" in u                   # 섹션 헤더가 프롬프트에 들어감
    assert "T1190" in u and "T1059" in u               # 후보 기법 id 가 계획 입력까지 도달
    assert "conf 0.95" in u                            # 신뢰도까지 그대로 전달(플래너가 가중 판단)


# ── _asset_situation: 없거나 비면 발판 줄로 폴백(기존 동작 호환) ──
def test_asset_situation_empty_falls_back_to_foothold():
    from attacker.assets_fake import InMemoryAssetGraph
    from attacker.round_engine import _asset_situation
    fl = "- foothold entry point: 10.0.0.5:8080"
    assert _asset_situation(None, foothold_line=fl) == fl
    assert _asset_situation(InMemoryAssetGraph(episode=1), foothold_line=fl) == fl


# ── _prior_findings_block: 지난 라운드 발견을 앵커된 자산명과 함께 렌더 ──
def test_prior_findings_block_renders_with_asset_names():
    from attacker.assets_fake import InMemoryAssetGraph
    from attacker.round_engine import _prior_findings_block
    g = InMemoryGraph(episode=1)
    ag = InMemoryAssetGraph(episode=1)
    aid = ag.add_asset("service", "admin-dashboard")
    fid = g.add_finding({"summary": "leaked token", "severity": "critical",
                         "technique": "T1552"}, anchors=[aid])
    s = _prior_findings_block(g, {fid}, ag)
    assert "leaked token" in s and "critical" in s and "T1552" in s
    assert "admin-dashboard" in s                      # 앵커된 자산명
    assert _prior_findings_block(g, set(), ag) == ""   # 빈 집합이면 빈 문자열


# ── R2 통합: 플래너가 받는 태세에 자산 지형 + 지난 라운드 침해(재검증)가 들어간다 ──
def test_planner_sees_assets_and_prior_breach_in_round2():
    from attacker.assets_fake import InMemoryAssetGraph
    captured = {}

    class _CapPlan:
        def chat_text(self, system, user, **kw):
            captured["user"] = user
            return '{"intents": []}'          # 즉시 종료(1웨이브)

    g = InMemoryGraph(episode=1)
    ag = InMemoryAssetGraph(episode=1)
    aid = ag.add_asset("service", "postgres.database.svc.cluster.local")
    # 지난 라운드 발견(R2 시작 전 그래프에 이미 존재) → 스냅샷되어 재검증 섹션으로
    g.add_finding({"summary": "dumped crown creds", "severity": "high",
                   "technique": "T1552"}, anchors=[aid])
    rnd = AttackRound(attacker_llm=_WorkLLM(), planner_llm=_CapPlan(), runner=_R(),
                      scope_policy=default_policy(), cfg=_cfg())
    rnd.run(_start(), episode=1, round=2, graph=g, asset_graph=ag)
    u = captured["user"]
    assert "KNOWN ASSETS" in u and "postgres.database.svc.cluster.local" in u
    assert "PREVIOUSLY BREACHED" in u and "dumped crown creds" in u and "T1552" in u


# ── R1(첫 라운드)엔 지난 라운드가 없으므로 재검증 섹션이 안 뜬다 ──
def test_round1_has_no_prior_breach_section():
    from attacker.assets_fake import InMemoryAssetGraph
    captured = {}

    class _CapPlan:
        def chat_text(self, system, user, **kw):
            captured.setdefault("user", user)
            return '{"intents": []}'

    g = InMemoryGraph(episode=1)
    ag = InMemoryAssetGraph(episode=1)
    # R1인데도 그래프에 발견이 있다 치더라도(비정상) round>1 아니면 스냅샷 안 함
    g.add_finding({"summary": "should not appear", "severity": "high"}, anchors=[])
    rnd = AttackRound(attacker_llm=_WorkLLM(), planner_llm=_CapPlan(), runner=_R(),
                      scope_policy=default_policy(), cfg=_cfg())
    rnd.run(_start(), episode=1, round=1, graph=g, asset_graph=ag)
    assert "PREVIOUSLY BREACHED" not in captured["user"]


# ── 겹침 억제: 한 웨이브가 같은 자산 2개 겨냥 → 1개만 실행(사실 1개) ──
def test_round_dedups_same_target_intents():
    dup = ('{"intents":[{"summary":"probe pg a","target":"postgres","technique":"T1046"},'
           '{"summary":"probe pg b","target":"postgres","technique":"T1046"}]}')
    plan = _PlanLLM([dup])
    rnd = AttackRound(attacker_llm=_WorkLLM(), planner_llm=plan, runner=_R(),
                      scope_policy=default_policy(), cfg=_cfg())
    g = InMemoryGraph(episode=1)
    rnd.run(_start(), episode=1, round=1, graph=g)
    assert len(g.recent_facts()) == 1          # 같은 자산 겨냥 2개 중 1개만 실행


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
    print("── 라운드 엔진 테스트 ──")
    sys.exit(_run())
