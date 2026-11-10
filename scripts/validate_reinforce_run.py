#!/usr/bin/env python3
"""공격 강화 검증기 — VM A 공격 하네스 저널 로그를 먹여, 이번 세션의 네 강화가
실제로 '작동했는지'를 로그 신호로 판정한다. LLM·네트워크·그래프 불필요(순수 파싱).

판정 대상(이번 세션 공격 강화):
  ① 반복 억제(no-progress)   : 같은 명령/같은 출력 반복을 끊었는가
  ② 워커 겹침 억제(dedup)    : 같은 자산 동시 겨냥을 플래너가 떨궜는가
  ③ 자산 겨냥(asset)         : 플래너가 자산 지형(미탐색 포함)을 받았는가
  ④ 공진화 재검증(re-verify) : R2+ 에서 지난 라운드 침해가 재검증 후보로 들어갔는가

쓰는 법:
  # VM A 에서 한 회차(2라운드 이상) 돌린 뒤 저널을 뽑아 먹인다
  journalctl -u <공격하네스유닛> --since '10 min ago' -o cat | \\
      python3 scripts/validate_reinforce_run.py
  # 또는 파일로
  python3 scripts/validate_reinforce_run.py run.log
  # 파서 자체 점검(합성 로그)
  python3 scripts/validate_reinforce_run.py --selftest
"""
from __future__ import annotations

import re
import sys
from collections import defaultdict

# ── 로그 라인 패턴(공격 하네스가 실제로 찍는 형식과 1:1) ──
_RE_NOPROG = re.compile(r"진전 없음\(반복 명령/동일 결과\)\s+(\d+)/(\d+)")
_RE_NOPROG_END = re.compile(r"연속 진전 없음\s+(\d+)회")
_RE_EXECFAIL_END = re.compile(r"연속 실행 실패\s+(\d+)회")
_RE_WAVE = re.compile(r"\[round r(\d+)\] wave (\d+): 플래너가 의도 (\d+)개 생성(?:, 겹침 (\d+)개 제거)?")
_RE_SITU = re.compile(r"\[round r(\d+)\] wave (\d+): 태세 → 자산 (\d+)개\(미탐색 (\d+)\) · 지난라운드침해 (\d+)건")
_RE_INTENT = re.compile(r"·\s*intent#(\d+):\s*(.*?)(?:\s*→\s*(.+?))?(?:\s*\[([^\]]+)\])?\s*$")
_RE_STEP = re.compile(r"\[공격 step (\d+)\]")
_RE_GIVEUP = re.compile(r"give_up\(막다른 길\)")
_RE_FLAG = re.compile(r"FLAG\{[^}]*\}")
_RE_KG_CAND = re.compile(r"KG후보 (\d+)개")              # 1차: 플래너가 받은 KG 후보 기법 수
_RE_KG_NOLINK = re.compile(r"KG미연결")                  # KG 미배선(graph_backend≠neo4j)
_RE_KG_PROC = re.compile(r"⟐ KG 절차 참고\(([^)]+)\)")   # 2차: 워커가 받은 핵심층 절차(기법)


def analyze(lines) -> dict:
    r = {
        "noprog_hits": 0, "noprog_deadends": 0, "execfail_deadends": 0,
        "dedup_total": 0, "waves": 0, "steps": 0, "give_ups": 0, "flags": 0,
        "rounds": defaultdict(lambda: {"waves": 0, "intents": 0, "deduped": 0,
                                       "targets": [], "situ": []}),
        "situ_rounds": set(),          # 태세 요약이 찍힌 라운드
        "reverify_rounds": set(),      # 지난라운드침해>0 로 재검증 후보가 들어간 라운드
        "untouched_seen": False,       # 미탐색 자산>0 을 한 번이라도 봤나
        "kg_cand_hits": 0,             # 1차 KG 후보 기법이 플래너에 주입된 횟수(후보>0)
        "kg_cand_total": 0,            # 주입된 KG 후보 기법 누계
        "kg_nolink": 0,                # KG 미연결 로그 횟수(graph_backend≠neo4j)
        "kg_proc_hits": 0,             # 2차 KG 절차가 워커에 주입된 횟수
        "kg_proc_techs": set(),        # 절차 주입된 기법 집합
    }
    for raw in lines:
        s = raw.rstrip("\n")
        if _RE_NOPROG.search(s):
            r["noprog_hits"] += 1
        if _RE_NOPROG_END.search(s):
            r["noprog_deadends"] += 1
        if _RE_EXECFAIL_END.search(s):
            r["execfail_deadends"] += 1
        # KG 신호 — 1차 후보는 태세 라인에 붙고(그 라인은 아래서 continue) 2차 절차는 별도 라인이라,
        # continue 전에 먼저 검사한다.
        m = _RE_KG_CAND.search(s)
        if m and int(m.group(1)) > 0:
            r["kg_cand_hits"] += 1
            r["kg_cand_total"] += int(m.group(1))
        if _RE_KG_NOLINK.search(s):
            r["kg_nolink"] += 1
        m = _RE_KG_PROC.search(s)
        if m:
            r["kg_proc_hits"] += 1
            r["kg_proc_techs"].add(m.group(1).strip())
        m = _RE_WAVE.search(s)
        if m:
            rd, _wv, nint, ndd = m.group(1), m.group(2), int(m.group(3)), int(m.group(4) or 0)
            r["waves"] += 1
            r["dedup_total"] += ndd
            rr = r["rounds"][rd]
            rr["waves"] += 1
            rr["intents"] += nint
            rr["deduped"] += ndd
            continue
        m = _RE_SITU.search(s)
        if m:
            rd, _wv, nast, nun, nbr = (m.group(1), m.group(2), int(m.group(3)),
                                       int(m.group(4)), int(m.group(5)))
            r["situ_rounds"].add(rd)
            r["rounds"][rd]["situ"].append((nast, nun, nbr))
            if nun > 0:
                r["untouched_seen"] = True
            if nbr > 0:
                r["reverify_rounds"].add(rd)
            continue
        m = _RE_INTENT.search(s)
        if m and m.group(3):
            # intent 로그에서 target 수집(플래너가 무엇을 겨냥했나 — 다양성 확인용)
            # 어느 라운드인지 직접 안 적혀 있으니 최근 wave 라운드에 귀속(근사)
            tgt = m.group(3).strip()
            if tgt:
                # 가장 최근 라운드 키(없으면 '?')
                last = max(r["rounds"].keys(), default="?")
                r["rounds"][last]["targets"].append(tgt)
        if _RE_STEP.search(s):
            r["steps"] += 1
        if _RE_GIVEUP.search(s):
            r["give_ups"] += 1
        if _RE_FLAG.search(s):
            r["flags"] += 1
    return r


def _verdict(ok: bool) -> str:
    return "\033[32m관측됨\033[0m" if ok else "\033[31m안 보임\033[0m"


def render(r: dict) -> str:
    out = []
    out.append("═══ 공격 강화 검증 ═══\n")

    multiround = len([k for k in r["rounds"] if k.isdigit()]) >= 2 or \
        any(int(k) >= 2 for k in r["rounds"] if k.isdigit())
    f1 = r["noprog_hits"] > 0 or r["noprog_deadends"] > 0
    f2 = r["dedup_total"] > 0
    f3 = len(r["situ_rounds"]) > 0 and r["untouched_seen"]
    f4 = len(r["reverify_rounds"]) > 0
    f5 = r["kg_cand_hits"] > 0          # 1차: 플래너가 KG 후보 기법을 실제로 받음
    f6 = r["kg_proc_hits"] > 0          # 2차: 워커가 핵심층 절차를 실제로 받음

    out.append(f"① 반복 억제(no-progress)   {_verdict(f1)}  "
               f"— 진전없음 감지 {r['noprog_hits']}회, 조기종료 {r['noprog_deadends']}회")
    out.append(f"② 워커 겹침 억제(dedup)    {_verdict(f2)}  "
               f"— 겹침 제거 누계 {r['dedup_total']}개")
    out.append(f"③ 자산 겨냥(asset)         {_verdict(f3)}  "
               f"— 태세 요약 찍힌 라운드 {sorted(r['situ_rounds'])}, 미탐색>0 {r['untouched_seen']}")
    out.append(f"④ 공진화 재검증(re-verify) {_verdict(f4)}  "
               f"— 지난라운드침해 투입 라운드 {sorted(r['reverify_rounds'])}"
               + ("" if multiround else "  (주의: 멀티라운드 로그가 아니면 ④는 원래 안 뜸)"))
    out.append(f"⑤ KG 후보 기법 주입(1차)   {_verdict(f5)}  "
               f"— 후보 주입 {r['kg_cand_hits']}회(누계 {r['kg_cand_total']}개)"
               + (f", KG미연결 {r['kg_nolink']}회" if r["kg_nolink"] else ""))
    out.append(f"⑥ KG 절차 주입(2차)        {_verdict(f6)}  "
               f"— 절차 주입 {r['kg_proc_hits']}회, 기법 {sorted(r['kg_proc_techs'])}")

    out.append("\n── 라운드별 ──")
    for rd in sorted(r["rounds"], key=lambda k: (not k.isdigit(), k)):
        rr = r["rounds"][rd]
        tset = list(dict.fromkeys(rr["targets"]))          # 순서 유지 중복 제거
        situ = rr["situ"][-1] if rr["situ"] else None
        situ_s = (f" 자산{situ[0]}(미탐색{situ[1]})·침해{situ[2]}" if situ else "")
        out.append(f"  R{rd}: 웨이브 {rr['waves']} · 의도 {rr['intents']} · "
                   f"겹침제거 {rr['deduped']}{situ_s}")
        if tset:
            out.append(f"        겨냥 자산: {', '.join(tset[:12])}")

    out.append("\n── 전체 ──")
    out.append(f"  스텝 {r['steps']} · give_up {r['give_ups']} · "
               f"exec-fail 조기종료 {r['execfail_deadends']} · FLAG 언급 {r['flags']}")
    if r["steps"]:
        waste = 100.0 * r["noprog_hits"] / r["steps"]
        out.append(f"  반복 낭비 비율(진전없음/스텝): {waste:.1f}%  "
                   f"(낮을수록 좋음 — 억제 전엔 env|grep 반복으로 높았음)")

    out.append("\n── 판정 ──")
    missing = [n for n, ok in [("①", f1), ("②", f2), ("③", f3), ("④", f4),
                               ("⑤", f5), ("⑥", f6)] if not ok]
    if not missing:
        out.append("  네 강화 모두 로그에서 관측됨. ✅")
    else:
        hint = ""
        if "③" in missing or "④" in missing:
            hint = "  (③④가 안 뜨면: 자산 그래프가 비었거나 병렬 경로가 아님 — mode=parallel·asset_graph 확인)"
        if "②" in missing:
            hint += "\n  (②는 플래너가 같은 자산을 두 번 안 냈으면 원래 0 — 정상일 수 있음)"
        if "⑤" in missing or "⑥" in missing:
            hint += ("\n  (⑤⑥ KG 미관측: graph_backend=neo4j·KG 적재 확인. 'KG미연결' 로그가 뜨면 "
                     "백엔드가 memory라 KG 콜백이 None. ⑥은 그 라운드 의도에 technique 가 없었거나 "
                     "그 기법의 Procedure 가 KG 에 없으면 원래 안 뜸)")
        out.append(f"  미관측: {', '.join(missing)}.{hint}")
    return "\n".join(out)


_SELFTEST_LOG = """\
[10:00:01] [round r1] wave 1: 플래너가 의도 3개 생성, 겹침 1개 제거
[10:00:01] [round r1] wave 1: 태세 → 자산 6개(미탐색 5) · 지난라운드침해 0건 · KG후보 4개
[10:00:02]     · intent#2: probe pg → postgres.database.svc.cluster.local [T1046]
[10:00:02]     · intent#3: enum sa → admin-dashboard [T1078]
[10:00:02] [work1·intent#2] ⟐ KG 절차 참고(T1046)
[10:00:03] [work1·intent#2] [공격 step 1] llm=1.2s exec=0.1s | sh -c env|grep
[10:00:04] [work1·intent#2] [공격] 진전 없음(반복 명령/동일 결과) 1/4 | sh env|grep
[10:00:05] [work1·intent#2] [공격] 진전 없음(반복 명령/동일 결과) 2/4 | sh env|grep
[10:00:06] [work1·intent#2] [공격 step 5] → give_up(막다른 길)
[10:00:20] [round r2] wave 1: 플래너가 의도 2개 생성
[10:00:20] [round r2] wave 1: 태세 → 자산 9개(미탐색 4) · 지난라운드침해 2건 · KG후보 3개
[10:00:21]     · intent#7: re-verify creds → postgres.database.svc.cluster.local [T1552]
[10:00:30] [work0·intent#7] [공격] 연속 진전 없음 4회(반복 낭비) → 턴 종료
[10:00:31] [work1·intent#8] [공격] 연속 실행 실패 8회(경로 차단 추정) → 턴 종료
[10:00:40] here: FLAG{smoke}
"""


def _selftest() -> int:
    r = analyze(_SELFTEST_LOG.splitlines())
    checks = {
        "noprog_hits>=2": r["noprog_hits"] >= 2,
        "noprog_deadends==1": r["noprog_deadends"] == 1,
        "execfail_deadends==1": r["execfail_deadends"] == 1,
        "dedup_total==1": r["dedup_total"] == 1,
        "situ_rounds has 1,2": r["situ_rounds"] == {"1", "2"},
        "reverify_rounds has 2 only": r["reverify_rounds"] == {"2"},
        "untouched_seen": r["untouched_seen"] is True,
        "flags>=1": r["flags"] >= 1,
        "give_ups>=1": r["give_ups"] >= 1,
        "kg_cand_hits==2": r["kg_cand_hits"] == 2,
        "kg_cand_total==7": r["kg_cand_total"] == 7,       # 4 + 3
        "kg_proc_hits>=1": r["kg_proc_hits"] >= 1,
        "kg_proc_techs has T1046": "T1046" in r["kg_proc_techs"],
    }
    ok = all(checks.values())
    for name, passed in checks.items():
        mark = "\033[32m✓\033[0m" if passed else "\033[31m✗\033[0m"
        print(f"  {mark} {name}")
    print("\n" + render(r))
    print(f"\nselftest: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


def main(argv) -> int:
    if "--selftest" in argv:
        return _selftest()
    if len(argv) > 1 and not argv[1].startswith("-"):
        with open(argv[1], encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    else:
        lines = sys.stdin.readlines()
    if not lines:
        print("입력 로그가 비어 있음. journalctl … | python3 scripts/validate_reinforce_run.py",
              file=sys.stderr)
        return 2
    print(render(analyze(lines)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
