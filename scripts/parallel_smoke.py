#!/usr/bin/env python3
"""병렬 워커 공격 하네스 스모크 — 실제 두 DGX 모델로 멀티워커 한 라운드가 도는지 확인.

실 클러스터 없이 '플러밍 + 두 LLM'만 본다: 가짜 실행기(echo)로 명령을 받아치므로,
플래너(정렬)가 의도를 뿌리고 → 워커 N(탈옥)이 claim·ReAct → 정착이 사실을 그래프에
쓰고 → 다음 웨이브로 이어지다 종료하는 '오케스트레이션+LLM'만 검증한다.
실제 공격(진짜 kubectl/psql)은 VM A에서 exec_mode로 서버를 띄웠을 때의 몫.

레포 안에서 실행(attacker/common 모듈 필요). requests 없이 urllib transport 주입이라
pydantic만 있으면 됨.

사용:
  python3 scripts/parallel_smoke.py                       # 기본: 공격 .109 / 플래너 .111
  python3 scripts/parallel_smoke.py --attacker 211.170.162.109 --planner 211.170.162.111
  python3 scripts/parallel_smoke.py --attacker-model <탈옥명> --planner-model <정렬명>
옵션:
  --workers 2  --budget 60  --max-waves 3  --time-limit 180  --timeout 300
  모델명 생략 시 각 주소의 /v1/models 에서 자동 선택(하나뿐이면 그걸, 여럿이면 목록 표시).
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from attacker.execute_action import CommandResult  # noqa: E402
from attacker.round_engine import AttackRound, RoundConfig  # noqa: E402
from attacker.graph_fake import InMemoryGraph  # noqa: E402
from attacker.scope import default_policy  # noqa: E402
from attacker.subprocess_runner import KubectlExecRunner, SubprocessRunner  # noqa: E402
from common.llm_client import OllamaClient  # noqa: E402
from common.messages import AttackTurnStart, Foothold  # noqa: E402


# ── 주소 정규화 + urllib transport(의존성 가볍게) ──
def normalize_base(arg: str) -> str:
    t = arg.strip()
    if not t.startswith(("http://", "https://")):
        t = "http://" + t
    p = urlsplit(t)
    netloc = p.netloc if ":" in p.netloc else p.netloc + ":11434"
    path = p.path.rstrip("/")
    if not path.endswith("/v1"):
        path = (path + "/v1") if path else "/v1"
    return urlunsplit((p.scheme, netloc, path, "", ""))


def urllib_transport(method: str, url: str, body, timeout: float) -> dict:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url, data=data, method=method,
        headers={"Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def discover_model(base_url: str, timeout: float) -> str | None:
    try:
        data = urllib_transport("GET", base_url.rstrip("/") + "/models", None, timeout)
    except Exception as e:  # noqa: BLE001
        print(f"  [모델 목록 조회 실패] {base_url}: {e}")
        return None
    ids = [m.get("id") for m in data.get("data", []) if m.get("id")]
    if not ids:
        print(f"  [모델 없음] {base_url}")
        return None
    if len(ids) == 1:
        return ids[0]
    print(f"  {base_url} 에 여러 모델 — --*-model 로 지정:")
    for i in ids:
        print(f"    - {i}")
    return None


# ── 가짜 실행기: 명령을 받아 그럴듯한 정찰 출력을 돌려줌(실 클러스터 불필요) ──
class EchoRunner:
    def run(self, tool, args, *, stdin=None, timeout=None):
        joined = " ".join(args)
        if tool in ("kubectl",) and "get" in args:
            out = ('{"items":[{"metadata":{"name":"postgres-0","namespace":"database"}},'
                   '{"metadata":{"name":"admin-dashboard-1","namespace":"frontend"}}]}')
        elif tool in ("curl", "wget"):
            out = "HTTP/1.1 200 OK\nServer: nginx/1.25\n<title>Internal Wiki</title>"
        elif tool in ("nc", "ncat"):
            out = "Connection to host port 5432 [tcp] succeeded!"
        else:
            out = f"[echo] {tool} {joined}"
        return CommandResult(exit_code=0, stdout=out, stderr="")


def main() -> int:
    ap = argparse.ArgumentParser(description="병렬 워커 하네스 스모크(실 두 모델)")
    ap.add_argument("--attacker", default="211.170.162.109", help="탈옥(공격) 모델 주소")
    ap.add_argument("--planner", default="211.170.162.111", help="정렬(플래너) 모델 주소")
    ap.add_argument("--attacker-model", default=None)
    ap.add_argument("--planner-model", default=None)
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--budget", type=float, default=60.0, help="의도 하나당 ReAct 예산(초)")
    ap.add_argument("--max-waves", type=int, default=3)
    ap.add_argument("--time-limit", type=float, default=180.0, help="라운드 전체 예산(초)")
    ap.add_argument("--timeout", type=float, default=300.0, help="단일 LLM 호출 타임아웃(초)")
    # ── 실행기 선택 ──
    ap.add_argument("--runner", choices=["echo", "exec", "local"], default="echo",
                    help="echo(기본,가짜·플러밍만) / exec(실 발판 파드 kubectl exec=진짜 공격) / "
                         "local(VM A 로컬 subprocess)")
    ap.add_argument("--kubeconfig", default="", help="exec 모드: 발판 전용 kubeconfig 경로")
    ap.add_argument("--namespace", default="frontend", help="exec 모드: 발판 파드 네임스페이스")
    ap.add_argument("--pod", default="deploy/attacker-foothold", help="exec 모드: 발판 파드")
    ap.add_argument("--step-timeout", type=float, default=15.0, help="단일 명령 실행 타임아웃(초)")
    args = ap.parse_args()

    atk_base = normalize_base(args.attacker)
    pln_base = normalize_base(args.planner)
    print(f"# 공격(탈옥) : {atk_base}")
    print(f"# 플래너(정렬): {pln_base}")

    atk_model = args.attacker_model or discover_model(atk_base, min(args.timeout, 30))
    pln_model = args.planner_model or discover_model(pln_base, min(args.timeout, 30))
    if not atk_model or not pln_model:
        print("모델을 확정하지 못했습니다. --attacker-model/--planner-model 로 지정하세요.")
        return 2
    print(f"# 공격 모델  : {atk_model}")
    print(f"# 플래너 모델: {pln_model}")
    print(f"# 워커 {args.workers} · 의도예산 {args.budget}s · max_waves {args.max_waves} · "
          f"라운드예산 {args.time_limit}s")

    # ── 실행기 선택 ──
    if args.runner == "exec":
        if not args.kubeconfig:
            print("\n[오류] --runner exec 는 --kubeconfig 가 필요합니다(발판 전용 kubeconfig).")
            return 2
        runner = KubectlExecRunner(kubeconfig=args.kubeconfig, namespace=args.namespace,
                                   pod_ref=args.pod, default_timeout=args.step_timeout)
        print(f"# 실행기     : exec(실 발판 파드 {args.namespace}/{args.pod}) — 진짜 공격\n")
    elif args.runner == "local":
        import os
        wd = "/tmp/attack-smoke-workspace"
        os.makedirs(wd, exist_ok=True)
        runner = SubprocessRunner(default_timeout=args.step_timeout, cwd=wd)
        print("# 실행기     : local(VM A 로컬 subprocess)\n")
    else:
        runner = EchoRunner()
        print("# 실행기     : echo(가짜 — 플러밍만, 실 클러스터 아님)\n")

    attacker_llm = OllamaClient(atk_base, atk_model, timeout=args.timeout,
                                transport=lambda m, u, b, t: urllib_transport(m, u, b, t))
    planner_llm = OllamaClient(pln_base, pln_model, timeout=args.timeout,
                               transport=lambda m, u, b, t: urllib_transport(m, u, b, t))

    cfg = RoundConfig(
        system_prompt=(_ROOT / "attacker" / "prompts" / "attacker_system.txt").read_text(encoding="utf-8"),
        session_id="smoke", n_workers=args.workers, step_timeout=args.step_timeout,
        intent_budget_sec=args.budget, intent_max_steps=8,
        planner_max_tokens=3000, max_waves=args.max_waves)

    start = AttackTurnStart(
        goal="reach the crown jewel: read customer PII rows in the 'customers' table "
             "of the postgres database in namespace 'database'",
        flag_format="FLAG{...}", time_limit_sec=int(args.time_limit),
        foothold=Foothold(attack_endpoint="10.0.0.5:8080"))

    graph = InMemoryGraph(episode=1)
    rnd = AttackRound(attacker_llm=attacker_llm, planner_llm=planner_llm,
                      runner=runner, scope_policy=default_policy(),
                      cfg=cfg, log=lambda m: print("  " + m, flush=True))

    print("── 라운드 시작 ──")
    t0 = time.time()
    try:
        res = rnd.run(start, episode=1, round=1, graph=graph)
    except Exception as e:  # noqa: BLE001
        import traceback
        traceback.print_exc()
        print(f"\n[실패] 라운드 중 예외: {type(e).__name__}: {e}")
        print("  → 주소/모델/네트워크 확인. 플래너 JSON이 계속 깨지면 토큰·프롬프트 조정 필요.")
        return 1
    dt = time.time() - t0

    print("\n── 결과 ──")
    print(f"  종료사유   : {res.end_reason.value}")
    print(f"  경과       : {dt:.1f}s (하네스 보고 {res.elapsed_sec:.1f}s)")
    print(f"  대본 스텝  : {len(res.replay_script.steps) if res.replay_script else 0}개")
    print(f"  플래그     : {[f.value for f in res.flags_obtained]}")
    facts = graph.recent_facts(limit=1000)
    findings = graph.recent_findings(limit=1000)
    intents = [n for n in graph.running_intents()] + graph.frontier(limit=1000)
    print(f"  그래프     : 사실 {len(facts)}개 · 발견 {len(findings)}개 · 남은의도 {len(intents)}개")
    print("\n  [요약]")
    for line in res.attack_summary.splitlines():
        print("  " + line)
    print("\n  [사실 샘플]")
    for f in facts[:5]:
        src = f.payload.get("source_step_ids", [])
        print(f"   - {f.payload.get('summary','')}  (steps={src})")
    if findings:
        print("\n  [발견]")
        for fd in findings[:5]:
            print(f"   - ({fd.payload.get('severity','')}) {fd.payload.get('summary','')} "
                  f"[{fd.payload.get('technique','')}]")

    # 판정: 스텝이 돌고 사실이 쌓였으면 플러밍 OK
    ok = (res.replay_script is not None and len(res.replay_script.steps) > 0 and len(facts) > 0)
    print("\n" + ("  ✅ 플러밍 OK — 플래너·워커·실행레인·정착·그래프가 두 실모델로 돌았습니다."
                  if ok else
                  "  ⚠ 스텝/사실이 안 쌓였습니다 — 모델 응답(JSON)·프롬프트·네트워크 점검."))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
