#!/usr/bin/env python3
"""DGX Ollama 공격 모델 지연·thinking 토글 자가 진단 — 실 프롬프트 그대로.

목적: 'ping' 테스트는 0.9s인데 실 공격 하네스는 120s 타임아웃이 반복될 때,
     원인이 ① 큰 프롬프트에서 Qwen3가 reasoning_effort 를 무시하는지
            ② 모델 콜드 스타트인지
            ③ 서버가 느린지
     를 사람 손 안 타고 판별한다.

실행(VM A):
    cd ~/capstone && git pull && python3 scripts/llm-latency-probe.py

출력: 케이스별 (time, content_len, finish_reason, thinking_detected) 표 + 자동 진단 메시지.
의존성: requests, pyyaml — common/llm_client.py 랑 똑같은 경로(설치돼 있음)."""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# 실 프롬프트/설정 그대로 로드 — 절대 복붙 아님
from attacker.planner import PLANNER_SYSTEM                  # noqa: E402
from attacker.intent_runner import SETTLE_SYSTEM             # noqa: E402
from common.config import load_config                        # noqa: E402

ATTACKER_SYSTEM = (Path(_ROOT) / "attacker" / "prompts" / "attacker_system.txt").read_text()


# ── 실 상황 블록(실 런에서 나오는 크기와 유사하게 — 자산 5개·사실 몇개·태세 전체) ──
_SITUATION_FOR_PLANNER = """\
GOAL: 대상 클러스터에서 다음 중요자산을 '실제로 반출'하라: 고객 PII(이름·이메일·전화·주소·주민번호) 반출; corp 운영 비밀(ops_secrets: 백업 DSN·메일 릴레이·객체저장소 키) 반출. 경로는 자유 — 정찰로 스스로 찾아라.

KNOWN ASSETS:
- foothold entry point: in-cluster exec(corp-ext/deploy/corp-attacker-foothold)
- [service] waf.corp-dmz.svc.cluster.local ✓id [explored]
  - [endpoint] waf.corp-dmz.svc.cluster.local/manager/html [explored]
  - [endpoint] waf.corp-dmz.svc.cluster.local/shell.jsp [explored]
- [service] kubernetes.default.svc.cluster.local [explored]
- [service] 10.43.0.1 [untouched]
- [service] cluster-network [explored]

CANDIDATE KNOWLEDGE (ATT&CK techniques the KB associates with the assets above — triage these):
- T1190 initial-access (conf 0.90; matches: waf, tomcat; via CVE-2017-12617)
- T1552 unsecured-creds (conf 0.80; matches: tomcat, config; via N/A)
- T1046 network-service-discovery (conf 0.75; matches: cluster-network; via N/A)
- T1552.001 credentials-in-files (conf 0.70; matches: webapp; via N/A)
- T1552.007 container-api (conf 0.60; matches: kubernetes; via N/A)

SELECTED KNOWLEDGE (stage-1 triage — techniques judged applicable to the assets):
- T1190 [high] on waf.corp-dmz.svc.cluster.local: known Tomcat 8.5.19 RCE path
- T1552.001 [medium] on waf.corp-dmz.svc.cluster.local: configs likely contain DB DSN

RECENT FACTS:
- #41 Tomcat Manager HTML interface returns 403 for default credentials (observed)
- #42 PUT to /shell.jsp succeeded with trailing slash; JSP webshell deployed (observed)
- #43 shell.jsp responds to ?cmd=id → uid=0(root) (observed)
- #44 env on webshell: no DB_URL/PG_HOST variables set (observed)
- #45 postgres.corp-dmz.svc.cluster.local does not resolve via cluster DNS (observed)

UNUSED FINDINGS (credentials/accesses already obtained but NOT yet leveraged — each line is 'F<id>: ...'). For every one that advances the GOAL, add ONE follow-up intent that USES it against the next target (e.g. authenticate to a service with the credential, or pivot deeper), and put that finding's number in "enables": [<id>]. Do not merely re-discover it — act on it:
F39: Remote Code Execution achieved via CVE-2017-12617 by deploying a JSP webshell [critical] (T1190) on waf.corp-dmz.svc.cluster.local

PREVIOUSLY BREACHED (last round — re-verify, may be patched):
- RCE via CVE-2017-12617 on waf.corp-dmz.svc.cluster.local [critical] (T1190)

APPROACHES ALREADY TRIED (previous rounds/waves ran these and got no breach — DO NOT propose a near-identical intent against the same target. If you must revisit one, state a genuinely DIFFERENT angle in "summary" and "why" — a new technique, a different endpoint path, fresh evidence that changes the picture. Repeating the same approach wastes intents and the attempt count stacks up as proof of futility):
- R2 [exhausted] T1552 on waf.corp-dmz.svc.cluster.local: Extract DB credentials from Tomcat context.xml
- R2 [exhausted] T1046 on cluster-network: Enumerate reachable internal services via nmap
- R3 [exhausted] T1552 on waf.corp-dmz.svc.cluster.local: Search Tomcat webapps for config files with DSN
- R3 [done] T1021 on postgres.corp.svc.cluster.local: Resolve and connect to internal DB
- R4 [exhausted] T1552.001 on waf.corp-dmz.svc.cluster.local: env + /proc inspection for creds
- R4 [exhausted] T1083 on waf.corp-dmz.svc.cluster.local: filesystem walk for config files

INTENTS ALREADY IN FLIGHT: (none)

TARGET INTENTS THIS WAVE: up to 2 (2 parallel workers will drain them). Give as many distinct, genuinely worthwhile directions as the current surface supports — fewer than 2 is correct when there isn't that much worth probing. Do NOT pad to the number with filler or near-duplicate directions."""


_SITUATION_FOR_WORKER = """\
INTENT: Probe the WAF service for exposed admin interfaces, API endpoints, or misconfigurations that reveal internal routing or credentials
TARGET: waf.corp-dmz.svc.cluster.local
WHY: path to PII via WAF compromise
TECHNIQUE: T1595.002
PLAN: ["enumerate WAF interfaces", "probe for misconfigurations", "extract credentials from configs"]

관측:
(아직 행동 없음)

예산: 120초 남음. 다음 행동을 JSON 형식으로 출력하라. 예: {"thought":"...","action":{"tool":"sh","args":["-c","<command>"]}}"""


_SITUATION_FOR_SETTLE = """\
Exploration direction:
INTENT: Probe the WAF service for exposed admin interfaces
TARGET: waf.corp-dmz.svc.cluster.local

What you observed:
[step 1] cmd: sh -c curl -sS http://waf.corp-dmz.svc.cluster.local/manager/html
          exit=0 stdout(200): HTTP/1.1 401 Unauthorized\\nWWW-Authenticate: Basic realm="Tomcat Manager Application"
[step 2] cmd: sh -c curl -sS -u tomcat:tomcat http://waf.corp-dmz.svc.cluster.local/manager/html
          exit=0 stdout(150): HTTP/1.1 403 Access Denied

Summarize your conclusions as the specified JSON object."""


def _call(url: str, body: dict, timeout: float = 150.0) -> dict:
    import requests
    t0 = time.time()
    try:
        r = requests.post(url, json=body, headers={"Content-Type": "application/json"},
                          timeout=timeout)
        elapsed = time.time() - t0
        try:
            data = r.json()
        except Exception:    # noqa: BLE001
            return {"ok": False, "elapsed": elapsed, "error": f"비JSON 응답({r.status_code})",
                    "body_snippet": r.text[:200]}
        if r.status_code != 200:
            return {"ok": False, "elapsed": elapsed, "error": f"HTTP {r.status_code}",
                    "body_snippet": str(data)[:200]}
        msg = (data.get("choices") or [{}])[0].get("message") or {}
        return {
            "ok": True,
            "elapsed": elapsed,
            "content": msg.get("content") or "",
            "reasoning_len": len(msg.get("reasoning") or ""),
            "finish_reason": (data.get("choices") or [{}])[0].get("finish_reason"),
            "prompt_tokens": (data.get("usage") or {}).get("prompt_tokens"),
            "completion_tokens": (data.get("usage") or {}).get("completion_tokens"),
        }
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "elapsed": time.time() - t0, "error": f"{type(e).__name__}: {e}"}


def _probe(url: str, model: str, label: str, system: str, user: str,
           *, reasoning_effort: str = "none", extra_body: dict | None = None,
           max_tokens: int = 200) -> dict:
    body: dict = {
        "model": model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "temperature": 0.0,
        "max_tokens": max_tokens,
        "stream": False,
    }
    if reasoning_effort is not None:
        body["reasoning_effort"] = reasoning_effort
    if extra_body:
        body.update(extra_body)
    # 사람이 멍하니 기다리지 않게 — 케이스 시작·끝을 각각 flush 해서 터미널에 즉시 반영
    print(f"  ▶ {label:<42} (측정 중 — 최대 150s)", end="", flush=True)
    res = _call(url, body)
    res["label"] = label
    res["sys_len"] = len(system)
    res["usr_len"] = len(user)
    res["reasoning_effort"] = reasoning_effort
    # 완료 — carriage return 으로 '측정 중' 줄 덮어씀
    print("\r" + " " * 80 + "\r", end="", flush=True)
    return res


def _row(r: dict) -> str:
    if not r.get("ok"):
        return (f"  {r['label']:<42} [실패] {r['elapsed']:6.2f}s  {r.get('error','')}"
                f"  ({r.get('body_snippet','')[:80]})")
    thinking = "O" if r["reasoning_len"] > 0 else "-"
    return (f"  {r['label']:<42} {r['elapsed']:6.2f}s  content={len(r['content']):>4}자  "
            f"thinking={thinking}  finish={str(r['finish_reason'])[:6]:<6}  "
            f"tok={r.get('prompt_tokens','?')}→{r.get('completion_tokens','?')}")


def main() -> int:
    cfg = load_config()
    url = cfg.dgx.attacker_base_url + "/chat/completions"
    model = cfg.dgx.attacker_model
    print(f"\n대상: {url}")
    print(f"모델: {model}")
    print(f"프롬프트 크기: planner_sys={len(PLANNER_SYSTEM)}자, "
          f"planner_situation={len(_SITUATION_FOR_PLANNER)}자, "
          f"attacker_sys={len(ATTACKER_SYSTEM)}자, "
          f"settle_sys={len(SETTLE_SYSTEM)}자\n")

    # 1회차는 warmup 포함일 수 있어 ping 두 번(콜드/웜 체크)
    print("── warmup(ping, reasoning_effort=none) 2회 ──", flush=True)
    for i in range(2):
        r = _probe(url, model, f"ping#{i+1}", "", "ping", max_tokens=20)
        print(_row(r), flush=True)
    # 첫 호출이 150s 걸려 실패했다면 서버 자체가 뻗은 상태 → 나머지 측정 무의미
    if not r.get("ok"):
        print("\n⚠ warmup ping 도 실패 — DGX Ollama 서버가 응답 안 함. "
              "서버 재시작부터 확인하세요(nvidia-smi / sudo systemctl restart ollama).",
              flush=True)
        return 2

    cases = [
        # 작은 프롬프트에서 reasoning_effort 효과 (대조군)
        ("ping / reasoning_effort=none",            "", "ping",                        "none",  None, 20),
        ("ping / reasoning_effort 없음",             "", "ping",                        None,    None, 20),

        # 실 PLANNER_SYSTEM + 실 상황 (하네스가 보내는 2차 플래너 호출과 동일 구조)
        ("PLANNER 실프롬프트 / r_e=none",          PLANNER_SYSTEM, _SITUATION_FOR_PLANNER, "none",  None, 600),
        ("PLANNER 실프롬프트 / r_e 없음",           PLANNER_SYSTEM, _SITUATION_FOR_PLANNER, None,    None, 600),
        # 폴백 스위치 — /no_think 를 user 끝에 추가 (구버전 Ollama 대비)
        ("PLANNER 실프롬프트 / r_e=none + /no_think",
         PLANNER_SYSTEM, _SITUATION_FOR_PLANNER + "\n\n/no_think", "none", None, 600),

        # 실 ATTACKER_SYSTEM + 실 상황 (ReAct 워커 한 스텝과 동일 구조)
        ("ATTACKER(ReAct) 실프롬프트 / r_e=none",   ATTACKER_SYSTEM, _SITUATION_FOR_WORKER, "none",  None, 400),
        ("ATTACKER(ReAct) 실프롬프트 / r_e 없음",    ATTACKER_SYSTEM, _SITUATION_FOR_WORKER, None,    None, 400),

        # 실 SETTLE
        ("SETTLE 실프롬프트 / r_e=none",            SETTLE_SYSTEM, _SITUATION_FOR_SETTLE, "none",  None, 400),
    ]

    print("\n── 실 프롬프트 측정 ──", flush=True)
    results: list[dict] = []
    for label, sys_p, usr_p, re_, extra_, mt in cases:
        r = _probe(url, model, label, sys_p, usr_p, reasoning_effort=re_,
                   extra_body=extra_, max_tokens=mt)
        results.append(r)
        print(_row(r), flush=True)

    # ── 자동 진단 ──
    print("\n── 자동 진단 ──")
    ok = [r for r in results if r.get("ok")]
    issues: list[str] = []

    # 1) r_e='none' 플래너가 실패/비정상 느림(>60s)
    pln_ne = next((r for r in ok if r["label"] == "PLANNER 실프롬프트 / r_e=none"), None)
    pln_no = next((r for r in ok if r["label"] == "PLANNER 실프롬프트 / r_e 없음"), None)
    if pln_ne and pln_ne["elapsed"] > 60:
        issues.append(f"⚠ 실제 PLANNER 호출이 {pln_ne['elapsed']:.1f}s 로 지나치게 느림 — "
                      "하네스 120s 타임아웃의 원인으로 유력")
    if pln_ne and pln_ne["reasoning_len"] > 0:
        issues.append("⚠ reasoning_effort='none' 보냈는데도 응답에 reasoning 필드가 실림 — "
                      "Qwen3이 큰 프롬프트에서 플래그 무시. Modelfile 베이크 필요")
    if pln_ne and pln_no and pln_no["elapsed"] > pln_ne["elapsed"] * 1.3:
        issues.append(f"→ 그래도 r_e=none 가 r_e 없음({pln_no['elapsed']:.1f}s)보다는 빠름 "
                      "→ 플래그가 '부분적으로' 먹음(일부 호출에서만)")

    # 2) ATTACKER(ReAct) 쪽
    atk = next((r for r in ok if r["label"] == "ATTACKER(ReAct) 실프롬프트 / r_e=none"), None)
    if atk and atk["elapsed"] > 60:
        issues.append(f"⚠ 실제 ATTACKER(ReAct) 호출이 {atk['elapsed']:.1f}s — "
                      "워커 intent budget(120s) 안에 명령 1~2회만 가능 → 지금 보이는 '0 facts, exhausted'와 일치")

    # 3) /no_think 폴백 효과
    nt = next((r for r in ok if "/no_think" in r["label"]), None)
    if pln_ne and nt and nt["elapsed"] < pln_ne["elapsed"] * 0.7:
        issues.append(f"✓ /no_think 폴백이 효과 있음({pln_ne['elapsed']:.1f}s → {nt['elapsed']:.1f}s) — "
                      "임시로 user 프롬프트 끝에 '/no_think' 추가하는 패치가 유효")

    # 4) 토큰 처리율
    if atk and atk["completion_tokens"]:
        tps = atk["completion_tokens"] / max(0.1, atk["elapsed"])
        if tps < 5:
            issues.append(f"⚠ 생성 속도가 {tps:.1f} tok/s 로 비정상적으로 느림 — "
                          "GPU 자원 경합·모델 양자화 문제·서버 과부하 의심 (정상이면 ≥20)")

    if not issues:
        print("  (뚜렷한 이상 신호 없음 — 실 런 저널 llm= 수치랑 이 결과 비교해주세요.)")
    else:
        for m in issues:
            print(" ", m)

    # ── 처방 ──
    print("\n── 처방 ──")
    if pln_ne and pln_ne["reasoning_len"] > 0 and pln_ne["elapsed"] > 30:
        print("""  [고확률] 큰 프롬프트에서 Qwen3가 reasoning_effort 를 무시
    → DGX 에서 non-thinking 변종 베이크:
        cat > /tmp/Modelfile.nt <<'EOF'
        FROM """ + model + """
        PARAMETER temperature 0
        SYSTEM "/no_think  Skip all internal reasoning; respond directly."
        EOF
        ollama create """ + model + """-nt -f /tmp/Modelfile.nt
    → config.yaml 의 dgx.attacker_model 을 '""" + model + """-nt' 로 교체 후 VM A 재시작""")
    elif atk and atk["elapsed"] > 30:
        print("""  [중확률] 서버·GPU 자원 문제 — DGX 에서:
        nvidia-smi             # GPU VRAM/프로세스 경합
        ollama ps              # 모델 로드 상태
        sudo systemctl restart ollama   # 상태 꼬임 해소
        env OLLAMA_KEEP_ALIVE=24h       # 모델 unload 방지""")
    else:
        print("  현재 실측은 정상 범위. 하네스 재시작 후 실 런 저널의 llm= 수치와 재대조하세요.")
    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
