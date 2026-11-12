#!/usr/bin/env python3
"""크라운 통로 점검기 — 실 VM-C 로그에 대고 게이트와 동일 경로로 반출 크라운을 뽑는다.

메인 킬체인 ④(직접 DB 접속 → 민감 테이블 조회)의 god-view 판정은
orchestrator.db_log_source.DbLogSource.crowns_in_window 이 담당한다. 이 스크립트는
그 클래스를 config.yaml 그대로 실 로그 파일에 물려 돌려, 루프를 돌리기 전에
'통로 정상 / 어디서 끊겼는지'를 한 번에 확인한다(validate_reinforce_run.py 의 운영측 짝).

사용:
  python3 -m scripts.check_crown_channel                 # 저장소 config.yaml, 파일 전체
  python3 -m scripts.check_crown_channel --config config.yaml --window-min 10
종료코드: 0=크라운 탐지, 1=통로 미완(미연결/포맷/스코핑/미도달), 2=설정·파일 오류
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from collections import Counter

# 저장소 루트 import 보장(python 파일 직접 실행 대비)
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.app_signals import crown_of_sql                       # noqa: E402
from common.config import load_config                             # noqa: E402
from orchestrator.db_log_source import DbLogSource, _pg_ts, _ROLE, _STMT  # noqa: E402


def _fmt_roles(roles) -> str:
    return ", ".join(sorted(roles)) if roles else "(스코핑 없음 — 모든 role)"


def main() -> int:
    ap = argparse.ArgumentParser(description="크라운 통로 점검")
    ap.add_argument("--config", default=None, help="config.yaml 경로(기본: 탐색)")
    ap.add_argument("--window-min", type=float, default=None,
                    help="최근 N분만 검사(기본: 파일 전체). 스모크 직후 확인용")
    args = ap.parse_args()

    try:
        cfg = load_config(args.config)
    except Exception as e:                                        # noqa: BLE001
        print(f"[오류] config 로드 실패: {e}", file=sys.stderr)
        return 2

    path = cfg.observability.db_log_path
    roles = set(cfg.observability.attacker_db_roles or [])
    print("크라운 통로 점검 — scripts/check_crown_channel.py")
    print(f"로그 경로   : {path}   (observability.db_log_path)")
    print(f"스코핑 role : {_fmt_roles(roles)}   (observability.attacker_db_roles)")

    if path.startswith("~"):
        print(f"\n[치명] db_log_path 가 틸드로 시작: {path}")
        print("  file_line_reader 는 open() 에 경로를 그대로 넘겨 ~ 를 확장하지 않는다.")
        print(f"  절대경로로 교체할 것:  echo \"$HOME{path[1:]}\"  → 출력값을 config 에 기입")
        return 2
    if not os.path.isfile(path):
        print(f"\n[단절:미연결] 로그 파일이 없음: {path}")
        print("  원인 후보: (1) sync 미기동  (2) db_log_path 가 sync 출력 경로와 불일치")
        print("  확인:  bash scripts/vmc-sync-dblog.sh &   # 기본 출력 $HOME/capstone/logs/vmb-dblog.log")
        print("  두 경로(DBLOG_LOCAL == observability.db_log_path)를 절대경로로 일치시킬 것")
        return 1

    try:
        with open(path, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        print(f"\n[오류] 로그 열기 실패: {e}", file=sys.stderr)
        return 2

    until = time.time() + 3600.0
    since = (time.time() - args.window_min * 60.0) if args.window_min else 0.0

    # 게이트와 '같은' 판정 경로(권위) — DbLogSource 를 config 그대로 물린다.
    src = DbLogSource(lambda: iter(lines), attacker_roles=roles or None)
    crowns = src.crowns_in_window(since_ts=since, until_ts=until)

    # 진단용 집계 + 증거줄(판정과 무관, 끊긴 지점 특정용).
    n_ts = n_stmt = 0
    role_ct: Counter = Counter()
    evidence: list[tuple[str, str, str]] = []   # (crown, role@db, sql) — 스코핑 내
    missed: list[tuple[str, str, str]] = []     # 크라운 쿼리지만 스코핑에서 제외됨
    for ln in lines:
        ts = _pg_ts(ln)
        if ts is None or not (since <= ts <= until):
            continue
        n_ts += 1
        rm = _ROLE.search(ln)
        role = rm.group("role") if rm else "?"
        if rm:
            role_ct[role] += 1
        sm = _STMT.search(ln)
        if not sm:
            continue
        n_stmt += 1
        c = crown_of_sql(sm.group(1))           # 스코핑과 무관하게 크라운 여부 먼저 판정
        if not c:
            continue
        at = (rm.group(0).split()[-1] if rm else "?")
        sql_disp = sm.group(1).strip()[:90]
        in_scope = (not roles) or (rm is not None and role in roles)
        (evidence if in_scope else missed).append((c, at, sql_disp))

    scope = f"최근 {args.window_min:g}분" if args.window_min else "파일 전체"
    print("-" * 60)
    print(f"검사 범위      : {scope}")
    print(f"총 줄          : {len(lines)}")
    print(f"타임스탬프 인식 : {n_ts}")
    print(f"statement 줄   : {n_stmt}")
    obs = ", ".join(f"{r}({c})" for r, c in role_ct.most_common()) or "(role prefix 미검출)"
    print(f"관측 role      : {obs}")
    print("-" * 60)

    if crowns:
        print("크라운 반출(게이트 판정 경로):")
        seen = set()
        for c, at, sql in evidence:
            key = (c, at, sql)
            if key in seen:
                continue
            seen.add(key)
            print(f"  {c:16s} ← {at:28s} {sql}")
        print(f"판정: 크라운 {len(crowns)}종 탐지 — 통로 정상")
        return 0

    # 미탐 — 끊긴 지점 특정
    print("크라운 반출: 없음")
    if n_ts == 0:
        print("[단절:포맷] 타임스탬프 인식 0 — log_line_prefix 불일치 또는 로그 빔")
        print("  VM-B postgres 설정 확인: log_statement=all, log_line_prefix='%m [%p] %u@%d '")
    elif n_stmt == 0:
        print("[단절:statement] 접속은 보이나 statement 줄 없음 — log_statement=all 미적용 의심")
    elif missed:
        print(f"[단절:스코핑] 크라운 쿼리가 로그에 있으나 스코핑({_fmt_roles(roles)})에서 제외됨:")
        seen = set()
        for c, at, sql in missed:
            if (c, at) in seen:
                continue
            seen.add((c, at))
            print(f"  {c:16s} ← {at:28s} {sql}")
        drop = sorted({at.split('@')[0] for _, at, _ in missed})
        print(f"  누락 role: {', '.join(drop)} — 이 중 유출 크레덴셜 role 을 attacker_db_roles 에 추가할 것")
    else:
        print("[미도달] 통로·스코핑 정상, 단 스코핑 role 의 민감 테이블 조회가 아직 없음(크라운 전)")
        print("  스모크로 통로만 확인:")
        print("    kubectl --kubeconfig ~/.kube/vmb-admin.kubeconfig exec -n database deploy/postgres -- \\")
        print("      psql -U appuser -d customerdb -c \"SELECT * FROM customers LIMIT 1;\"")
        print("  또는 --force-crown 없이 공격 루프를 돌려 워커가 직접 도달하는지 볼 것")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
