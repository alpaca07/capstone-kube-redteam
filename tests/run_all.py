#!/usr/bin/env python3
"""모든 test_*.py 를 돌려 합계 보고 — VM 어디서든 `python3 tests/run_all.py`.

각 테스트 파일은 독립 self-run(러너)이라 서브프로세스로 실행하고 결과만 집계.
pytest 불필요(의존성: pydantic·pyyaml만). CI/실제 VM 환경 검증용.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

_SUMMARY = re.compile(r"(\d+) passed, (\d+) failed")


def main() -> int:
    here = Path(__file__).resolve().parent
    files = sorted(here.glob("test_*.py"))
    if not files:
        print("test_*.py 없음")
        return 1

    total_p = total_f = 0
    rc = 0
    for f in files:
        res = subprocess.run([sys.executable, str(f)], capture_output=True, text=True)
        m = _SUMMARY.search(res.stdout)
        if m:
            p, fl = int(m.group(1)), int(m.group(2))
        else:
            p, fl = 0, 1          # 러너 자체가 터짐(import 에러 등)
        total_p += p
        total_f += fl
        ok = (fl == 0 and m is not None)
        print(f"  {'✓' if ok else '✗'} {f.name:34} {p:>3} passed, {fl} failed")
        if not ok:
            rc = 1
            if m is None:         # 크래시면 꼬리 출력(디버그)
                tail = (res.stdout + res.stderr).strip().splitlines()[-8:]
                for line in tail:
                    print(f"      | {line}")

    print(f"\n== 합계: {total_p} passed, {total_f} failed  ({len(files)} files) ==")
    return rc


if __name__ == "__main__":
    sys.exit(main())
