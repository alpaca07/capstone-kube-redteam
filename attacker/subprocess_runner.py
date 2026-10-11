"""실 CommandRunner — 도구를 subprocess로 실행 (공격·리플레이 공용 실행 손발).

execute_action / replay_engine 이 주입받는 CommandRunner 이음새의 실제 구현.
테스트에선 fake runner를 주입하므로, 여기엔 '진짜 프로세스 실행'만 담는다.

안전:
- 범위검사(킬스위치)는 상위(execute_action·replay_engine)가 '실행 전에' 끝낸다.
  여기선 명령을 셸 해석 없이 argv 리스트로 직접 실행한다(shell=False) → 인젝션 표면 축소.
  단 tool="sh" 처럼 공격자가 명시적으로 셸을 고른 경우는 그 도구가 알아서 해석한다.
- 각 명령에 타임아웃을 건다(단일 명령이 영원히 매달리지 않게). 초과 시 exit 124 로 보고.
"""
from __future__ import annotations

import subprocess
from typing import Optional

from .execute_action import CommandResult


class SubprocessRunner:
    """argv를 shell=False로 실행. 타임아웃·실행불가·크래시를 CommandResult로 흡수."""

    def __init__(self, *, default_timeout: float = 60.0,
                 cwd: Optional[str] = None, env: Optional[dict] = None) -> None:
        self.default_timeout = default_timeout
        self.cwd = cwd
        self.env = env

    def run(self, tool: str, args: list, *, stdin: Optional[str] = None,
            timeout: Optional[float] = None) -> CommandResult:
        cmd = [tool, *[str(a) for a in args]]
        try:
            p = subprocess.run(
                cmd, input=stdin, capture_output=True, text=True,
                timeout=timeout or self.default_timeout,
                cwd=self.cwd, env=self.env, shell=False)
            return CommandResult(exit_code=p.returncode,
                                 stdout=p.stdout or "", stderr=p.stderr or "")
        except subprocess.TimeoutExpired as e:
            partial = e.stdout.decode() if isinstance(e.stdout, bytes) else (e.stdout or "")
            return CommandResult(exit_code=124, stdout=partial,
                                 stderr=f"[timeout {timeout or self.default_timeout}s] {tool}")
        except FileNotFoundError:
            return CommandResult(exit_code=127, stdout="",
                                 stderr=f"[명령 없음] {tool} (해당 도구가 이 VM에 설치돼 있어야 함)")
        except Exception as e:  # noqa: BLE001 — 실행 손발은 어떤 OS 오류도 삼켜 루프를 보호
            return CommandResult(exit_code=1, stdout="", stderr=f"[실행 오류] {type(e).__name__}: {e}")


__all__ = ["SubprocessRunner"]
