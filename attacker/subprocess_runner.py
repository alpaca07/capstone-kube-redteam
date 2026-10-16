"""실 CommandRunner — 도구를 subprocess로 실행 (공격·리플레이 공용 실행 손발).

execute_action / replay_engine 이 주입받는 CommandRunner 이음새의 실제 구현.
테스트에선 fake runner를 주입하므로, 여기엔 '진짜 프로세스 실행'만 담는다.

안전:
- 범위검사(킬스위치)는 상위(execute_action·replay_engine)가 '실행 전에' 끝낸다.
  여기선 명령을 셸 해석 없이 argv 리스트로 직접 실행한다(shell=False) → 인젝션 표면 축소.
  단 tool="sh" 처럼 공격자가 명시적으로 셸을 고른 경우는 그 도구가 알아서 해석한다.
- 각 명령에 타임아웃을 건다(단일 명령이 영원히 매달리지 않게). 초과 시 exit 124 로 보고.

실행 위치:
- 기본(exec_prefix 없음): 이 VM(VM A)에서 직접 실행.
- KubectlExecRunner: exec_prefix 로 명령을 `kubectl exec <발판파드> -- <tool> <args>` 로 감싸
  frontend 파드 '안'에서 실행 → 공격자가 클러스터 내부 서비스에 도달('웹 계층 침해' 발판).
  argv 리스트로 투명하게 앞에 붙일 뿐이라 상위 로직·리플레이 대본(안쪽 명령만 기록)은 불변.
"""
from __future__ import annotations

import subprocess
from typing import Optional

from .execute_action import CommandResult


class SubprocessRunner:
    """argv를 shell=False로 실행. 타임아웃·실행불가·크래시를 CommandResult로 흡수."""

    def __init__(self, *, default_timeout: float = 15.0,
                 cwd: Optional[str] = None, env: Optional[dict] = None,
                 exec_prefix: Optional[list] = None) -> None:
        self.default_timeout = default_timeout
        self.cwd = cwd
        self.env = env
        self.exec_prefix = list(exec_prefix) if exec_prefix else []   # 명령 앞에 붙일 argv(예: kubectl exec …)

    def _build_cmd(self, tool: str, args: list) -> list:
        """실제로 실행할 argv. exec_prefix 가 있으면 그 뒤에 tool·args 를 붙인다(투명 래핑)."""
        return [*self.exec_prefix, tool, *[str(a) for a in args]]

    def run(self, tool: str, args: list, *, stdin: Optional[str] = None,
            timeout: Optional[float] = None) -> CommandResult:
        cmd = self._build_cmd(tool, args)
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


class KubectlExecRunner(SubprocessRunner):
    """공격 명령을 frontend 발판 파드 '안'에서 kubectl exec 로 실행하는 러너('웹 계층 침해' 발판).

    명령을 `kubectl --kubeconfig <kc> exec -n <ns> <pod> -i -- <tool> <args…>` 로 투명 래핑한다.
    → 공격자가 internal-wiki·postgres 등 .svc.cluster.local 내부 서비스에 도달(킬체인 ①③④).
    kubeconfig 는 frontend exec 전용(secret-read·pod생성 없음)이라 ②는 여전히 스스로 털어야 한다.
    SubprocessRunner 를 그대로 재사용하되 exec_prefix 만 붙이므로 타임아웃·오류 흡수는 동일.
    """

    def __init__(self, *, kubeconfig: str, namespace: str = "frontend",
                 pod_ref: str = "deploy/attacker-foothold", default_timeout: float = 15.0,
                 env: Optional[dict] = None) -> None:
        prefix = ["kubectl", "--kubeconfig", kubeconfig, "exec",
                  "-n", namespace, pod_ref, "-i", "--"]
        super().__init__(default_timeout=default_timeout, env=env, exec_prefix=prefix)


__all__ = ["SubprocessRunner", "KubectlExecRunner"]
