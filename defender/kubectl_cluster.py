"""실 어댑터 — kubectl로 클러스터를 적용/삭제/조회하는 Cluster 구현.

patcher의 ClusterClient(apply/delete/healthcheck)와 state_query의 ClusterReader(can_i/get/
find_text)를 한 클래스로 구현. 명령 생성·파싱(순수)과 실제 subprocess(runner 주입) 분리 →
kubectl 없이 명령·파싱 테스트. VM B는 자기 클러스터 접근 권한(kubeconfig)으로 kubectl 실행.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Optional

from .patcher import OpResult

# runner: (args, stdin) -> RunResult. stdin은 apply -f - 용.
Runner = Callable[[list, Optional[str]], "RunResult"]

_APP_NAMESPACES = {"frontend", "backend", "database", "internal"}


@dataclass
class RunResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


class KubectlError(RuntimeError):
    pass


def subprocess_runner(kubeconfig: Optional[str] = None) -> Runner:
    """기본 runner — subprocess. 지연 import. KUBECONFIG 주입 가능(없으면 기본)."""
    def _r(args: list, stdin: Optional[str] = None) -> RunResult:
        import os
        import subprocess
        env = dict(os.environ)
        if kubeconfig:
            env["KUBECONFIG"] = kubeconfig
        p = subprocess.run(args, input=stdin, capture_output=True, text=True, env=env)
        return RunResult(p.returncode, p.stdout, p.stderr)
    return _r


class KubectlCluster:
    def __init__(self, *, runner: Optional[Runner] = None, kubeconfig: Optional[str] = None,
                 context: Optional[str] = None) -> None:
        self.runner = runner or subprocess_runner(kubeconfig)
        self.context = context

    def _run(self, *args: str, stdin: Optional[str] = None) -> RunResult:
        base = ["kubectl"]
        if self.context:
            base += ["--context", self.context]
        return self.runner(base + list(args), stdin)

    # ───────────── ClusterClient (patcher) ─────────────
    def apply(self, manifest: str, *, dry_run: bool = False) -> OpResult:
        args = ["apply", "-f", "-"]
        if dry_run:
            args.append("--dry-run=server")
        r = self._run(*args, stdin=manifest)
        return OpResult(r.returncode == 0, (r.stderr or r.stdout).strip())

    def delete(self, kind: str, name: str, namespace: str = "", *, dry_run: bool = False) -> OpResult:
        args = ["delete", kind, name, "--ignore-not-found"]
        if namespace:
            args += ["-n", namespace]
        if dry_run:
            args.append("--dry-run=server")
        r = self._run(*args)
        return OpResult(r.returncode == 0, (r.stderr or r.stdout).strip())

    def healthcheck(self) -> OpResult:
        """앱 네임스페이스의 Deployment가 모두 ready면 가용(True)."""
        r = self._run("get", "deploy", "-A", "-o", "json")
        if r.returncode != 0:
            return OpResult(False, r.stderr.strip())
        try:
            data = json.loads(r.stdout or "{}")
        except json.JSONDecodeError:
            return OpResult(False, "deploy json 파싱 실패")
        bad = []
        for item in data.get("items", []):
            ns = (item.get("metadata") or {}).get("namespace", "")
            if ns not in _APP_NAMESPACES:
                continue
            want = (item.get("spec") or {}).get("replicas", 1)
            have = (item.get("status") or {}).get("readyReplicas", 0)
            if have < want:
                bad.append(f"{ns}/{(item.get('metadata') or {}).get('name')}({have}/{want})")
        return OpResult(not bad, "ok" if not bad else "not ready: " + ", ".join(bad))

    # ───────────── ClusterReader (state_query) ─────────────
    def can_i(self, verb: str, resource: str, *, as_user: str = "",
              all_namespaces: bool = False, namespace: str = "") -> bool:
        args = ["auth", "can-i", verb, resource]
        if as_user:
            args += ["--as", as_user]
        if all_namespaces:
            args.append("-A")
        elif namespace:
            args += ["-n", namespace]
        r = self._run(*args)
        return r.stdout.strip().lower().startswith("yes")

    def get(self, kind: str, *, namespace: str = "", name: str = "") -> list:
        args = ["get", kind]
        if name:
            args.append(name)
        if namespace:
            args += ["-n", namespace]
        args += ["-o", "json"]
        r = self._run(*args)
        if r.returncode != 0:
            return []
        try:
            data = json.loads(r.stdout or "{}")
        except json.JSONDecodeError:
            return []
        if "items" in data:
            return data["items"]
        return [data] if data else []

    def find_text(self, needle: str, *, kinds: list, namespaces: list) -> bool:
        for kind in kinds:
            for ns in namespaces:
                r = self._run("get", kind, "-n", ns, "-o", "yaml")
                if r.returncode == 0 and needle in r.stdout:
                    return True
        return False


__all__ = ["RunResult", "Runner", "KubectlError", "subprocess_runner", "KubectlCluster"]
