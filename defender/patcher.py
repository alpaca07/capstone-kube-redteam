"""패치 세트 적용기 — 라운드당 1세트 atomic.

TriageResult.patch_plan → 구체 클러스터 조치로 렌더 → 전부 dry-run(관문) → 전부 적용 →
헬스체크. dry-run이 하나라도 실패하면 세트 전체 미적용(원자성). 패치 후 서비스가 죽으면
healthcheck_passed=False (과잉 차단 감점 신호). 적용 I/O는 ClusterClient 주입 → fake 테스트.

렌더 가능한 액션(킬체인 방어): networkpolicy(③), rbac 축소(②), pod 삭제. 나머지는 미지원 기록.
실제 적용은 클러스터 전체 대상(특정 NS 아님).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Protocol, runtime_checkable

from .triage import PatchStep


@dataclass
class OpResult:
    ok: bool
    detail: str = ""


@runtime_checkable
class ClusterClient(Protocol):
    """클러스터 적용/삭제/헬스체크 이음새. 실 구현=kubectl, 테스트=fake."""

    def apply(self, manifest: str, *, dry_run: bool = False) -> OpResult:
        ...

    def delete(self, kind: str, name: str, namespace: str = "", *, dry_run: bool = False) -> OpResult:
        ...

    def healthcheck(self) -> OpResult:
        """패치 후 서비스 정상 여부(ok=True면 가용)."""
        ...


@dataclass
class AppliedPatch:
    action: str
    target: str
    ok: bool
    detail: str = ""


@dataclass
class PatchOutcome:
    applied: list[AppliedPatch] = field(default_factory=list)
    patch_applied: bool = False        # 하나라도 실제 적용됐나
    healthcheck_passed: bool = True
    note: str = ""


# ───────────── patch_plan → 구체 조치 렌더 ─────────────
@dataclass
class _Op:
    kind: str                          # "apply" | "delete"
    manifest: str = ""
    del_kind: str = ""
    del_name: str = ""
    del_ns: str = ""
    label: str = ""


def _np_manifest(ns: str) -> str:
    """database 등 NS ingress를 backend/internal 티어로만 제한하는 NetworkPolicy(③ 방어)."""
    return (
        "apiVersion: networking.k8s.io/v1\n"
        "kind: NetworkPolicy\n"
        "metadata:\n"
        f"  name: restrict-{ns}-ingress\n"
        f"  namespace: {ns}\n"
        "spec:\n"
        "  podSelector: {}\n"
        "  policyTypes: [Ingress]\n"
        "  ingress:\n"
        "  - from:\n"
        "    - namespaceSelector: {matchLabels: {tier: backend}}\n"
        "    - namespaceSelector: {matchLabels: {tier: internal}}\n")


def _strip_kind(target: str, *kinds: str) -> str:
    t = target.strip()
    for k in kinds:
        if t.lower().startswith(k + "/"):
            return t.split("/", 1)[1]
    return t


def _ns_from_target(target: str) -> Optional[str]:
    t = target.strip()
    if t.lower().startswith("ns/") or t.lower().startswith("namespace/"):
        return t.split("/", 1)[1]
    if "/" not in t and t:
        return t                       # 그냥 NS 이름으로 간주
    return None


def _ns_pod_from_target(target: str) -> tuple[str, str]:
    t = _strip_kind(target, "pod", "pods")
    if "/" in t:                       # "ns/pod"
        ns, pod = t.split("/", 1)
        return ns, pod
    return "", t


def render_op(step: PatchStep) -> Optional[_Op]:
    """patch_plan 한 단계 → 구체 조치. 미지원이면 None."""
    a = step.action.lower()
    tgt = step.target.strip()
    if "networkpolicy" in a or "netpol" in a or "network" in a:
        ns = _ns_from_target(tgt) or "database"
        return _Op(kind="apply", manifest=_np_manifest(ns), label=f"NetworkPolicy({ns})")
    if "rbac" in a or "role" in a:
        name = _strip_kind(tgt, "clusterrolebinding", "crb")
        # sa/serviceaccount 대상은 바인딩명을 특정 못 하므로 미지원(LLM이 바인딩명 주도록 유도)
        if not name or tgt.lower().startswith(("sa/", "serviceaccount/")):
            return None
        return _Op(kind="delete", del_kind="clusterrolebinding", del_name=name,
                   label=f"delete clusterrolebinding/{name}")
    if "pod" in a and ("delete" in a or "remove" in a or "kill" in a):
        ns, pod = _ns_pod_from_target(tgt)
        if not pod:
            return None
        return _Op(kind="delete", del_kind="pod", del_name=pod, del_ns=ns,
                   label=f"delete pod {ns or '?'}/{pod}")
    return None


class Patcher:
    def __init__(self, cluster: ClusterClient) -> None:
        self.cluster = cluster

    def _exec(self, op: _Op, *, dry_run: bool) -> OpResult:
        if op.kind == "apply":
            return self.cluster.apply(op.manifest, dry_run=dry_run)
        return self.cluster.delete(op.del_kind, op.del_name, op.del_ns, dry_run=dry_run)

    def apply_plan(self, plan: list[PatchStep]) -> PatchOutcome:
        rendered = [(s, render_op(s)) for s in plan]
        unsupported = [AppliedPatch(s.action, s.target, False, "미지원 액션")
                       for s, o in rendered if o is None]
        ops = [(s, o) for s, o in rendered if o is not None]

        if not ops:
            return PatchOutcome(applied=unsupported, patch_applied=False,
                                healthcheck_passed=True, note="적용할 패치 없음")

        # dry-run 관문(원자성): 하나라도 실패하면 세트 전체 미적용
        for s, o in ops:
            r = self._exec(o, dry_run=True)
            if not r.ok:
                skipped = [AppliedPatch(s2.action, s2.target, False, "세트 미적용(dry-run 실패)")
                           for s2, _ in ops]
                return PatchOutcome(applied=skipped + unsupported, patch_applied=False,
                                    healthcheck_passed=True,
                                    note=f"dry-run 실패 → 원자적 롤백: {o.label}: {r.detail}")

        # 전부 적용
        applied = []
        for s, o in ops:
            r = self._exec(o, dry_run=False)
            applied.append(AppliedPatch(s.action, s.target, r.ok, r.detail))

        hc = self.cluster.healthcheck()
        return PatchOutcome(applied=applied + unsupported,
                            patch_applied=any(a.ok for a in applied),
                            healthcheck_passed=hc.ok, note=hc.detail)


__all__ = ["OpResult", "ClusterClient", "AppliedPatch", "PatchOutcome",
           "render_op", "Patcher"]
