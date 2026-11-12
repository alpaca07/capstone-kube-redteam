"""방어 관점 타깃 토폴로지 — 방어 하네스가 자기 클러스터를 훑어 구조를 스냅샷.

god-view 실제 도면이 아니라 '방어자가 관측(kubectl 조회)으로 재구성한 지도'다. 대시보드(P7)가
이걸 색상코드 아키텍처 구성도로 자동 렌더한다(네임스페이스=영역, 서비스=노드, NetworkPolicy
유무=경계선). 라운드마다 다시 떠서 패치로 경계가 '생기는 변화'를 추적한다.

ClusterReader.get(kind, namespace=…) 만 쓰는 '읽기 전용' 열거 — 쓰기·판단 없음. 조회 실패/빈
결과는 조용히 건너뛴다(방어자 가시성의 한계 자체가 드러나는 설계 의도).
"""
from __future__ import annotations

from typing import Optional

# 대상 앱이 사는 네임스페이스(열거 범위). kube-system 등 플랫폼 네임스페이스는 노이즈라 기본 제외.
_DEFAULT_NAMESPACES = ("frontend", "backend", "database", "internal", "targets")


def enumerate_topology(reader, *, namespaces: Optional[list] = None) -> dict:
    """ClusterReader 로 네임스페이스별 서비스·디플로이·NetworkPolicy 를 훑어 토폴로지 dict 로.

    reader: get(kind, *, namespace="", name="") -> list[dict] 를 가진 ClusterReader(실=KubectlCluster).
    namespaces: 열거할 네임스페이스. None 이면 클러스터에서 조회(없으면 기본 앱 네임스페이스).
    반환: {"generated": False|True, "namespaces": [{name, services[], deployments[],
          network_policies[], has_network_policy}], "note": …}
    """
    get = getattr(reader, "get", None)
    if not callable(get):
        return {"generated": False, "namespaces": [], "note": "reader 에 get 없음"}

    ns_names = namespaces if namespaces is not None else _discover_namespaces(get)
    out_ns = []
    for ns in ns_names:
        services = [_svc(it) for it in _safe_get(get, "services", ns)]
        deployments = [_dep(it) for it in _safe_get(get, "deployments", ns)]
        netpols = [_name(it) for it in _safe_get(get, "networkpolicies", ns)]
        netpols = [n for n in netpols if n]
        if not (services or deployments or netpols):
            continue                       # 비거나 조회 실패한 네임스페이스는 건너뜀
        out_ns.append({
            "name": ns,
            "services": [s for s in services if s.get("name")],
            "deployments": [d for d in deployments if d.get("name")],
            "network_policies": netpols,
            "has_network_policy": bool(netpols),   # 경계선 유무(패치로 생기는 핵심 변화)
        })
    return {"generated": True, "namespaces": out_ns}


# ───────────── 조회 헬퍼(전부 방어적) ─────────────
def _discover_namespaces(get) -> list:
    items = _safe_get(get, "namespaces", "")
    names = [_name(it) for it in items]
    names = [n for n in names if n and n not in _SYSTEM_NS]
    return names or list(_DEFAULT_NAMESPACES)


_SYSTEM_NS = {"kube-system", "kube-public", "kube-node-lease", "default"}


def _safe_get(get, kind: str, namespace: str) -> list:
    try:
        r = get(kind, namespace=namespace) if namespace else get(kind)
        return r if isinstance(r, list) else []
    except Exception:                      # noqa: BLE001 — 조회 실패는 가시성 한계로 간주
        return []


def _name(item) -> str:
    return ((item or {}).get("metadata") or {}).get("name", "") if isinstance(item, dict) else ""


def _svc(item) -> dict:
    if not isinstance(item, dict):
        return {}
    spec = item.get("spec") or {}
    ports = []
    for p in spec.get("ports") or []:
        if isinstance(p, dict) and p.get("port") is not None:
            ports.append(p["port"])
    return {"name": _name(item), "type": spec.get("type", "ClusterIP"), "ports": ports,
            "selector": spec.get("selector") or {}}


def _dep(item) -> dict:
    if not isinstance(item, dict):
        return {}
    spec = item.get("spec") or {}
    return {"name": _name(item), "replicas": spec.get("replicas", 1)}


__all__ = ["enumerate_topology"]
