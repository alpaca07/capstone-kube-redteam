"""스코프 검사 — 킬스위치 2단 중 '예방'.

execute_action이 명령을 실행하기 '전에' 범위를 대조한다. 범위 밖이면 실행 안 하고 차단 +
사유 반환(VM C가 보고받아 감지·대응). 허용: 공격 대상(VM B 사설망)·클러스터 내부.
금지: 관리망(VM C) 등 명시 호스트, 인터넷(공인 IP/외부 도메인), 파괴적 명령.

순수 로직(명령 문자열 → 허용/차단). 네트워크 없이 테스트.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

# 파괴적 명령(랩 호스트 파손·범위 이탈 위험). 공격 자체(타깃 앱 공격)는 막지 않음.
_DESTRUCTIVE = [
    re.compile(r"\brm\s+-[a-zA-Z]*[rf][a-zA-Z]*\s+/"),   # rm -rf/-r/-f 로 절대경로 삭제
    re.compile(r"\bmkfs\b"),
    re.compile(r"\bdd\b[^\n]*\bof=/dev/"),
    re.compile(r"\b(shutdown|reboot|halt|poweroff|init\s+0|init\s+6)\b"),
    re.compile(r"\bwipefs\b"),
    re.compile(r">\s*/dev/sd[a-z]"),
    re.compile(r":\s*\(\s*\)\s*\{"),                       # fork bomb :(){
]

# 명령에서 호스트 뽑기: 생 IPv4 + 임의 스킴 URI의 호스트(postgresql://u:p@host:port 포함)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URI_HOST = re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]*://(?:[^/@\s\"']*@)?([^/:\s\"']+)")


@dataclass
class ScopePolicy:
    denied_hosts: list[str] = field(default_factory=list)  # 명시 금지(VM C 관리망 IP 등)
    block_public: bool = True                              # 공인 IP·외부 도메인 차단
    extra_destructive: list[str] = field(default_factory=list)  # 추가 파괴 패턴(정규식)
    protected_paths: list[str] = field(default_factory=list)    # 자기 하네스 소스/설정 경로(접근 차단)


@dataclass
class ScopeResult:
    allowed: bool
    reason: str
    hosts: list[str] = field(default_factory=list)


def default_policy(denied_hosts: Optional[list[str]] = None,
                   protected_paths: Optional[list[str]] = None) -> ScopePolicy:
    """기본 정책 — 관리망(VM C)은 denied_hosts로, 자기 하네스 소스는 protected_paths로 차단, 인터넷 차단."""
    return ScopePolicy(denied_hosts=list(denied_hosts or []), block_public=True,
                       protected_paths=list(protected_paths or []))


def _hosts_in(command: str) -> list[str]:
    out: list[str] = []
    out.extend(_URI_HOST.findall(command))
    out.extend(_IPV4.findall(command))
    # 중복 제거(순서 유지)
    seen: set[str] = set()
    uniq: list[str] = []
    for h in out:
        if h not in seen:
            seen.add(h)
            uniq.append(h)
    return uniq


def _is_internal_host(host: str) -> bool:
    """사설/클러스터 내부면 True, 외부(인터넷)면 False."""
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    h = host.lower()
    if h == "localhost" or "." not in h:          # bare 이름 = 클러스터 서비스
        return True
    if (h.endswith(".local") or h.endswith(".cluster.local")
            or h.endswith(".svc") or ".svc." in h):
        return True
    return False                                   # 공인 FQDN


def check_scope(command: str, policy: ScopePolicy) -> ScopeResult:
    """명령이 범위 안이면 allowed=True, 아니면 사유와 함께 False."""
    cmd = command or ""

    # 1) 파괴적 명령
    for pat in _DESTRUCTIVE:
        if pat.search(cmd):
            return ScopeResult(False, f"파괴적 명령 차단: /{pat.pattern}/")
    for extra in policy.extra_destructive:
        if re.search(extra, cmd):
            return ScopeResult(False, f"파괴적 명령 차단(추가): /{extra}/")

    # 1.5) 자기 하네스 경로 보호 — 공격자가 자기 소스/설정을 읽어 가짜 FLAG 를 줍는 것 방지.
    #      목표물은 원격 대상에 있지 로컬 하네스에 없다.
    for p in policy.protected_paths:
        if p and p in cmd:
            return ScopeResult(False, f"보호 경로 접근 차단(자기 하네스): {p}")

    hosts = _hosts_in(cmd)

    # 2) 명시 금지 호스트(관리망 등) — 문자열 포함도 함께 검사(안전빵)
    for d in policy.denied_hosts:
        if not d:
            continue
        if d in cmd or d in hosts:
            return ScopeResult(False, f"금지 호스트 접근: {d}", hosts)

    # 3) 인터넷(공인) 차단
    if policy.block_public:
        for h in hosts:
            # 셸 변수 미해석 호스트(예: in-cluster 스캔 루프의 10.43.0.$i)는 평가 불가 →
            # 공인 차단에서 제외. 파괴적·명시 금지호스트 검사는 위에서 이미 전체 명령에 적용됨.
            if "$" in h:
                continue
            if not _is_internal_host(h):
                return ScopeResult(False, f"범위 밖(외부) 호스트: {h}", hosts)

    return ScopeResult(True, "ok", hosts)


__all__ = ["ScopePolicy", "ScopeResult", "default_policy", "check_scope"]
