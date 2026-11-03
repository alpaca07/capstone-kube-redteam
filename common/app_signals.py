"""앱 레벨 웹 공격 신호 — 서비스 JSON 감사 로그의 요청을 웹 공격 기법으로 분류.

VM C(god-view, orchestrator.app_log_source)와 VM D(방어자, defender.filter)가 공유한다.
같은 기법 키를 써야 truth(심판)와 방어자 보고가 탐지 채점(TP/FP)에서 맞물린다. k3s 감사로그·
Falco 는 앱 레벨(HTTP 페이로드)을 못 보므로, 취약 서비스가 민감 요청마다 JSON 한 줄을 찍고
여기서 페이로드 악성 여부로 분류한다. 탐지는 '시도' 기준(차단 성사 여부는 verdict).

기법 키는 점(.) 없는 고유 토큰(scorer._base 가 서로 안 접음 → SQLi·SSRF 분리 측정). 괄호 안 실제 MITRE.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import unquote_plus, urlparse

WEB_SQLI = "WEB_SQLI"          # MITRE T1190 (Exploit Public-Facing Application)
WEB_SSRF = "WEB_SSRF"          # MITRE T1190
WEB_CMDI = "WEB_CMDI"          # MITRE T1059 / T1190
WEB_CREDLEAK = "WEB_CREDLEAK"  # MITRE T1552.001 (① 크레덴셜 노출 축)
WEB_TECHNIQUES = (WEB_SQLI, WEB_SSRF, WEB_CMDI, WEB_CREDLEAK)

_SQLI = re.compile(
    r"(?i)(union\s+select|\bor\s+1\s*=\s*1\b|--|/\*|'\s*or\b|'\s*union\b"
    r"|;\s*(drop|select|insert|update|delete)\b)")
_CMD_META = re.compile(r"[;&|`]|\$\(")


def is_internal_or_file(url: str) -> bool:
    """SSRF 판정 — file/gopher/dict 스킴, 또는 내부(.svc/.cluster.local/localhost)·사설/루프백 IP."""
    try:
        p = urlparse(url)
    except ValueError:
        return False
    if p.scheme in ("file", "gopher", "dict", "ftp"):
        return True
    if p.scheme not in ("http", "https"):
        return False
    host = (p.hostname or "").lower()
    if not host:
        return False
    if host in ("localhost", "kubernetes.default") or host.endswith(
            (".svc", ".cluster.local", ".local", ".internal")):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False   # 공인 호스트명 — 내부 아님
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_reserved or ip.is_unspecified)


def classify(path: str, query: str = "", url: Optional[str] = None) -> Optional[str]:
    """요청(path·query·url) → 웹 공격 기법. 악성 페이로드일 때만(정상 요청 None). query 는 URL 인코딩 그대로."""
    q = unquote_plus(query or "")
    if path == "/api/products" and q:
        return WEB_SQLI if _SQLI.search(q) else None
    if path == "/api/products/preview":
        return WEB_SSRF if (url and is_internal_or_file(url)) else None
    if path == "/admin/diag":
        return WEB_CMDI if _CMD_META.search(q) else None
    if path == "/debug/config":
        return WEB_CREDLEAK
    return None


def map_app_event(ev: dict) -> Optional[str]:
    """JSON 감사 로그 1줄(dict) → 기법. god-view AppLogSource 용(src!=app 이면 None)."""
    if ev.get("src") != "app":
        return None
    return classify(ev.get("path", ""), ev.get("query", "") or "", ev.get("url"))


__all__ = [
    "WEB_SQLI", "WEB_SSRF", "WEB_CMDI", "WEB_CREDLEAK", "WEB_TECHNIQUES",
    "is_internal_or_file", "classify", "map_app_event",
]
