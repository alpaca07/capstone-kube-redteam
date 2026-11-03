"""앱 로그 소스 — 서비스가 stdout에 찍는 JSON 감사 로그를 god-view로 읽어 웹 공격 기법을 뽑는다.

k3s 감사로그·Falco 는 '앱 레벨' 공격(SQLi·SSRF·cmd injection·cred-leak)을 못 본다(감사=k8s API,
Falco=syscall; HTTP 페이로드는 사각). 그래서 취약 서비스가 민감 요청마다 JSON 한 줄
({"ts","src":"app","svc","path","query","url"?,"status"})을 stdout 에 찍고, VM C 가 그 로그를
직접 읽어(위조·누락 방지) 페이로드 악성 여부를 판정해 기법으로 매핑한다. 탐지는 '시도' 기준
(차단 성사 여부는 verdict). 하드닝 버전도 시도는 로깅(탐지≠차단).

매핑:
  /api/products?q=  에 SQLi 토큰           → WEB_SQLI     (MITRE T1190)
  /api/products/preview url 이 내부/파일    → WEB_SSRF     (T1190)
  /admin/diag?host= 에 셸 메타문자          → WEB_CMDI     (T1059/T1190)
  /debug/config 접근                        → WEB_CREDLEAK (T1552.001)
신규 서비스/경로는 여기 매핑만 늘리면 CompositeLogSource 로 truth 에 자동 편입된다.
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import Optional
from urllib.parse import unquote_plus, urlparse

from common.k8s_logs import parse_rfc3339

from .log_source import LineReader

# 웹 기법 키 — 점(.) 없는 고유 토큰(scorer._base 가 서로 안 접음 → SQLi·SSRF 분리 측정).
WEB_SQLI = "WEB_SQLI"          # MITRE T1190 (Exploit Public-Facing Application)
WEB_SSRF = "WEB_SSRF"          # MITRE T1190
WEB_CMDI = "WEB_CMDI"          # MITRE T1059 / T1190
WEB_CREDLEAK = "WEB_CREDLEAK"  # MITRE T1552.001 (① 크레덴셜 노출 축)

_SQLI = re.compile(
    r"(?i)(union\s+select|\bor\s+1\s*=\s*1\b|--|/\*|'\s*or\b|'\s*union\b"
    r"|;\s*(drop|select|insert|update|delete)\b)")
_CMD_META = re.compile(r"[;&|`]|\$\(")


def _is_internal_or_file(url: str) -> bool:
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


def map_app_event(ev: dict) -> Optional[str]:
    """앱 감사 로그 1줄(dict) → 웹 공격 기법. 악성 페이로드일 때만 기법(정상 요청은 None)."""
    if ev.get("src") != "app":
        return None
    path = ev.get("path", "")
    query = unquote_plus(ev.get("query", "") or "")
    if path == "/api/products" and query:
        return WEB_SQLI if _SQLI.search(query) else None
    if path == "/api/products/preview":
        url = ev.get("url")
        return WEB_SSRF if (url and _is_internal_or_file(url)) else None
    if path == "/admin/diag":
        return WEB_CMDI if _CMD_META.search(query) else None
    if path == "/debug/config":
        return WEB_CREDLEAK
    return None


def _loads(line: str) -> Optional[dict]:
    try:
        obj = json.loads(line)
        return obj if isinstance(obj, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


def app_ts(ev: dict) -> Optional[float]:
    return parse_rfc3339(ev.get("ts", ""))


class AppLogSource:
    """서비스 앱 감사 로그를 god-view로 조회. 시간창 내 관측 웹 기법 집합 반환."""

    def __init__(self, reader: LineReader) -> None:
        self.reader = reader

    def techniques_in_window(self, *, since_ts: float, until_ts: float) -> set[str]:
        out: set[str] = set()
        for line in self.reader():
            ev = _loads(line)
            if ev is None:
                continue
            ts = app_ts(ev)
            if ts is None or not (since_ts <= ts <= until_ts):
                continue
            t = map_app_event(ev)
            if t:
                out.add(t)
        return out


class CompositeLogSource:
    """여러 LogSource 를 합쳐 기법 집합을 합집합(Audit+Falco+App). LogSource Protocol 충족."""

    def __init__(self, *sources) -> None:
        self.sources = sources

    def techniques_in_window(self, *, since_ts: float, until_ts: float) -> set[str]:
        out: set[str] = set()
        for s in self.sources:
            out |= s.techniques_in_window(since_ts=since_ts, until_ts=until_ts)
        return out


__all__ = [
    "WEB_SQLI", "WEB_SSRF", "WEB_CMDI", "WEB_CREDLEAK",
    "map_app_event", "app_ts", "AppLogSource", "CompositeLogSource",
]
