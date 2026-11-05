"""앱 로그 소스 — 서비스가 stdout에 찍는 JSON 감사 로그를 god-view로 읽어 웹 공격 기법을 뽑는다.

k3s 감사로그·Falco 는 '앱 레벨' 공격(SQLi·SSRF·cmd injection·cred-leak)을 못 본다(감사=k8s API,
Falco=syscall; HTTP 페이로드는 사각). 그래서 취약 서비스가 민감 요청마다 JSON 한 줄
({"ts","src":"app","svc","path","query","url"?,"status"})을 stdout 에 찍고, VM C 가 그 로그를
직접 읽어(위조·누락 방지) 페이로드 악성 여부를 판정해 기법으로 매핑한다.

로그 줄 → 기법 분류 로직은 common.app_signals(VM C·VM D 공유) — truth 와 방어자 보고가 같은 키를
써야 탐지 채점이 맞물리기 때문. 여기선 '시간창 조회 + 파일 I/O'만 담당한다.
"""
from __future__ import annotations

import json
from typing import Optional

from common.app_signals import (
    CROWN_TARGETS, WEB_CMDI, WEB_CREDLEAK, WEB_SQLI, WEB_SSRF,
    crown_target, map_app_event)
from common.k8s_logs import parse_rfc3339

from .log_source import LineReader


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

    def crowns_in_window(self, *, since_ts: float, until_ts: float) -> set[str]:
        """시간창 내 '크라운 반출 자백'으로 실제 침해된 크라운 자산 키 집합.

        기법 집합(techniques_in_window)과 '별개 축' — 기법=시도, 크라운=실제 달성.
        조건표 평가기(app_access 통로)가 이 집합으로 '목표 자산이 실제 빠졌나'를 판정한다.
        """
        out: set[str] = set()
        for line in self.reader():
            ev = _loads(line)
            if ev is None:
                continue
            ts = app_ts(ev)
            if ts is None or not (since_ts <= ts <= until_ts):
                continue
            c = crown_target(ev)
            if c:
                out.add(c)
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
    "CROWN_TARGETS", "crown_target",
    "map_app_event", "app_ts", "AppLogSource", "CompositeLogSource",
]
