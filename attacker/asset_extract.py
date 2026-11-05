"""자산 기계 추출 — 실행한 명령·출력에서 관측 자산을 뽑는다(LLM 없음, 결정론적).

하이브리드(D) 1단계: 워커가 친 명령과 그 출력에서 서비스·엔드포인트·호스트를 정규식으로
포집해 '미식별 자산'(CPE 없음)으로 쌓는다. 식별(CPE·kind 정교화)은 2단계(1차 플래너/KG) 몫.
모델이 보고 안 한 것까지 '관측된 전부'를 포집하는 게 기계 추출의 장점.

반환은 {kind, name, attrs} 리스트 — kind는 유동(자산 그래프 설계대로 거친 분류만).
name은 자산 그래프 dedup 키라 정규화(소문자·공백제거).
"""
from __future__ import annotations

import re

# K8s 서비스 DNS: foo.bar.svc.cluster.local (하위도메인 여러 단계 허용)
_SVC_DNS = re.compile(r"\b([a-z0-9][a-z0-9.-]*\.svc\.cluster\.local)\b", re.I)
# URL: http(s)://host[:port][/path]
_URL = re.compile(r"\bhttps?://([a-z0-9.\-]+)(?::(\d+))?(/[^\s'\"]*)?", re.I)
# IP:port
_IP_PORT = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}):(\d+)\b")
# 단독 IPv4
_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# DB 접속 꼴: -h <host> ... -p <port> (psql/mysql/redis-cli 등, 포트가 콜론 아님)
_DB_HOST = re.compile(r"-h\s+([a-z0-9][a-z0-9.\-]*)", re.I)
_DB_PORT = re.compile(r"-p\s+(\d+)")


def _norm(name: str) -> str:
    return (name or "").strip().lower().rstrip(".")


def _valid_ip(ip: str) -> bool:
    try:
        return all(0 <= int(o) <= 255 for o in ip.split("."))
    except ValueError:
        return False


def extract_assets(texts, *, intent_target: str = "") -> list[dict]:
    """명령·출력 문자열들(+의도 target)에서 관측 자산을 뽑는다. name으로 중복 제거.

    texts: 자산을 긁을 문자열들(명령 전체 문자열·stdout 발췌 등)의 이터러블.
    intent_target: 플래너가 명시한 대상(가장 신뢰도 높은 자산 신호).
    """
    found: dict[str, dict] = {}       # name → asset dict(중복 제거)

    def add(kind: str, name: str, **attrs):
        name = _norm(name)
        if not name or len(name) < 3:
            return
        if name in found:
            # 이미 있으면 attrs만 보강(kind는 먼저 잡힌 것 유지)
            found[name]["attrs"].update({k: v for k, v in attrs.items() if v is not None})
            return
        found[name] = {"kind": kind, "name": name,
                       "attrs": {k: v for k, v in attrs.items() if v is not None}}

    # 의도 target: 플래너가 지목한 자산(가장 강한 신호). CIDR 범위는 단일 자산 아님 → 제외.
    if intent_target:
        raw_t = intent_target.strip()
        if not re.search(r"/\d{1,2}\b", raw_t):            # CIDR(/24 등)이면 건너뜀
            t = raw_t.split("(")[0].strip()                # 'A (B)' 꼴은 앞부분만
            m = _IP_PORT.search(t)
            if m and _valid_ip(m.group(1)):
                add("service", f"{m.group(1)}:{m.group(2)}", port=int(m.group(2)))
            elif t:
                add("service", t, source="intent_target")

    for raw in texts:
        s = str(raw or "")
        # K8s 서비스 DNS
        for m in _SVC_DNS.finditer(s):
            add("service", m.group(1))
        # URL → host(서비스) + path(엔드포인트)
        for m in _URL.finditer(s):
            host, port, path = m.group(1), m.group(2), m.group(3)
            add("service", host, port=int(port) if port else None)
            if path and path != "/" and len(path) > 1:
                add("endpoint", f"{_norm(host)}{path}", on=_norm(host))
        # IP:port → 서비스
        for m in _IP_PORT.finditer(s):
            ip, port = m.group(1), m.group(2)
            if _valid_ip(ip):
                add("service", f"{ip}:{port}", port=int(port))
        # DB 접속 꼴(-h host -p port): host에 점이 있을 때만(IP·FQDN) 서비스로(짧은 플래그값 오탐 방지)
        hm, pm = _DB_HOST.search(s), _DB_PORT.search(s)
        if hm and pm and "." in hm.group(1):
            add("service", f"{_norm(hm.group(1))}:{int(pm.group(1))}", port=int(pm.group(1)))
        # 단독 IP → 호스트(단, IP:port로 이미 잡힌 건 중복 무시됨)
        for m in _IP.finditer(s):
            ip = m.group(1)
            if _valid_ip(ip):
                add("host", ip)

    return list(found.values())


__all__ = ["extract_assets"]
