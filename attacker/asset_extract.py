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

    반환 각 자산: {kind, name, attrs, parent?}. parent는 상위 자산 name(계층 CONTAINS용).
    호스트⊃서비스⊃엔드포인트 2~3단 계층을 암시한다. 단독 IP 남발은 안 함(노이즈 방지) —
    IP는 그 위에 포트·URL·엔드포인트가 관측될 때 '호스트 부모'로만 생성.

    texts: 자산을 긁을 문자열들. intent_target: 플래너가 지목한 대상(최강 신호).
    """
    found: dict[str, dict] = {}       # name → asset dict(중복 제거)

    def add(kind: str, name: str, *, parent: str = "", **attrs):
        name = _norm(name)
        if not name or len(name) < 3:
            return
        if name in found:
            found[name]["attrs"].update({k: v for k, v in attrs.items() if v is not None})
            if parent and not found[name].get("parent"):
                found[name]["parent"] = _norm(parent)
            return
        d = {"kind": kind, "name": name,
             "attrs": {k: v for k, v in attrs.items() if v is not None}}
        if parent:
            d["parent"] = _norm(parent)
        found[name] = d

    # 의도 target: 최강 신호. CIDR 제외.
    if intent_target:
        raw_t = intent_target.strip()
        if not re.search(r"/\d{1,2}\b", raw_t):
            t = raw_t.split("(")[0].strip()
            m = _IP_PORT.search(t)
            if m and _valid_ip(m.group(1)):
                add("host", m.group(1))
                add("service", f"{m.group(1)}:{m.group(2)}", parent=m.group(1),
                    port=int(m.group(2)), source="intent_target")
            elif t:
                add("service", t, source="intent_target")

    for raw in texts:
        s = str(raw or "")
        # K8s 서비스 DNS (평면 — 네임스페이스 계층 추론은 섣부르니 안 함)
        for m in _SVC_DNS.finditer(s):
            add("service", m.group(1))
        # URL → host(서비스) + path(엔드포인트, host의 자식)
        for m in _URL.finditer(s):
            host, port, path = m.group(1), m.group(2), m.group(3)
            add("service", host, port=int(port) if port else None)
            if path and path != "/" and len(path) > 1:
                add("endpoint", f"{_norm(host)}{path}", parent=host)
        # IP:port → 서비스(그 IP를 호스트 부모로)
        for m in _IP_PORT.finditer(s):
            ip, port = m.group(1), m.group(2)
            if _valid_ip(ip):
                add("host", ip)
                add("service", f"{ip}:{port}", parent=ip, port=int(port))
        # DB 접속 꼴(-h host -p port): host에 점 있을 때만. IP면 호스트 부모로.
        hm, pm = _DB_HOST.search(s), _DB_PORT.search(s)
        if hm and pm and "." in hm.group(1):
            host, port = hm.group(1), int(pm.group(1))
            looks_ip = re.fullmatch(r"\d+(?:\.\d+){3}", host) is not None
            if looks_ip and not _valid_ip(host):
                pass                          # IP 모양인데 유효하지 않음 → 노이즈, 버림
            else:
                par = host if (looks_ip and _valid_ip(host)) else ""
                if par:
                    add("host", par)
                add("service", f"{_norm(host)}:{port}", parent=par, port=port)
        # ※ 단독 IP는 자산으로 안 만든다(노이즈) — 위에서 포트·URL과 함께일 때만 호스트로 생성

    return list(found.values())


__all__ = ["extract_assets"]
