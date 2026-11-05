"""앱 레벨 웹 공격 신호 — 서비스 JSON 감사 로그의 요청을 웹 공격 기법으로 분류.

VM C(god-view, orchestrator.app_log_source)와 VM D(방어자, defender.filter)가 공유한다.
같은 기법 키를 써야 truth(심판)와 방어자 보고가 탐지 채점(TP/FP)에서 맞물린다. k3s 감사로그·
Falco 는 앱 레벨(HTTP 페이로드)을 못 보므로, 취약 서비스가 민감 요청마다 JSON 한 줄을 찍고
여기서 페이로드 악성 여부로 분류한다. 탐지는 '시도' 기준(차단 성사 여부는 verdict).

기법 키는 점(.) 없는 고유 토큰(scorer._base 가 서로 안 접음 → 분리 측정). 괄호 안이 실제 MITRE.
  Tier A: WEB_SQLI·WEB_SSRF·WEB_CMDI·WEB_CREDLEAK
  Tier B: WEB_BOLA(영수증 IDOR)·WEB_MASSASSIGN(권한 필드 대량할당)·WEB_AUTHN(alg:none 위조 토큰)
"""
from __future__ import annotations

import ipaddress
import re
from typing import Optional
from urllib.parse import unquote_plus, urlparse

WEB_SQLI = "WEB_SQLI"              # T1190 (Exploit Public-Facing Application)
WEB_SSRF = "WEB_SSRF"              # T1190
WEB_CMDI = "WEB_CMDI"             # T1059 / T1190
WEB_CREDLEAK = "WEB_CREDLEAK"     # T1552.001
WEB_BOLA = "WEB_BOLA"             # T1190 / T1213 (Broken Object Level Authorization / IDOR)
WEB_MASSASSIGN = "WEB_MASSASSIGN"  # T1190 (Mass Assignment → 권한상승)
WEB_AUTHN = "WEB_AUTHN"           # T1078 (Valid Accounts — 위조 토큰 수용)
WEB_TECHNIQUES = (WEB_SQLI, WEB_SSRF, WEB_CMDI, WEB_CREDLEAK,
                  WEB_BOLA, WEB_MASSASSIGN, WEB_AUTHN)

_SQLI = re.compile(
    r"(?i)(union\s+select|\bor\s+1\s*=\s*1\b|--|/\*|'\s*or\b|'\s*union\b"
    r"|;\s*(drop|select|insert|update|delete)\b)")
_CMD_META = re.compile(r"[;&|`]|\$\(")
_PRIV_FIELDS = ("role", "tier", "is_admin", "isadmin", "admin")   # mass-assign 권한 필드


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


def classify(path: str, query: str = "", url: Optional[str] = None, *,
             fields: Optional[str] = None, authn: Optional[str] = None) -> Optional[str]:
    """요청 → 웹 공격 기법. 악성일 때만(정상 요청 None). query 는 URL 인코딩 그대로.
    fields: 요청 본문의 필드명 목록(mass-assign 판정). authn: 인증 이상 표식(alg:none 등)."""
    q = unquote_plus(query or "")
    # ── Tier A ──
    if path == "/api/products" and q:
        return WEB_SQLI if _SQLI.search(q) else None
    if path == "/api/products/preview":
        return WEB_SSRF if (url and is_internal_or_file(url)) else None
    if path == "/admin/diag":
        return WEB_CMDI if _CMD_META.search(q) else None
    if path == "/debug/config":
        return WEB_CREDLEAK
    # ── Tier B ──
    if path.startswith("/api/invoice/"):
        return WEB_BOLA                        # 인증 없는 영수증 열람/열거(IDOR) — 정상 호출자 없음
    if path == "/api/account/update":
        f = (fields or "").lower()
        return WEB_MASSASSIGN if any(k in f for k in _PRIV_FIELDS) else None
    if path == "/api/me" and (authn or "").lower() in ("none", "none_alg", "unsigned"):
        return WEB_AUTHN                        # 서명 없는(alg:none) 위조 토큰 수용 = 인증 우회
    return None


def map_app_event(ev: dict) -> Optional[str]:
    """JSON 감사 로그 1줄(dict) → 기법. god-view AppLogSource 용(src!=app 이면 None)."""
    if ev.get("src") != "app":
        return None
    if ev.get("event"):   # crown_exfil 등 '요청 로그'가 아닌 자백 줄은 기법 분류 대상 아님
        return None
    return classify(ev.get("path", ""), ev.get("query", "") or "", ev.get("url"),
                    fields=ev.get("fields"), authn=ev.get("authn"))


# ───────────── 크라운 반출 자백(플래그리스 최종 침해 판정) ─────────────
# 취약 서비스가 민감 데이터를 실제로 읽어 응답에 실을 때 찍는 자백 줄의 target 키.
# 기법(web_*)과 '별개 축' — 기법=시도, 크라운=실제 침해 달성.
CROWN_INTERNAL_SECRETS = "internal_secrets"   # ④ 목표물(과거 값기반 FLAG 자리)
CROWN_CUSTOMERS_PII = "customers_pii"          # 고객 PII(이름·이메일·전화·주소·주민번호)
CROWN_TARGETS = (CROWN_INTERNAL_SECRETS, CROWN_CUSTOMERS_PII)


def crown_target(ev: dict) -> Optional[str]:
    """crown_exfil 자백 줄 → 반출된 크라운 자산 키. 자백 줄이 아니면 None.

    심판(god-view)이 '값 대조'가 아니라 '접근 흔적'으로 최종 침해를 판정하는 통로(app 계층).
    """
    if ev.get("src") == "app" and ev.get("event") == "crown_exfil":
        t = ev.get("target")
        if isinstance(t, str) and t in CROWN_TARGETS:
            return t
    return None


_PII_COLS = ("ssn", "email", "phone", "address")


def crown_of_sql(sql: str) -> Optional[str]:
    """실행된 SQL 문자열 → 반출된 크라운 자산 키. DB 접근기록(postgres statement 로그)용.

    공격자가 직접 DB 에 접속(③ NetworkPolicy 부재)해 민감 테이블을 조회하는 경로를 잡는다 —
    앱을 안 거쳐 app 자백 줄이 안 남는 메인 킬체인 ④ 의 주 경로. postgres 로그엔 결과 행수가
    없으므로 '민감 테이블을 조회하는 SELECT 를 실행했다'를 접근 흔적으로 본다(app 통로의
    _crown_of 는 cur.rowcount 까지 보지만 여기선 쿼리 패턴만). 정상 앱 쿼리(이름만 조인 등)는
    PII 컬럼이 없어 None.
    """
    q = (sql or "").lower()
    if "select" not in q:                   # 반출은 조회 계열만(UPDATE/INSERT 제외)
        return None
    if "internal_secrets" in q:             # 정상 앱은 이 테이블 미접근 → 조회=④ 반출
        return CROWN_INTERNAL_SECRETS
    if "customers" in q and ("*" in q or any(c in q for c in _PII_COLS)):
        return CROWN_CUSTOMERS_PII          # 고객 PII 조회(SELECT * 또는 민감 컬럼)
    return None


__all__ = [
    "WEB_SQLI", "WEB_SSRF", "WEB_CMDI", "WEB_CREDLEAK",
    "WEB_BOLA", "WEB_MASSASSIGN", "WEB_AUTHN", "WEB_TECHNIQUES",
    "is_internal_or_file", "classify", "map_app_event",
    "CROWN_INTERNAL_SECRETS", "CROWN_CUSTOMERS_PII", "CROWN_TARGETS",
    "crown_target", "crown_of_sql",
]
