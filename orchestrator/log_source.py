"""실 어댑터 — k3s 감사로그 + Falco 로그를 god-view로 읽어 MITRE 기법을 뽑는 LogSource.

Protocol(logs.py) 뒤에 끼우는 실제 층. 설계 핵심: '로그 줄 → 기법 매핑'의 순수 로직과
'파일 읽기 I/O'를 분리한다. line reader(주입 가능)만 교체하면 샘플 로그로 매핑을 테스트할
수 있고, 실전에선 파일에서 읽는다. VM C는 공격받는 VM B를 안 거치고 로그를 직접 읽는다
(위조·누락 방지). 탐지는 의도적으로 불완전 — 여기 매핑되는 기법만 '관측 가능'(나머지는 사각).

관측 매핑(환경 구축 observability 문서와 일치):
  ② 감사로그: admin-sa 가 secret get/list → T1078 (가장 선명)
  Falco:      컨테이너 셸 → T1059 / 발판→DB connect → T1210(③) / 발판 wget·curl → T1552.001(①)
  [Wave1] 감사: admin-sa configmaps→T1552.001 · pods create→T1610 · namespaces→T1613 ·
               selfsubject*review→T1069   Falco: 호스트 /host read→T1611 · 포트스캐너→T1046
  신규 기법은 여기 매핑만 추가하면 sequencer._build_truth 가 자동으로 truth 에 넣어 탐지 채점한다.
"""
from __future__ import annotations

import json
from typing import Callable, Iterable, Optional

from common.k8s_logs import audit_ts as _audit_ts, falco_ts as _falco_ts, parse_rfc3339

# 로그 줄(JSON)을 순서대로 내놓는 콜백. 호출마다 새로 순회 가능해야 함.
LineReader = Callable[[], Iterable[str]]

_ADMIN_SA = "system:serviceaccount:internal:admin-sa"
_FOOTHOLD_SA = "system:serviceaccount:frontend:foothold-sa"
_ATTACKER_SAS = {_ADMIN_SA, _FOOTHOLD_SA}     # 공격자가 쥐는 SA(정상 트래픽과 구분)
_SECRET_VERBS = {"get", "list", "watch"}
_SELF_REVIEWS = {"selfsubjectaccessreviews", "selfsubjectrulesreviews"}  # auth can-i


# ───────────── 순수 매핑 (시간 파싱은 common.k8s_logs 공유) ─────────────
def map_audit_event(ev: dict) -> Optional[str]:
    """k3s 감사 이벤트 → MITRE 기법.

    ②(admin-sa secret 접근, T1078) 외 Wave1 확장 — 모두 '정상 트래픽엔 없는' 공격자 전용 신호
    (admin-dashboard 는 Secret 엔드포인트와 코드 볼륨마운트만 쓰지 configmap/pods/namespaces 를
     API 로 조회·생성하지 않는다):
      - admin-sa  configmaps get/list   → T1552.001 (평문 크레덴셜 ConfigMap 조회 = 다경로)
      - admin-sa  pods create           → T1610     (탈취 토큰으로 악성 파드 배포)
      - admin-sa  namespaces list/watch → T1613     (탈취 토큰으로 리소스/네임스페이스 열거)
      - 공격자 SA selfsubject*review create → T1069  (auth can-i 권한 열거)
    """
    user = (ev.get("user") or {}).get("username", "")
    verb = ev.get("verb", "")
    resource = (ev.get("objectRef") or {}).get("resource", "")
    if user == _ADMIN_SA:
        if resource == "secrets" and verb in _SECRET_VERBS:
            return "T1078"        # ② 과권한 SA — Secret 조회
        if resource == "configmaps" and verb in _SECRET_VERBS:
            return "T1552.001"    # 다경로 크레덴셜 — 평문 ConfigMap(legacy-db-config)
        if resource == "pods" and verb == "create":
            return "T1610"        # Deploy Container — 악성 파드 배포
        if resource == "namespaces" and verb in {"list", "watch"}:
            return "T1613"        # Container/Resource Discovery — 네임스페이스 열거
    if user in _ATTACKER_SAS and resource in _SELF_REVIEWS and verb == "create":
        return "T1069"            # Permission Groups Discovery — auth can-i
    return None


def map_falco_event(ev: dict) -> Optional[str]:
    """Falco 이벤트 → MITRE 기법. rule 이름 = falco-values customRules 와 1:1."""
    rule = ev.get("rule", "")
    if rule == "Terminal shell in container":
        return "T1059"   # 명령/스크립트 실행(발판 exec — 킬체인 ①②③④ 단계는 아님)
    if rule == "Lateral movement to database":
        return "T1210"   # ③ 측면이동 — frontend 발판 → postgres:5432 성공 연결
    if rule == "Credential access from foothold":
        return "T1552.001"   # ① 크레덴셜 수집 — 발판에서 wget/curl(wiki 단서·SSRF 페치)
    if rule == "Escape to host filesystem":
        return "T1611"   # [Wave1] 컨테이너 탈출 — /host 민감파일 read
    if rule == "Port scan from foothold":
        return "T1046"   # [Wave1] 네트워크 서비스 탐색 — 포트 스캐너 기동
    return None


def _loads(line: str) -> Optional[dict]:
    try:
        obj = json.loads(line)
        return obj if isinstance(obj, dict) else None
    except (json.JSONDecodeError, ValueError):
        return None


# ───────────── reader ─────────────
def file_line_reader(path: str) -> LineReader:
    """파일에서 줄 단위로 읽는 기본 reader. 파일 없으면 빈 순회."""
    def _r() -> Iterable[str]:
        try:
            with open(path, encoding="utf-8") as f:
                for line in f:
                    yield line
        except FileNotFoundError:
            return
    return _r


class AuditFalcoLogSource:
    """감사 + Falco 로그를 god-view로 조회. 시간창 내 관측 기법 집합을 반환."""

    def __init__(self, audit_reader: LineReader, falco_reader: LineReader) -> None:
        self.audit_reader = audit_reader
        self.falco_reader = falco_reader

    def techniques_in_window(self, *, since_ts: float, until_ts: float) -> set[str]:
        out: set[str] = set()
        for line in self.audit_reader():
            ev = _loads(line)
            if ev is None:
                continue
            ts = _audit_ts(ev)
            if ts is None or not (since_ts <= ts <= until_ts):
                continue
            t = map_audit_event(ev)
            if t:
                out.add(t)
        for line in self.falco_reader():
            ev = _loads(line)
            if ev is None:
                continue
            ts = _falco_ts(ev)
            if ts is None or not (since_ts <= ts <= until_ts):
                continue
            t = map_falco_event(ev)
            if t:
                out.add(t)
        return out


__all__ = [
    "LineReader", "parse_rfc3339", "map_audit_event", "map_falco_event",
    "file_line_reader", "AuditFalcoLogSource",
]
