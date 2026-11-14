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
  [가] Falco: 특권컨테이너 상승행위(mount/nsenter)→T1068 · setuid/capability 악용→T1548 (핵심층 신규 절차 관측화)
  신규 기법은 여기 매핑만 추가하면 sequencer._build_truth 가 자동으로 truth 에 넣어 탐지 채점한다.
"""
from __future__ import annotations

import json
from typing import Callable, Iterable, Optional

from common.app_signals import CROWN_CONTAINER_DEPLOY, CROWN_RESOURCE_HIJACK
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
    if rule == "Privilege escalation in container":
        return "T1068"   # [가] 권한상승 익스플로잇 — 특권 컨테이너 mount/nsenter 상승 행위(T1611 /host read 와 구분)
    if rule == "Elevation control abuse":
        return "T1548"   # [가] 권한상승 제어 악용 — setuid 호출·capability 조작(capsh/setcap)
    if rule == "Cryptocurrency mining in container":
        return "T1496"   # 사후 — Resource Hijacking(마이너 프로세스 실행)
    return None


def map_falco_crown(ev: dict) -> Optional[str]:
    """Falco 이벤트 → 사후 크라운 자산. 베이스라인엔 없는 신호라 attribution 불필요."""
    if ev.get("rule") == "Cryptocurrency mining in container":
        return CROWN_RESOURCE_HIJACK   # T1496 — 연산자원 탈취 달성
    return None


def map_audit_crown(ev: dict) -> Optional[str]:
    """감사 이벤트 → 사후 크라운 자산. 공격자 SA 의 파드 '생성 성공' = 악성 컨테이너 배포(T1610).

    베이스라인에선 admin-sa 가 파드를 생성하지 않으므로(admin-dashboard 는 Secret 만 조회)
    공격자-SA pods create = 악성 배포로 결정적. 감사 이벤트라 시간창에 묶인다(재생 검증 호환).
      - 성공(2xx)만 크라운: 방어자가 RBAC 로 생성을 막으면 거부(4xx)도 create 로 찍히므로,
        거부를 가짜 FAKE_PATCH 로 오판 않게 responseStatus 2xx 를 요구.
      - actor 는 user·impersonatedUser 양쪽: 실공격은 토큰 직접 인증(user=admin-sa),
        --as 점검은 impersonatedUser 에 들어감 — 둘 다 포착.
    """
    code = (ev.get("responseStatus") or {}).get("code") or 0
    if not 200 <= code < 300:
        return None
    actors = {(ev.get("user") or {}).get("username", ""),
              (ev.get("impersonatedUser") or {}).get("username", "")}
    resource = (ev.get("objectRef") or {}).get("resource", "")
    if _ADMIN_SA in actors and resource == "pods" and ev.get("verb") == "create":
        return CROWN_CONTAINER_DEPLOY
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

    def _scan_crowns(self, since_ts: float, until_ts: float) -> tuple[set[str], set[str]]:
        """시간창 내 사후 크라운을 통로별로 수집 → (audit 크라운, falco 크라운)."""
        audit_c: set[str] = set()
        falco_c: set[str] = set()
        for line in self.audit_reader():
            ev = _loads(line)
            if ev is None:
                continue
            ts = _audit_ts(ev)
            if ts is None or not (since_ts <= ts <= until_ts):
                continue
            c = map_audit_crown(ev)
            if c:
                audit_c.add(c)
        for line in self.falco_reader():
            ev = _loads(line)
            if ev is None:
                continue
            ts = _falco_ts(ev)
            if ts is None or not (since_ts <= ts <= until_ts):
                continue
            c = map_falco_crown(ev)
            if c:
                falco_c.add(c)
        return audit_c, falco_c

    def crowns_in_window(self, *, since_ts: float, until_ts: float) -> set[str]:
        """사후 크라운(런타임·API 통로): Falco 마이너 실행 → resource_hijack, 감사 공격자-SA
        파드 배포 → container_deploy. 둘 다 이벤트라 시간창에 묶인다(재생 검증 호환). 앱·DB
        레벨 반출(HTTP 페이로드·SQL 결과)은 사각 → AppLogSource/DbLogSource 가 담당."""
        audit_c, falco_c = self._scan_crowns(since_ts, until_ts)
        return audit_c | falco_c

    def crowns_by_channel_in_window(self, *, since_ts: float, until_ts: float) -> dict[str, set[str]]:
        """통로별 사후 크라운 맵(표시 전용) — {"audit": {...}, "falco": {...}}."""
        audit_c, falco_c = self._scan_crowns(since_ts, until_ts)
        out: dict[str, set[str]] = {}
        if audit_c:
            out["audit"] = audit_c
        if falco_c:
            out["falco"] = falco_c
        return out


__all__ = [
    "LineReader", "parse_rfc3339", "map_audit_event", "map_falco_event",
    "map_falco_crown", "map_audit_crown",
    "file_line_reader", "AuditFalcoLogSource",
]
