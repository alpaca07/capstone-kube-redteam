"""신규 취약점 주기 수집 → 2단 반영 파이프라인(개발 모드 전용, 인터넷 ON).

설계(사용자 확정): 실시간 아님, '주기 + 2단 반영 + 환경 실증 승격'.
  1단(표준 사실)  : NVD 로 받은 신규 CVE 의 CVE·CWE·CLASSIFIED_AS 를 그대로 적재(parse_nvd).
  2단(제안 지식)  : CVE 마다 LLM 이 ④⑤ env 를 저작 → authoring 게이트 통과분만 THEORETICAL 로
                    적재(build_core_layer source=llm) + CVE→기법 직접매핑(source=llm, EXPLOITED_BY).
  3단(실증 승격)  : god-view 가 학습런에서 VERIFIED 로 올림 — 여기(수집) 범위 밖(오케스트레이터).

'주기'는 워터마크(마지막 수집 시점 lastMod)로 구현: 매 실행이 그 이후 변경분만 받는다.
실험 중(인터넷 OFF)엔 돌지 않는다 — 받은 KG 는 clean-baseline 스냅샷에 얼려 통계런에 쓴다.

이음새(테스트는 네트워크·LLM 없이): NvdFeed(수집) · authoring.Author(저작) · Session(적재).
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol

from . import authoring, graph_writer, load_products, sources

NVD_WINDOW_MAX_DAYS = 120   # NVD 2.0 lastMod 질의 한 번의 최대 범위

# ─────────────────────────── 시각 유틸 ───────────────────────────
_ISO = "%Y-%m-%dT%H:%M:%S.000Z"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime(_ISO)


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def _shift_iso(iso: str, days: int) -> str:
    return (_parse_iso(iso) + timedelta(days=days)).strftime(_ISO)


def _clamp_window(since_iso: str, until_iso: str, window_days: int) -> tuple[str, bool]:
    """NVD 한 질의 범위 상한(window_days)으로 since 를 당긴다. (조정된 since, 클램프됨?)."""
    since, until = _parse_iso(since_iso), _parse_iso(until_iso)
    if until - since > timedelta(days=window_days):
        return (until - timedelta(days=window_days)).strftime(_ISO), True
    return since_iso, False


# ─────────────────────────── 워터마크 상태 ───────────────────────────
def load_state(path: str) -> dict:
    """{"last_mod": iso|None}. 없거나 깨졌으면 빈 dict(첫 실행으로 취급)."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(path: str, last_mod: str) -> None:
    """원자적 교체로 워터마크 저장(수집 성공 후에만 호출)."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"last_mod": last_mod}, f, ensure_ascii=False)
    os.replace(tmp, path)


# ─────────────────────────── 수집 이음새 ───────────────────────────
class NvdFeed(Protocol):
    """변경분(fetch_modified) 또는 지정 id(fetch_ids)의 CVE 를 NVD 모양({"vulnerabilities":[{"cve":{...}}]})으로."""
    def fetch_modified(self, since_iso: str, until_iso: str) -> dict: ...
    def fetch_ids(self, cve_ids: list[str]) -> dict: ...


class UrllibNvdFeed:
    """실전 NVD 2.0 피드 — lastModStartDate/EndDate 로 변경분을 페이지네이션 수집(개발 모드)."""

    API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, *, api_key: str | None = None, sleep: float | None = None,
                 page: int = 2000, timeout: float = 120.0, log=None) -> None:
        self.api_key = api_key or os.environ.get("NVD_API_KEY")
        # 키 없으면 5req/30s 제한 → 넉넉히(기존 __main__ 과 같은 기준)
        self.sleep = sleep if sleep is not None else (0.7 if self.api_key else 6.5)
        self.page = page
        self.timeout = timeout
        self._log = log or (lambda m: None)   # 진행 로그 이음새(CLI만 출력, 기본 조용)

    def _get(self, params: dict, *, retries: int = 6) -> dict:
        headers = {"apiKey": self.api_key} if self.api_key else {}
        url = self.API + "?" + urllib.parse.urlencode(params)
        for attempt in range(retries + 1):
            try:
                req = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as e:
                # 429(레이트리밋)·5xx(일시 장애)는 백오프 재시도. NVD 는 키 없으면 자주 503/429 를 돌려준다.
                if e.code in (429, 500, 502, 503, 504) and attempt < retries:
                    wait = int((e.headers or {}).get("Retry-After") or 0) or min(45, 8 * (attempt + 1))
                    self._log(f"[nvd] {e.code} — {wait}s 후 재시도 ({attempt + 1}/{retries})"
                              + ("" if self.api_key else " · 키 없이는 자주 막힘(NVD_API_KEY 권장)"))
                    time.sleep(wait)
                    continue
                if e.code == 404:   # NVD 는 유효하지 않거나 미활성인 apiKey 에 404 를 돌려준다
                    self._log("[nvd] 404 — apiKey 가 유효하지 않거나 미활성일 수 있음(활성화/재발급). "
                              "키 없이 돌리려면 NVD_API_KEY 해제")
                raise
            except (urllib.error.URLError, TimeoutError) as e:
                if attempt < retries:
                    wait = min(45, 8 * (attempt + 1))
                    self._log(f"[nvd] {type(e).__name__} — {wait}s 후 재시도 ({attempt + 1}/{retries})")
                    time.sleep(wait)
                    continue
                raise
        return {}

    def fetch_modified(self, since_iso: str, until_iso: str) -> dict:
        out: list = []
        start = 0
        self._log(f"[nvd] 수집 시작 {since_iso} ~ {until_iso}"
                  + ("" if self.api_key else " (키 없음 — 페이지당 대기 길다)"))
        while True:
            d = self._get({"lastModStartDate": since_iso, "lastModEndDate": until_iso,
                           "startIndex": start, "resultsPerPage": self.page})
            got = d.get("vulnerabilities", [])
            out.extend(got)
            total = d.get("totalResults", 0)
            start += d.get("resultsPerPage", 0) or len(got)
            self._log(f"[nvd] {len(out)}/{total} 수신")
            if not got or start >= total:
                break
            time.sleep(self.sleep)
        return {"vulnerabilities": out}

    def fetch_ids(self, cve_ids: list[str]) -> dict:
        """지정 CVE id 만 콕 집어 수집(cveId 질의). 창·워터마크·허용목록 무관 — 데모·강제 1건에 빠르다."""
        out: list = []
        for i, cid in enumerate(cve_ids, 1):
            self._log(f"[nvd] 타깃 {i}/{len(cve_ids)} {cid}")
            out.extend(self._get({"cveId": cid}).get("vulnerabilities", []))
            if i < len(cve_ids):
                time.sleep(self.sleep)
        return {"vulnerabilities": out}


class FakeNvdFeed:
    """테스트용 — 고정 응답(또는 (since,until)→응답 콜러블)."""

    def __init__(self, response: dict | None = None, *, fn=None) -> None:
        self.response = response or {"vulnerabilities": []}
        self.fn = fn
        self.calls: list[tuple[str, str]] = []

    def fetch_modified(self, since_iso: str, until_iso: str) -> dict:
        self.calls.append((since_iso, until_iso))
        return self.fn(since_iso, until_iso) if self.fn else self.response

    def fetch_ids(self, cve_ids: list[str]) -> dict:
        self.calls.append(("ids", tuple(cve_ids)))
        want = set(cve_ids)
        resp = self.fn(cve_ids) if callable(self.fn) else self.response
        return {"vulnerabilities": [e for e in resp.get("vulnerabilities", [])
                                    if e.get("cve", {}).get("id") in want]}


# ─────────────────────────── 허용목록 필터 ───────────────────────────
def allowlist_prefixes(path: str) -> frozenset[str]:
    """kg-cpe-allowlist.yaml → {"cpe:2.3:a:vendor:product", ...}. CVE 가 우리 제품 것인지 거르는 기준."""
    return frozenset(f"cpe:2.3:a:{p['vendor']}:{p['product']}"
                     for p in load_products.load_allowlist(path))


def cve_hits_allowlist(entry: dict, prefixes: frozenset[str]) -> bool:
    """CVE 의 영향 CPE 중 하나라도 허용목록 제품 접두로 시작하면 우리 대상(바닥층 ②가)."""
    for criteria, _vrange in sources._iter_cpe_matches(entry.get("cve", {})):
        if any(criteria.startswith(p + ":") for p in prefixes):
            return True
    return False


def cve_context(entry: dict) -> dict:
    """NVD CVE 엔트리 → 저작기 입력 맥락(설명·CWE·참조 URL)."""
    cve = entry.get("cve", {})
    cwes: list[str] = []
    for w in cve.get("weaknesses", []):
        for d in w.get("description", []):
            v = d.get("value", "")
            if v.startswith("CWE-") and v not in cwes:
                cwes.append(v)
    refs = [r.get("url", "") for r in cve.get("references", []) if r.get("url")]
    return {"cve": cve.get("id"), "description": sources._cve_description(cve),
            "cwes": cwes, "references": refs, "technique_candidates": []}


def _write_env(out_dir: str, env: dict) -> None:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{env['env']}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(env, f, ensure_ascii=False, indent=2)


# ─────────────────────────── 보고 ───────────────────────────
@dataclass
class IngestReport:
    since: str
    until: str
    clamped: bool
    fetched: int
    matched: int
    authored: int
    rejected: list[tuple[str, list[str]]] = field(default_factory=list)
    warnings: list[tuple[str, list[str]]] = field(default_factory=list)
    bottom_nodes: int = 0
    bottom_rels: int = 0
    core_nodes: int = 0
    core_rels: int = 0
    mapping_rels: int = 0
    advanced_to: str | None = None

    def summary(self) -> str:
        lines = [
            f"[ingest] 창 {self.since} ~ {self.until}" + (" (120일 상한 클램프)" if self.clamped else ""),
            f"  수집 {self.fetched} · 허용목록 매칭 {self.matched} · 저작 {self.authored} · 거절 {len(self.rejected)}",
            f"  반영 노드(바닥층 {self.bottom_nodes} · 핵심층 {self.core_nodes} · 매핑원 {self.mapping_rels}) "
            f"관계({self.bottom_rels}+{self.core_rels}+{self.mapping_rels})",
            f"  워터마크 {'진행 안 함(dry-run)' if self.advanced_to is None else '→ ' + self.advanced_to}",
        ]
        for cve, probs in self.rejected:
            extra = f" (+{len(probs) - 1})" if len(probs) > 1 else ""
            lines.append(f"  · 거절 {cve}: {probs[0]}{extra}")
        return "\n".join(lines)


# ─────────────────────────── 파이프라인 ───────────────────────────
def run_ingest(*, feed: NvdFeed, author: authoring.Author, session,
               allowlist_path: str | None = None, prefixes: frozenset[str] | None = None,
               state_path: str, out_dir: str | None = None,
               window_days: int = NVD_WINDOW_MAX_DAYS, now_iso: str | None = None,
               since_override: str | None = None, cve_ids: list[str] | None = None,
               load_cpe_nodes: bool = False,
               dry_run: bool = False, log=None) -> IngestReport:
    """한 회차 수집: 변경분 받기 → 허용목록 필터 → 1단 적재 + 2단 저작(게이트) 적재 → 워터마크 전진.

    session: graph_writer.Session(실전=neo4j / 테스트·점검=graph_writer.DryRunSession).
             적재는 항상 session 으로 흘려 Cypher·스키마 검사를 태운다. dry_run 은 '워터마크 전진'만 막는다.
    prefixes/allowlist_path: 허용목록 접두사를 직접 주거나(테스트·캐시) 경로에서 읽는다(실전). 둘 다 없으면 에러.
    """
    _log = log or (lambda m: None)   # 진행 로그 이음새(CLI만 출력, 기본 조용)
    now_iso = now_iso or _utcnow_iso()

    if cve_ids:
        # 타깃 모드: 창·워터마크·허용목록 필터 없이 지정 CVE 만 콕 집어 2단까지(데모·강제 1건).
        since, clamped = f"(타깃 CVE {len(cve_ids)}건)", False
        raw = feed.fetch_ids(cve_ids)
        entries = raw.get("vulnerabilities", [])
        matched = entries
        _log(f"[ingest] 타깃 {len(cve_ids)} → 수집 {len(entries)} · 전부 2단 저작 대상")
    else:
        if prefixes is None:
            if not allowlist_path:
                raise ValueError("prefixes 또는 allowlist_path 중 하나는 필요하다")
            prefixes = allowlist_prefixes(allowlist_path)
        state = load_state(state_path)
        raw_since = since_override or state.get("last_mod") or _shift_iso(now_iso, -window_days)
        since, clamped = _clamp_window(raw_since, now_iso, window_days)
        raw = feed.fetch_modified(since, now_iso)
        entries = raw.get("vulnerabilities", [])
        matched = [e for e in entries if cve_hits_allowlist(e, prefixes)]
        _log(f"[ingest] 수집 {len(entries)} · 허용목록 매칭 {len(matched)}"
             + (f" · 2단 저작 시작({len(matched)}건)" if matched else " · 저작할 것 없음"))

    # 1단 — 표준 사실(CVE·CWE·CLASSIFIED_AS). CPE 열거 적재는 토글(기본 off, 노이즈 차단).
    prev_cpe = sources.LOAD_NVD_CPE
    sources.LOAD_NVD_CPE = bool(load_cpe_nodes)
    try:
        bnodes, brels = sources.parse_nvd({"vulnerabilities": matched})
    finally:
        sources.LOAD_NVD_CPE = prev_cpe

    # 2단 — CVE 마다 저작 → 게이트. 통과분만 THEORETICAL env + CVE→기법(source=llm).
    envs: list[dict] = []
    mappings: list[dict] = []
    rejected: list[tuple[str, list[str]]] = []
    warnings: list[tuple[str, list[str]]] = []
    for i, e in enumerate(matched, 1):
        ctx = cve_context(e)
        _log(f"  [저작 {i}/{len(matched)}] {ctx.get('cve')} …")
        env, problems = authoring.author_env(ctx, author)
        if env is None:
            rejected.append((ctx.get("cve") or "?", problems))
            _log(f"    거절: {problems[0] if problems else '?'}")
            continue
        if problems:
            warnings.append((ctx.get("cve") or "?", problems))
        envs.append(env)
        _log(f"    통과 → THEORETICAL ({env.get('technique') or '기법없음'})")
        if env.get("technique"):
            mappings.append({"cve": ctx["cve"], "technique": env["technique"],
                             "category": "exploitation_technique", "source": "llm"})
        if out_dir:
            _write_env(out_dir, env)

    cnodes, crels = (sources.build_core_layer({"environments": envs}, source="llm",
                                              validation_level="THEORETICAL")
                     if envs else ([], []))
    mnodes, mrels = sources.parse_cve_attack({"mappings": mappings}) if mappings else ([], [])

    # 적재 — 항상 session 으로(DryRunSession 이면 집계만). 순서: 바닥층 → 핵심층 → 매핑.
    _log("[ingest] KG 반영…")
    graph_writer.merge_nodes(session, bnodes)
    graph_writer.merge_rels(session, brels)
    graph_writer.merge_nodes(session, cnodes)
    graph_writer.merge_rels(session, crels)
    graph_writer.merge_nodes(session, mnodes)
    graph_writer.merge_rels(session, mrels)

    advanced = None
    if not dry_run and not cve_ids:   # 타깃 모드는 시간 스윕이 아니라 워터마크 안 건드림
        save_state(state_path, now_iso)
        advanced = now_iso

    return IngestReport(
        since=since, until=now_iso, clamped=clamped,
        fetched=len(entries), matched=len(matched), authored=len(envs),
        rejected=rejected, warnings=warnings,
        bottom_nodes=len(bnodes), bottom_rels=len(brels),
        core_nodes=len(cnodes), core_rels=len(crels), mapping_rels=len(mrels),
        advanced_to=advanced,
    )


__all__ = [
    "NVD_WINDOW_MAX_DAYS", "NvdFeed", "UrllibNvdFeed", "FakeNvdFeed",
    "load_state", "save_state", "allowlist_prefixes", "cve_hits_allowlist",
    "cve_context", "IngestReport", "run_ingest",
]
