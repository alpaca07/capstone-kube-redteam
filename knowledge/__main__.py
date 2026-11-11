"""CLI 진입점 — 지식 그래프 ETL 적재.

  # 개발모드(인터넷 ON): 공식 소스에서 받아 Neo4j 에 적재
  python -m knowledge --sources cwe,attack,capec

  # 미리 받아둔 로컬 파일로 적재(인터넷 제한 환경) — 아래 파일명 규칙
  python -m knowledge --sources cwe,attack,capec --data-dir ./kg_data

  # 적재 없이 건수만(점검)
  python -m knowledge --sources attack,capec --data-dir ./kg_data --dry-run

적재 순서 주의: cwe -> attack -> capec (CAPEC 관계가 CWE·Technique id 참조).
Neo4j 접속: 환경변수 NEO4J_URI / NEO4J_USER / NEO4J_PASSWORD (또는 --uri/--user/--password).
로컬 파일명: enterprise-attack.json / stix-capec.json / cwec*.xml (또는 cwec*.xml.zip)
"""
from __future__ import annotations

import argparse
import csv
import glob
import io
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

from . import authoring, graph_writer, ingest, load_products, schema, sources

# 공식 소스 URL (개발모드에서 직접 받기)
URLS = {
    "attack": "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json",
    "capec":  "https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json",
    "cwe":    "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
}


def _get(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as resp:
        return resp.read()


def _cwe_root_from_zip(data: bytes) -> ET.Element:
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        name = next(n for n in z.namelist() if n.lower().endswith(".xml"))
        return ET.fromstring(z.read(name))


def fetch(source: str, data_dir: str | None):
    """소스 원본 로드. data_dir 있으면 로컬 파일, 없으면 공식 URL 다운로드."""
    if source == "nvd":
        # nvd 는 run()에서 fetch_nvd()로 처리한다(타깃 CVE/CPE 가 필요해 시그니처가 다름).
        # 여기 도달하면 run() 디스패치 버그.
        raise RuntimeError("nvd 는 fetch_nvd()로 수집한다 — fetch() 로 오면 안 됨")
    if data_dir:
        if source == "attack":
            return json.load(open(os.path.join(data_dir, "enterprise-attack.json")))
        if source == "capec":
            return json.load(open(os.path.join(data_dir, "stix-capec.json")))
        if source == "cwe":
            hits = glob.glob(os.path.join(data_dir, "cwec*.xml*"))
            if not hits:
                raise FileNotFoundError(f"{data_dir} 에 cwec*.xml(.zip) 없음")
            path = hits[0]
            if path.endswith(".zip"):
                return _cwe_root_from_zip(open(path, "rb").read())
            return ET.parse(path).getroot()
    # 다운로드
    data = _get(URLS[source])
    if source == "cwe":
        return _cwe_root_from_zip(data)
    return json.loads(data)


# --- NVD 수집 (CVE/CPE, VulHub 타깃 기준) ------------------------------------
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd_get(params: dict, *, retries: int = 6) -> dict:
    """NVD API 2.0 한 번 호출. 키 있으면 헤더로(레이트리밋 완화). 환경변수 NVD_API_KEY.
    429(레이트리밋)·일시 네트워크 오류는 백오프 재시도(429 는 Retry-After 헤더 존중)."""
    headers = {}
    key = os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    url = NVD_API + "?" + urllib.parse.urlencode(params)
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=120) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            if e.code == 429 and attempt < retries:
                wait = int((e.headers or {}).get("Retry-After") or 0) or min(45, 8 * (attempt + 1))
                print(f"  [nvd] 429 레이트리밋 — {wait}s 대기 후 재시도 ({attempt + 1}/{retries}). "
                      f"키 없으면 느림: NVD_API_KEY 발급 권장", flush=True)
                time.sleep(wait)
                continue
            raise
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt < retries:
                wait = min(45, 8 * (attempt + 1))
                print(f"  [nvd] 일시 오류 {type(e).__name__} — {wait}s 후 재시도 "
                      f"({attempt + 1}/{retries})", flush=True)
                time.sleep(wait)
                continue
            raise
    return {}   # 도달 불가(위에서 return/raise)


def _nvd_collect_cpe(cpe_match: str, sleep: float) -> list:
    """virtualMatchString 으로 한 제품에 걸린 CVE 를 페이지네이션으로 다 긁음."""
    out, start = [], 0
    while True:
        d = _nvd_get({"virtualMatchString": cpe_match, "startIndex": start, "resultsPerPage": 2000})
        got = d.get("vulnerabilities", [])
        out.extend(got)
        start += d.get("resultsPerPage", 0) or len(got)
        if not got or start >= d.get("totalResults", 0):
            break
        time.sleep(sleep)
    return out


def fetch_nvd(args) -> dict:
    """타깃(CVE id 목록 / 제품 CPE 목록)으로 NVD API 2.0 수집, 합친 응답을 돌려줌.

    타깃 출처(합쳐 씀): --nvd-cve, --nvd-cpe, 그리고 targets 파일 JSON({"cve_ids":[...], "cpe_matches":[...]}).
    미리 받아둔 덤프 <data-dir>/nvd-raw.json 이 있으면 그걸 그대로 쓴다(오프라인/재현).
    """
    if args.data_dir:
        dump = os.path.join(args.data_dir, "nvd-raw.json")
        if os.path.exists(dump):
            return json.load(open(dump))

    cve_ids = list(args.nvd_cve or [])
    cpe_matches = list(args.nvd_cpe or [])
    tgt = args.nvd_targets or (os.path.join(args.data_dir, "nvd_targets.json") if args.data_dir else "nvd_targets.json")
    if os.path.exists(tgt):
        t = json.load(open(tgt))
        cve_ids += t.get("cve_ids", [])
        cpe_matches += t.get("cpe_matches", [])
    if not cve_ids and not cpe_matches:
        raise SystemExit(
            "nvd: 타깃이 없다. VM-B 에 심은 취약점 기준으로 아래 중 하나를 줘라.\n"
            "  --nvd-cve CVE-2021-44228,CVE-...        (정확히 그 CVE만)\n"
            "  --nvd-cpe cpe:2.3:a:apache:log4j        (그 제품의 CVE 전부)\n"
            f"  또는 {tgt} 에  {{\"cve_ids\":[...], \"cpe_matches\":[...]}}  형태로 적기")

    sleep = 0.7 if os.environ.get("NVD_API_KEY") else 6.5   # 키 없으면 5req/30s 제한 → 넉넉히
    seen, vulns = set(), []
    for cid in cve_ids:
        vulns += _nvd_get({"cveId": cid}).get("vulnerabilities", [])
        time.sleep(sleep)
    for cpe in cpe_matches:
        vulns += _nvd_collect_cpe(cpe, sleep)
        time.sleep(sleep)
    # CVE 질의와 제품 질의가 겹칠 수 있으니 id 로 중복 제거
    uniq = []
    for entry in vulns:
        cid = entry.get("cve", {}).get("id")
        if cid and cid not in seen:
            seen.add(cid)
            uniq.append(entry)
    return {"vulnerabilities": uniq}


# --- CVE->ATT&CK 매핑 로드 (큐레이트 JSON + 선택적 CTID CSV) ------------------
_CTID_CSV = "Att&ckToCveMappings.csv"
_CTID_COLS = {   # CSV 컬럼 -> category
    "Primary Impact": "primary_impact",
    "Secondary Impact": "secondary_impact",
    "Exploitation Technique": "exploitation_technique",
    "Uncategorized": "uncategorized",
}


def _load_ctid_csv(path: str) -> list:
    """CTID Att&ckToCveMappings.csv -> 매핑 레코드. 셀은 'T1190; T1078' 처럼 ; 로 여러 개."""
    out = []
    with open(path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            cve = (row.get("CVE ID") or "").strip()
            if not cve:
                continue
            for col, cat in _CTID_COLS.items():
                for t in (row.get(col) or "").split(";"):
                    t = t.strip()
                    if t:
                        out.append({"cve": cve, "technique": t, "category": cat, "source": "ctid"})
    return out


def _load_curated(path: str) -> list:
    """큐레이트 JSON({"mappings":[{"cve":..,"techniques":[..]|"technique":..,"category":..}]}) -> 레코드."""
    data = json.load(open(path))
    out = []
    for m in data.get("mappings", []):
        cve = m.get("cve")
        cat = m.get("category", "")
        techs = m.get("techniques") or ([m["technique"]] if m.get("technique") else [])
        for t in techs:
            out.append({"cve": cve, "technique": t, "category": cat, "source": m.get("source", "curated")})
    return out


def _load_kev(path: str) -> list:
    """CTID KEV->ATT&CK JSON(mapping_objects[]) -> 레코드. 실제 악용 CVE(CISA KEV) + 최신 ATT&CK."""
    data = json.load(open(path))
    out = []
    for o in data.get("mapping_objects", []):
        cve = (o.get("capability_id") or "").strip()
        tech = (o.get("attack_object_id") or "").strip()
        if cve.upper().startswith("CVE-") and tech.upper().startswith("T"):
            out.append({"cve": cve, "technique": tech,
                        "category": o.get("mapping_type", ""), "source": "kev"})
    return out


def _newest_kev(data_dir: str) -> str | None:
    """data-dir 아래에서 KEV enterprise 매핑 JSON 중 날짜(파일명 MM.DD.YYYY) 최신 하나 고름."""
    hits = [h for h in glob.glob(os.path.join(data_dir, "**", "*attack-*-enterprise.json"), recursive=True)
            if "kev" in os.path.basename(h).lower()]
    if not hits:
        return None

    def key(p):
        m = re.search(r"kev-(\d{2})\.(\d{2})\.(\d{4})", os.path.basename(p))
        return (m.group(3), m.group(1), m.group(2)) if m else ("0000", "00", "00")

    return max(hits, key=key)


def fetch_cve_attack(args) -> dict:
    """CVE->ATT&CK 매핑을 모아 {"mappings":[...]}. 우선순위대로 있으면 합쳐 씀:
       KEV(--kev-json 또는 data-dir 자동탐색, 최신·권장) + 큐레이트 JSON(--cve-map) + CTID 2021 CSV(data-dir)."""
    mappings = []
    # KEV (최신 실악용 CVE 매핑)
    kev = args.kev_json or (_newest_kev(args.data_dir) if args.data_dir else None)
    if kev and os.path.exists(kev):
        mappings += _load_kev(kev)
    # 큐레이트
    cmap = args.cve_map or (os.path.join(args.data_dir, "cve_attack.json") if args.data_dir else None)
    if cmap and os.path.exists(cmap):
        mappings += _load_curated(cmap)
    # CTID 2021 CSV (레거시 베이스라인)
    if args.data_dir:
        csv_path = os.path.join(args.data_dir, _CTID_CSV)
        if os.path.exists(csv_path):
            mappings += _load_ctid_csv(csv_path)
    if not mappings:
        raise SystemExit(
            "cve_attack: 매핑이 없다. 아래 중 하나를 줘라.\n"
            "  --kev-json <KEV JSON>                 (CTID KEV->ATT&CK, 최신·권장)\n"
            "  --cve-map ./kg_data/cve_attack.json   (큐레이트)\n"
            f"  또는 data-dir 아래에 KEV JSON / {_CTID_CSV} 두기(자동 탐색)")
    return {"mappings": mappings}


# --- 바닥층 CPE allowlist 로드 (자산 카탈로그) --------------------------------
# Product/allowlist 는 knowledge.load_products 가 정본(Product·ServiceType·IDENTIFIED_BY, kg-cpe-allowlist.yaml).
# nvd 입력(cpe_matches)은 load_products.emit_nvd_targets, CPE 필터는 --nvd-cpe-filter(아래) 로 그 allowlist 를 공유.


# --- 핵심층 환경 로드 (④⑤ 수기 저작) ----------------------------------------
def fetch_core(args) -> dict:
    """핵심층 환경 JSON 로드. --core <파일|디렉토리>, 없으면 패키지 knowledge/core_layer/ 전체(*.json)."""
    target = args.core or os.path.join(os.path.dirname(__file__), "core_layer")
    if os.path.isdir(target):
        files = sorted(glob.glob(os.path.join(target, "*.json")))
    elif os.path.exists(target):
        files = [target]
    else:
        raise SystemExit(f"core: {target} 없음 (--core 로 파일/디렉토리 지정)")
    envs = []
    for f in files:
        d = json.load(open(f))
        if d.get("environments"):
            envs += d["environments"]
        elif d.get("env"):
            envs.append(d)
    return {"environments": envs}


def connect(args):
    """Neo4j 세션. neo4j 드라이버는 여기서만 import(없어도 dry-run 됨)."""
    from neo4j import GraphDatabase
    uri = args.uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = args.user or os.environ.get("NEO4J_USER", "neo4j")
    pw = args.password or os.environ.get("NEO4J_PASSWORD")
    if not pw:
        raise SystemExit("NEO4J_PASSWORD (또는 --password) 필요")
    driver = GraphDatabase.driver(uri, auth=(user, pw))
    return driver.session()


def _build_author(args) -> authoring.Author:
    """ingest 2단 저작용 LLM 저작기(DGX 모델). 주소·모델은 인자나 환경변수로."""
    url = args.llm_url or os.environ.get("OLLAMA_BASE_URL")
    model = args.llm_model or os.environ.get("OLLAMA_MODEL")
    if not url or not model:
        raise SystemExit(
            "ingest 2단 저작에 DGX 모델이 필요하다. 아래 중 하나로 줘라.\n"
            "  --llm-url http://<DGX>:11434/v1  --llm-model <model>\n"
            "  또는 환경변수 OLLAMA_BASE_URL / OLLAMA_MODEL")
    from common.llm_client import OllamaClient
    return authoring.LlmAuthor(OllamaClient(url, model,
                                            max_tokens=args.llm_max_tokens or None))


def _run_ingest(args) -> None:
    """주기 수집 1회(개발 모드, 인터넷 ON): 변경분 → 허용목록 필터 → 1단 적재 + 2단 저작 적재."""
    feed = ingest.UrllibNvdFeed()
    author = _build_author(args)
    session = graph_writer.DryRunSession() if args.dry_run else connect(args)
    allowlist = args.nvd_cpe_filter or load_products._DEFAULT_ALLOWLIST
    report = ingest.run_ingest(
        feed=feed, author=author, session=session,
        allowlist_path=allowlist, state_path=args.state, out_dir=args.out_dir,
        window_days=args.window_days, since_override=args.since,
        load_cpe_nodes=args.nvd_cpe_nodes, dry_run=args.dry_run)
    print(report.summary())


def run(args) -> None:
    if args.bootstrap:
        session = connect(args)
        stmts = schema.constraint_statements()
        for st in stmts:
            session.run(st)
        print(f"[bootstrap] 제약조건·색인 {len(stmts)}개 적용 완료 (적재 전에 한 번만)")
        return
    if args.ingest:
        _run_ingest(args)
        return
    source_list = [s.strip() for s in args.sources.split(",") if s.strip()]
    sources.LOAD_NVD_CPE = bool(args.nvd_cpe_nodes)   # NVD CPE 열거 적재 여부(기본 False)
    if args.nvd_cpe_filter and args.nvd_cpe_nodes:   # 바닥층: CPE 노드를 allowlist 제품만으로 제한(노이즈·메모리 차단)
        sources.CPE_FILTER = frozenset(
            f"cpe:2.3:a:{p['vendor']}:{p['product']}"
            for p in load_products.load_allowlist(args.nvd_cpe_filter))
    session = graph_writer.DryRunSession() if args.dry_run else connect(args)
    for source in source_list:
        if source not in sources.PARSERS:
            raise SystemExit(f"unknown source: {source} (쓸 수 있는 것: {list(sources.PARSERS)})")
        if source == "nvd":
            raw = fetch_nvd(args)
        elif source == "cve_attack":
            raw = fetch_cve_attack(args)
        elif source == "core":
            raw = fetch_core(args)
        else:
            raw = fetch(source, args.data_dir)
        nodes, rels = sources.PARSERS[source](raw)
        n = graph_writer.merge_nodes(session, nodes)
        r = graph_writer.merge_rels(session, rels)
        print(f"[{source}] nodes={n} rels={r}")
    if args.dry_run:
        print("(dry-run: 실제 적재 안 함)")


def main() -> None:
    ap = argparse.ArgumentParser(prog="knowledge", description="지식 그래프 ETL 적재")
    ap.add_argument("--sources", default="cwe,attack,capec",
                    help="적재 소스 쉼표구분 (cwe,attack,capec,nvd,cve_attack). 순서 cwe->attack->capec, nvd/cve_attack 은 그 뒤")
    ap.add_argument("--data-dir", default=None, help="로컬 원본 파일 디렉토리(없으면 공식 URL 다운로드)")
    ap.add_argument("--dry-run", action="store_true", help="적재 없이 건수만")
    ap.add_argument("--bootstrap", action="store_true", help="라벨 id 유일성 제약·색인만 적용하고 종료(적재 전 1회)")
    ap.add_argument("--uri", default=None); ap.add_argument("--user", default=None)
    ap.add_argument("--password", default=None)
    # nvd 타깃(VM-B 에 심은 취약점 기준) — 쉼표구분. targets 파일로도 줄 수 있음.
    _csv = lambda s: [x.strip() for x in s.split(",") if x.strip()]
    ap.add_argument("--nvd-cve", default=[], type=_csv, help="NVD 타깃 CVE id (예: CVE-2021-44228,CVE-2021-45046)")
    ap.add_argument("--nvd-cpe", default=[], type=_csv, help="NVD 타깃 제품 CPE/virtualMatchString (예: cpe:2.3:a:apache:log4j)")
    ap.add_argument("--nvd-targets", default=None, help="타깃 JSON 파일 경로({\"cve_ids\":[...],\"cpe_matches\":[...]})")
    ap.add_argument("--nvd-cpe-nodes", action="store_true", help="NVD CPE 열거도 적재(기본 꺼짐 — 벤더 제품 노이즈 차단). 바닥층 Product↔CVE 조인(load_products --link)하려면 켜야 함")
    ap.add_argument("--nvd-cpe-filter", metavar="YAML", default=None, help="바닥층 — 이 allowlist(kg-cpe-allowlist.yaml) 제품 CPE 만 노드 생성(열거 노이즈·메모리 차단). --nvd-cpe-nodes 와 함께.")
    ap.add_argument("--core", default=None, help="핵심층 환경 JSON 파일/디렉토리(core 소스, 기본=knowledge/core_layer/)")
    ap.add_argument("--cve-map", default=None, help="CVE->ATT&CK 큐레이트 매핑 JSON 경로(cve_attack 소스)")
    ap.add_argument("--kev-json", default=None, help="CTID KEV->ATT&CK 매핑 JSON 경로(없으면 data-dir 에서 최신 자동탐색)")
    # --- 신규 취약점 주기 수집(2단 반영) ---
    ap.add_argument("--ingest", action="store_true",
                    help="신규 CVE 주기 수집 → 1단(표준) 적재 + 2단(LLM 저작, THEORETICAL) 적재. 개발 모드(인터넷 ON)")
    ap.add_argument("--since", default=None, help="수집 시작 시점 override(ISO, 예 2026-11-01T00:00:00.000Z). 없으면 워터마크")
    ap.add_argument("--state", default="runs/kg-ingest-state.json", help="워터마크 상태 파일(마지막 수집 시점)")
    ap.add_argument("--out-dir", default="runs/core_layer_auto", help="자동 저작 env JSON 보관 디렉토리(감사·재현용). 빈값이면 미보관")
    ap.add_argument("--window-days", type=int, default=ingest.NVD_WINDOW_MAX_DAYS, help="NVD 한 질의 최대 범위(일, ≤120)")
    ap.add_argument("--llm-url", default=None, help="저작 LLM base_url(예 http://<DGX>:11434/v1). 없으면 OLLAMA_BASE_URL")
    ap.add_argument("--llm-model", default=None, help="저작 LLM 모델명. 없으면 OLLAMA_MODEL")
    ap.add_argument("--llm-max-tokens", type=int, default=2048, help="저작 호출 토큰 상한")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
