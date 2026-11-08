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
import glob
import io
import json
import os
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

from . import graph_writer, sources

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
        raise NotImplementedError("nvd: VulHub 타깃 CPE 확정 후 구현")
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


def _nvd_get(params: dict) -> dict:
    """NVD API 2.0 한 번 호출. 키 있으면 헤더로(레이트리밋 완화). 환경변수 NVD_API_KEY."""
    headers = {}
    key = os.environ.get("NVD_API_KEY")
    if key:
        headers["apiKey"] = key
    url = NVD_API + "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=120) as resp:
        return json.loads(resp.read())


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


def run(args) -> None:
    source_list = [s.strip() for s in args.sources.split(",") if s.strip()]
    session = graph_writer.DryRunSession() if args.dry_run else connect(args)
    for source in source_list:
        if source not in sources.PARSERS:
            raise SystemExit(f"unknown source: {source} (쓸 수 있는 것: {list(sources.PARSERS)})")
        raw = fetch_nvd(args) if source == "nvd" else fetch(source, args.data_dir)
        nodes, rels = sources.PARSERS[source](raw)
        n = graph_writer.merge_nodes(session, nodes)
        r = graph_writer.merge_rels(session, rels)
        print(f"[{source}] nodes={n} rels={r}")
    if args.dry_run:
        print("(dry-run: 실제 적재 안 함)")


def main() -> None:
    ap = argparse.ArgumentParser(prog="knowledge", description="지식 그래프 ETL 적재")
    ap.add_argument("--sources", default="cwe,attack,capec",
                    help="적재 소스 쉼표구분 (cwe,attack,capec,nvd). 순서 cwe->attack->capec 권장")
    ap.add_argument("--data-dir", default=None, help="로컬 원본 파일 디렉토리(없으면 공식 URL 다운로드)")
    ap.add_argument("--dry-run", action="store_true", help="적재 없이 건수만")
    ap.add_argument("--uri", default=None); ap.add_argument("--user", default=None)
    ap.add_argument("--password", default=None)
    # nvd 타깃(VM-B 에 심은 취약점 기준) — 쉼표구분. targets 파일로도 줄 수 있음.
    _csv = lambda s: [x.strip() for x in s.split(",") if x.strip()]
    ap.add_argument("--nvd-cve", default=[], type=_csv, help="NVD 타깃 CVE id (예: CVE-2021-44228,CVE-2021-45046)")
    ap.add_argument("--nvd-cpe", default=[], type=_csv, help="NVD 타깃 제품 CPE/virtualMatchString (예: cpe:2.3:a:apache:log4j)")
    ap.add_argument("--nvd-targets", default=None, help="타깃 JSON 파일 경로({\"cve_ids\":[...],\"cpe_matches\":[...]})")
    run(ap.parse_args())


if __name__ == "__main__":
    main()
