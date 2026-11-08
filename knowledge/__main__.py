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
                    help="적재 소스 쉼표구분 (cwe,attack,capec,nvd). 순서 cwe->attack->capec 권장")
    ap.add_argument("--data-dir", default=None, help="로컬 원본 파일 디렉토리(없으면 공식 URL 다운로드)")
    ap.add_argument("--dry-run", action="store_true", help="적재 없이 건수만")
    ap.add_argument("--uri", default=None); ap.add_argument("--user", default=None)
    ap.add_argument("--password", default=None)
    run(ap.parse_args())


if __name__ == "__main__":
    main()
