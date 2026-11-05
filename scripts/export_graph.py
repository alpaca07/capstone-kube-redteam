#!/usr/bin/env python3
"""탐색 그래프를 JSON으로 내보낸다 — 시각화 뷰어(아티팩트)에 붙여넣기용.

Neo4j에 쌓인 한 에피소드의 의도·사실·발견 노드와 관계(YIELDS·PROVES·SPAWNS·
DERIVED_FROM)를 그래프 뷰어가 읽는 JSON으로 덤프한다. neo4j 드라이버 필요(이미 설치됨).

사용(VM A):
  python3 scripts/export_graph.py --neo4j-pass 'password'                 # episode 1 → graph.json
  python3 scripts/export_graph.py --neo4j-pass 'password' --episode 3 --out ep3.json
  python3 scripts/export_graph.py --neo4j-pass 'password' --stdout        # 파일 대신 화면출력(복사용)

출력 JSON을 그래프 뷰어 아티팩트의 붙여넣기 칸에 넣으면 그래프로 그려진다.
"""
from __future__ import annotations

import argparse
import json
import sys


def main() -> int:
    ap = argparse.ArgumentParser(description="탐색 그래프 JSON 내보내기")
    ap.add_argument("--neo4j-uri", default="bolt://127.0.0.1:7687")
    ap.add_argument("--neo4j-user", default="neo4j")
    ap.add_argument("--neo4j-pass", required=True)
    ap.add_argument("--neo4j-db", default=None)
    ap.add_argument("--episode", type=int, default=1)
    ap.add_argument("--out", default="graph.json")
    ap.add_argument("--stdout", action="store_true", help="파일 대신 화면 출력")
    args = ap.parse_args()

    try:
        from neo4j import GraphDatabase
    except ImportError:
        print("neo4j 드라이버 없음 → pip install neo4j", file=sys.stderr)
        return 2

    driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_pass))
    ep = args.episode
    with driver.session(database=args.neo4j_db) as s:
        node_rows = list(s.run(
            "MATCH (n:Explore {episode:$ep}) "
            "RETURN n.id AS id, n.kind AS kind, n.state AS state, n.payload_json AS pj",
            ep=ep))
        edge_rows = list(s.run(
            "MATCH (a:Explore {episode:$ep})-[r]->(b:Explore {episode:$ep}) "
            "RETURN a.id AS src, type(r) AS rel, b.id AS dst", ep=ep))
    driver.close()

    nodes = []
    for r in node_rows:
        try:
            payload = json.loads(r["pj"]) if r["pj"] else {}
        except Exception:  # noqa: BLE001
            payload = {"_raw": r["pj"]}
        nodes.append({"id": r["id"], "kind": r["kind"],
                      "state": r["state"], "payload": payload})
    edges = [{"src": r["src"], "rel": r["rel"], "dst": r["dst"]} for r in edge_rows]

    out = {"episode": ep, "nodes": nodes, "edges": edges}
    blob = json.dumps(out, ensure_ascii=False, indent=2)

    if not nodes:
        print(f"[경고] episode {ep}에 탐색 노드가 없습니다. "
              f"--graph neo4j 로 스모크를 먼저 돌렸는지 확인하세요.", file=sys.stderr)

    if args.stdout:
        print(blob)
    else:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob)
        print(f"내보냄: {args.out}  (노드 {len(nodes)}개 · 엣지 {len(edges)}개)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
