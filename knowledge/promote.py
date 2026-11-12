"""off-KG 포획 저널 → 핵심층 승급(god-view 실증) — 2단 반영의 3단.

팀원 수집 파이프라인(knowledge.ingest/authoring)이 남긴 설계상 공백을 메운다:
  1단 표준사실(NVD) · 2단 LLM 저작(THEORETICAL) 은 ingest 담당,
  3단 '환경 실증 승급' 은 공수 루프(god-view) 몫 — 여기(promote)가 그것.

공수 루프(VM C)가 off_kg.jsonl 에 남긴 'KG에 없는 기법으로 달성한 침해'를,
authoring.validate_env(2단과 같은 형식 게이트)에 통과시킨 뒤 핵심층 env(④⑤)로 KG에 반영한다.
  - 출처 = coevolution(KS-coevolution-loop) : LLM 제안(llm)과 구분되는 '실증' 출처
  - 신뢰수준(validation_level) : 크라운 → VERIFIED / 진행도 → OBSERVED (god-view 가 작동을 확인)

  # 승급 후보 생성(검토용 JSON + 요약) — Neo4j 불필요
  python3 -m knowledge.promote --journal orchestrator/logs/off_kg.jsonl

  # 검토 후 적재(개발기, Neo4j) — 신뢰수준별로 build_core_layer(source=coevolution)
  python3 -m knowledge.promote --journal orchestrator/logs/off_kg.jsonl --load
  # 또는 검토·수정한 파일에서:
  python3 -m knowledge.promote --from knowledge/learned/<run>.json --load

주의: 적재는 반드시 이 명령(--load)으로. `--sources core` 로 넣으면 출처가 core 로 잘못 붙는다
(출처·신뢰수준은 build_core_layer 인자라 JSON 에 안 실림).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import time

from common.app_signals import CROWN_TARGETS
from common.off_kg import read_journal

from . import authoring, graph_writer, sources

# 결과 등급(심판 관측 우선).
_RANK = {"CROWN": 3, "PROGRESS": 2, "UNCONFIRMED": 1, "FAILED": 0}
# 결과 → 신뢰수준(god-view 사다리): 크라운=실증 완료 / 진행도=기법 관측(부분).
_LEVEL = {"CROWN": "VERIFIED", "PROGRESS": "OBSERVED"}
_TID = re.compile(r"^T\d{4}(\.\d{3})?$")
_AO_PROGRESS = {"id": "AO-command-execution", "name": "명령 실행"}
_AO_CROWN = {"id": "AO-data-exposure", "name": "민감 데이터 유출"}


def _val(outcome) -> str:
    return getattr(outcome, "value", outcome)


def _rank(outcome) -> int:
    return _RANK.get(_val(outcome), 0)


def _slug(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-") or "x"


def _product(cpe: str) -> str:
    parts = (cpe or "").split(":")
    return parts[4] if len(parts) > 4 and parts[4] else (cpe or "")


def gate_and_dedup(records, *, min_rank: int = 2, include_unconfirmed: bool = False):
    """등급 게이트 + (기법, 자산) 중복 제거(최고 등급 1건). 기본=PROGRESS 이상(god-view 확인)."""
    best: dict[tuple, object] = {}
    for r in records:
        rk = _rank(r.outcome)
        if not (rk >= min_rank or (include_unconfirmed and rk >= 1)):
            continue
        key = (r.hint.technique_id or "", r.target.cpe or r.target.endpoint or "")
        if key not in best or _rank(best[key].outcome) < rk:
            best[key] = r
    return list(best.values())


def record_to_env(rec) -> dict:
    """off-KG 레코드 → 핵심층 env(authoring.validate_env 통과 형식).

    진행도 ER = falco/technique/<기법> (유효 기법 있을 때).
    크라운 ER = crown/asset/in [크라운 상수] (특정 자산 미상이라 둘 다 허용).
    """
    raw_tech = (rec.hint.technique_id or "").strip()
    tech = raw_tech if _TID.match(raw_tech) else ""     # 유효 기법만(아니면 생략 → 경고, 에러 아님)
    base = _product(rec.target.cpe) if rec.target.cpe else (rec.target.endpoint or "target")
    slug = f"learned-{_slug(tech or 'na')}-{_slug(base)}"
    crown = rec.godview.crown
    level = _LEVEL.get(_val(rec.outcome), "OBSERVED")
    steps = "; ".join((s.tool + " " + " ".join(s.args)).strip()
                      for s in rec.procedure.steps[:4])

    env: dict = {
        "_note": (f"off-KG 포획 승급 — run {rec.id.run_id} ep{rec.id.episode} r{rec.id.round} "
                  f"finding#{rec.id.intent_id}. 출처=coevolution 수준={level}. 검토 권장."),
        "_validation": level,                            # 적재 시 신뢰수준(load_envs 가 묶는 키). 게이트는 무시
        "env": slug,
        "procedure": {
            "id": f"PROC-{slug}",
            "name": (rec.trigger.reason[:80] or f"off-KG {tech or 'unknown'}"),
            "description": steps or rec.attacker_claim.claimed_outcome or "off-KG 포획 절차",
            "status": level,
        },
        "preconditions": [],
        "expected_results": [],
    }
    if tech:
        env["technique"] = tech
    for i, pre in enumerate(rec.target.preconditions):
        env["preconditions"].append(
            {"id": f"PRE-{slug}-{i}", "name": pre[:60], "description": pre})
    if tech:                                             # 진행도(god-view 가 기법 관측)
        env["expected_results"].append({
            "id": f"ER-{slug}-progress", "kind": "progress", "outcome": _AO_PROGRESS,
            "conditions": [{"channel": "falco", "field": "technique",
                            "operator": "eq", "expected": tech}]})
    if crown:                                            # 크라운(민감 자산 실제 침해)
        env["expected_results"].append({
            "id": f"ER-{slug}-crown", "kind": "crown", "outcome": _AO_CROWN,
            "conditions": [{"channel": "crown", "field": "asset",
                            "operator": "in", "expected": list(CROWN_TARGETS)}]})
    return env


def promote(records) -> tuple[list[dict], list[tuple]]:
    """레코드 → (유효 env 목록, 거절 [(env명, errors)]). authoring.validate_env 로 형식 게이트."""
    envs: list[dict] = []
    rejected: list[tuple] = []
    for r in records:
        env = record_to_env(r)
        errors, _warnings = authoring.validate_env(env)
        (rejected.append((env.get("env"), errors)) if errors else envs.append(env))
    return envs, rejected


def load_envs(session, envs) -> tuple[int, int]:
    """신뢰수준(_validation)별로 묶어 build_core_layer(source=coevolution)로 적재."""
    by_level: dict[str, list[dict]] = {}
    for e in envs:
        by_level.setdefault(e.get("_validation", "OBSERVED"), []).append(e)
    tn = tr = 0
    for level, group in by_level.items():
        nodes, rels = sources.build_core_layer(
            {"environments": group}, source="coevolution", validation_level=level)
        tn += graph_writer.merge_nodes(session, nodes)
        tr += graph_writer.merge_rels(session, rels)
    return tn, tr


def _write_doc(out_dir: str, run_id: str, envs: list[dict]) -> str:
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, f"{run_id or 'learned'}.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"_origin": "coevolution-loop", "_run_id": run_id,
                   "_generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                   "environments": envs}, f, ensure_ascii=False, indent=2)
    return out


def _connect(args):
    from neo4j import GraphDatabase
    uri = args.uri or os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = args.user or os.environ.get("NEO4J_USER", "neo4j")
    pw = args.password or os.environ.get("NEO4J_PASSWORD")
    if not pw:
        raise SystemExit("NEO4J_PASSWORD (또는 --password) 필요")
    return GraphDatabase.driver(uri, auth=(user, pw)).session()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="knowledge.promote",
        description="off-KG 포획 저널 → 핵심층 승급(god-view 실증, 2단 반영의 3단)")
    ap.add_argument("--journal", default="orchestrator/logs/off_kg.jsonl",
                    help="off-KG 저널 경로(VM C 산출물)")
    ap.add_argument("--from", dest="from_file", default=None,
                    help="검토·수정한 승급 JSON 에서 적재(저널 대신)")
    ap.add_argument("--out-dir", default="knowledge/learned", help="검토용 JSON 출력 디렉토리")
    ap.add_argument("--min-outcome", choices=["progress", "crown"], default="progress",
                    help="승급 하한: progress=god-view 확인 이상(기본) / crown=크라운만")
    ap.add_argument("--include-unconfirmed", action="store_true",
                    help="미확인(공격자 주장만)도 포함 — 커버리지 공백 신호용(노이즈↑)")
    ap.add_argument("--load", action="store_true", help="Neo4j 에 실제 반영(기본=검토용 JSON 만)")
    ap.add_argument("--uri", default=None)
    ap.add_argument("--user", default=None)
    ap.add_argument("--password", default=None)
    args = ap.parse_args(argv)

    if args.from_file:
        doc = json.load(open(args.from_file, encoding="utf-8"))
        run_id = doc.get("_run_id", "learned")
        envs, rejected = [], []
        for e in doc.get("environments", []):
            errs, _ = authoring.validate_env(e)
            (rejected.append((e.get("env"), errs)) if errs else envs.append(e))
        print(f"[promote] {args.from_file}: 유효 {len(envs)}·거절 {len(rejected)}")
    else:
        records = read_journal(args.journal)
        if not records:
            print(f"[promote] 저널 비었거나 없음: {args.journal}")
            return 0
        min_rank = _RANK["CROWN"] if args.min_outcome == "crown" else _RANK["PROGRESS"]
        kept = gate_and_dedup(records, min_rank=min_rank,
                              include_unconfirmed=args.include_unconfirmed)
        envs, rejected = promote(kept)
        run_id = kept[0].id.run_id if kept else "learned"
        print(f"[promote] 저널 {len(records)}건 → 승급후보 {len(kept)}건 "
              f"→ 유효 {len(envs)}·거절 {len(rejected)}")

    out = _write_doc(args.out_dir, run_id, envs)
    print(f"  검토용: {out}")
    for name, errs in rejected[:10]:
        print(f"  [거절] {name}: {errs[0]}")

    if args.load:
        n, r = load_envs(_connect(args), envs)
        print(f"  [적재] 출처=coevolution nodes={n} rels={r} (신뢰수준별 VERIFIED/OBSERVED)")
    else:
        print(f"  적재(검토 후, 개발기): python3 -m knowledge.promote --from {out} --load")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
