"""라운드 상세 persist — 드릴다운용 원자료를 라운드당 한 파일로 떨군다.

채점기(rounds.jsonl)는 차트용 수치만 가볍게 남기고 공격 대본·방어 탐지 근거·패치 항목·검증
세부를 버린다. 그 원자료를 여기서 round_detail/<ep>-<rnd>.json 에 따로 보관한다 →
대시보드의 방어 탐지·패치 그래프(P8)·패치세트 큐레이션·회차 보고서(P9)가 읽는다.

방어 토폴로지(방어자가 대상을 훑어 재구성한 지도)가 결과에 실려 오면 defense_topology/
<ep>-<rnd>.json 으로도 따로 떨군다 → 타깃 아키텍처 자동 생성 화면(P7)이 읽는다.

설계:
- round_detail_dict 는 순수 함수(객체 → dict) — 디스크 없이 테스트.
- 쓰기는 원자적(temp → os.replace)으로 폴링 중 half-write 방지.
- pydantic 모델은 model_dump(mode="json"), 데이터클래스(VerificationResult)는 수동 직렬화.
- 실패는 삼킨다(보조 로깅 — 실험을 멈추면 안 됨).
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Optional


def round_detail_dict(episode: int, round: int, *, attack=None, defense=None,
                      verification=None) -> dict:
    """한 라운드의 공격·방어·검증 객체를 JSON 직렬화 가능한 상세 dict 로."""
    return {
        "episode": episode,
        "round": round,
        "ts": time.time(),
        "attack": _dump(attack),
        "defense": _dump(defense),
        "verification": _verif_dict(verification),
    }


def write_round_detail(out_dir: Optional[str], episode: int, round: int, *,
                       attack=None, defense=None, verification=None) -> None:
    """상세 dict 를 round_detail/<ep>-<rnd>.json 에 원자적으로 쓴다. 토폴로지가 있으면 별도 파일도.

    out_dir 가 None 이면 무동작. 실패는 삼킨다(보조 로깅).
    """
    if not out_dir:
        return
    try:
        detail = round_detail_dict(episode, round, attack=attack, defense=defense,
                                   verification=verification)
        _atomic_write(Path(out_dir) / "round_detail" / f"{episode}-{round}.json", detail)
        topo = getattr(defense, "topology", None)
        if topo:
            _atomic_write(Path(out_dir) / "defense_topology" / f"{episode}-{round}.json",
                          {"episode": episode, "round": round, "ts": time.time(),
                           "topology": topo})
        snap = getattr(attack, "graph_snapshot", None)       # 공격 탐색 그래프(표시 전용)
        if snap:
            _atomic_write(Path(out_dir) / "attack_graph" / f"{episode}-{round}.json",
                          {"episode": episode, "round": round, "ts": time.time(),
                           "graph": snap})
    except Exception:                      # noqa: BLE001 — 보조 로깅, 실패해도 실험 지속
        pass


# ───────────── 직렬화 헬퍼 ─────────────
def _dump(obj):
    """pydantic 모델 → model_dump(mode='json'), 아니면 그대로(None 포함)."""
    if obj is None:
        return None
    md = getattr(obj, "model_dump", None)
    if callable(md):
        return md(mode="json")
    return obj


def _verif_dict(v) -> Optional[dict]:
    """VerificationResult(데이터클래스) 수동 직렬화 — verdict/method/detail + post 재생."""
    if v is None:
        return None
    verdict = getattr(v, "verdict", None)
    post = getattr(v, "post", None)
    return {
        "verdict": getattr(verdict, "value", verdict),
        "method": getattr(v, "method", "") or "",
        "detail": getattr(v, "detail", "") or "",
        "flags_still_reachable": list(getattr(v, "flags_still_reachable", []) or []),
        "post": _dump(post),
    }


def _atomic_write(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


__all__ = ["round_detail_dict", "write_round_detail"]
