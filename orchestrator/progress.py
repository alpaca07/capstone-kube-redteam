"""실시간 진행 상태 sink — 시퀀서가 단계마다 '지금 상태'를 원자적 JSON으로 떨군다.

api.py 의 /api/status 가 이 파일(progress.json)을 읽어 대시보드에 라이브로 보여준다(폴링).
stdout 로그(run.out)와 달리 **구조화된 현재 상태**를 제공 → 0~8 단계 표시기·턴 예산 바·
현재 에피소드/라운드/활성 에이전트의 소스. 채점기 sink(rounds.jsonl)와는 별개.

설계:
- 상태는 단일 dict, update(**fields)로 머지하고 매번 파일에 원자적 기록(temp→os.replace).
- Callable[[dict], None] 로도 쓰이게 __call__ 제공(시퀀서 훅과 호환).
- 디스크 쓰기 실패는 무시(모니터링 보조라 실험을 멈추면 안 됨).

공유 계약(phase 인덱스 ↔ 이름) — 대시보드 LOOP 와 1:1:
    0 초기화 / 1 공격 턴 / 2 방어 턴 / 3 검증 / 4 채점 / 5 에피소드 종료
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path
from typing import Optional

PHASES = ["초기화", "공격 턴", "방어 턴", "검증", "채점", "에피소드 종료"]


class ProgressSink:
    """진행 상태를 progress.json 에 원자적으로 기록하는 stateful sink."""

    def __init__(self, path: str | os.PathLike) -> None:
        self.path = Path(path)
        self._state: dict = {
            "status": "idle",            # idle | running | done | aborted
            "episode": 0,
            "total_episodes": 0,
            "round": 0,
            "max_rounds": 0,
            "phase": 0,
            "phase_name": PHASES[0],
            "active": None,              # "attacker" | "defender" | None(심판)
            "turn_started": None,        # epoch(초) — 턴 경과 계산용
            "time_limit_sec": 0,
            "last_verdict": None,        # 직전 라운드 판정(blocked/fake_patch/...)
            "flags_reached": [],         # 현재 에피소드 누적 god-view 플래그(①②③ + 크라운 objective id)
            "crowns_reached": [],        # 그중 크라운(중요자산 반출) objective id — 어느 자산이 빠졌나
            "crowns_by_channel": {},     # {크라운 objective id: [통로]} — 어느 통로(app·db)로 빠졌나
            "goals_reached": [],         # 달성 최종 목표(db_exfil 등) — 실제 침해 성립 여부
            "updated_at": time.time(),
        }

    def update(self, **fields) -> None:
        if "phase" in fields and "phase_name" not in fields:
            p = fields["phase"]
            if isinstance(p, int) and 0 <= p < len(PHASES):
                fields["phase_name"] = PHASES[p]
        self._state.update(fields)
        self._state["updated_at"] = time.time()
        self._write()

    def __call__(self, fields: dict) -> None:
        """시퀀서가 Callable[[dict], None] 로 호출할 때."""
        self.update(**fields)

    def snapshot(self) -> dict:
        return dict(self._state)

    def _write(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            fd, tmp = tempfile.mkstemp(dir=str(self.path.parent), suffix=".tmp")
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as f:
                    json.dump(self._state, f, ensure_ascii=False)
                os.replace(tmp, self.path)       # 원자적 교체(폴링 중 half-write 방지)
            except Exception:                    # noqa: BLE001
                try:
                    os.unlink(tmp)
                except OSError:
                    pass
                raise
        except Exception:                        # noqa: BLE001 — 모니터링 보조, 실패해도 실험 지속
            pass


__all__ = ["ProgressSink", "PHASES"]
