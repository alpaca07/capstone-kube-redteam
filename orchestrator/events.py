"""행위 이벤트 sink — 심판이 라운드마다 '무슨 일이 오갔나'를 구조화 한 줄씩 떨군다.

채점기(rounds.jsonl 수치)·진행 sink(progress.json 현재 상태)와는 별개의 세 번째 로그다.
여기엔 하네스별 개별 행위(공격 명령 한 스텝, 방어 탐지 한 건, 패치 한 건, 판정)가 시간순으로
쌓인다 → 대시보드의 이벤트 로그(하네스별 탭)와 사건 타임라인(MTTD 시각)의 소스.

공통 봉투(한 줄 = 한 사건):
    {ts, episode, round, phase, actor, type, payload}
  actor : "attacker" | "defender" | "judge"
  type  : attack_step · attack_turn · detection · patch · defense_turn · verdict
  phase : progress.py 와 같은 단계 인덱스(0 초기화 /1 공격 /2 방어 /3 검증 /4 채점)

설계(진행 sink·채점기 패턴 그대로):
- EventSink 는 write 콜백 주입(파일 append 등) 또는 None(무동작) — 테스트는 리스트로 받는다.
- 디스크 쓰기 실패는 삼킨다(모니터링 보조 — 실패해도 실험은 안 멈춘다).
- '라운드 결과(공격·방어·검증) → 이벤트들' 변환은 record_round_events 순수 함수로 분리.
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Callable, Optional

# actor 상수(오타 방지)
ATTACKER = "attacker"
DEFENDER = "defender"
JUDGE = "judge"


def _warn_event_fail(where: str, exc: Exception) -> None:
    """이벤트 쓰기 실패는 실험을 멈추지 않되(모니터링 보조), 왜 실패했는지 stderr 로 한 줄 남긴다.
    (과거엔 조용히 삼켜 events.jsonl 이 안 생겨도 원인을 알 수 없었다.) CAPSTONE_EVENTS_QUIET=1 로 끈다."""
    if os.environ.get("CAPSTONE_EVENTS_QUIET") == "1":
        return
    print(f"[events] {where} 쓰기 실패(무시하고 계속): {type(exc).__name__}: {exc}", file=sys.stderr)


class EventSink:
    """행위 이벤트를 받아 write 콜백으로 흘리는 sink(없으면 무동작)."""

    def __init__(self, write: Optional[Callable[[dict], None]] = None, *, run_id: str = "") -> None:
        self._write = write
        self._run_id = run_id              # 실행 식별자 — 레코드에 박아 대시보드가 회차별 분리

    def emit(self, type: str, *, actor: str, episode: int, round: int,
             payload: Optional[dict] = None, phase: Optional[int] = None) -> dict:
        ev = {"ts": time.time(), "run_id": self._run_id, "episode": episode, "round": round,
              "phase": phase, "actor": actor, "type": type, "payload": payload or {}}
        if self._write is not None:
            try:
                self._write(ev)
            except Exception as e:         # noqa: BLE001 — 모니터링 보조, 실패해도 실험 지속
                _warn_event_fail("emit", e)
        return ev

    def __call__(self, ev: dict) -> None:
        """Callable[[dict], None] 로도 쓰이게(이미 만들어진 이벤트를 그대로 흘림)."""
        if self._write is not None:
            try:
                self._write(ev)
            except Exception as e:         # noqa: BLE001
                _warn_event_fail("__call__", e)


def jsonl_event_sink(path: str) -> Callable[[dict], None]:
    """이벤트 dict 를 JSON Lines 파일에 append 하는 write 콜백(실전 로깅용)."""
    def _sink(ev: dict) -> None:
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev, ensure_ascii=False) + "\n")
    return _sink


# ───────────── 라운드 결과 → 이벤트들(순수 변환) ─────────────
def record_round_events(sink: Optional[EventSink], *, episode: int, round: int,
                        attack=None, defense=None, verification=None) -> None:
    """한 라운드의 공격·방어·검증 객체에서 개별 행위 이벤트를 뽑아 sink 로 흘린다.

    생략 라운드(방어·검증이 합성)여도 공격 활동은 남는다. 전부 None-안전(getattr 폴백)이라
    객체 모양이 조금 달라도 터지지 않는다 — 모니터링 보조라 견고성이 정확성보다 중요.
    """
    if sink is None:
        return
    try:
        if attack is not None:
            _emit_attack(sink, episode, round, attack)
        if defense is not None:
            _emit_defense(sink, episode, round, defense)
        if verification is not None:
            _emit_verdict(sink, episode, round, verification)
    except Exception as e:                 # noqa: BLE001 — 이벤트 기록 실패가 라운드를 깨면 안 됨
        _warn_event_fail("record_round_events", e)


def _emit_attack(sink: EventSink, episode: int, round: int, attack) -> None:
    script = getattr(attack, "replay_script", None)
    steps = getattr(script, "steps", None) or []
    for st in steps:
        cmd = getattr(st, "command", None)
        res = getattr(st, "result", None)
        det = getattr(st, "determinism", None)
        sink.emit("attack_step", actor=ATTACKER, episode=episode, round=round, phase=1,
                  payload={
                      "step": getattr(st, "step", None),
                      "step_id": getattr(st, "step_id", ""),
                      "tool": getattr(cmd, "tool", "") if cmd else "",
                      "args": list(getattr(cmd, "args", []) or []) if cmd else [],
                      "success": bool(getattr(res, "success", False)) if res else False,
                      "determinism": _enum_val(det),
                  })
    sink.emit("attack_turn", actor=ATTACKER, episode=episode, round=round, phase=1,
              payload={
                  "end_reason": _enum_val(getattr(attack, "end_reason", None)),
                  "steps": len(steps),
                  "summary": getattr(attack, "attack_summary", "") or "",
                  "elapsed_sec": getattr(attack, "elapsed_sec", 0.0),
              })


def _emit_defense(sink: EventSink, episode: int, round: int, defense) -> None:
    for d in getattr(defense, "detected", []) or []:
        sink.emit("detection", actor=DEFENDER, episode=episode, round=round, phase=2,
                  payload={
                      "technique": getattr(d, "technique", None),
                      "evidence": getattr(d, "evidence", "") or "",
                      "confidence": getattr(d, "confidence", None),
                  })
    # 적용/스킵을 모두 보여주려 patch_attempts(사람이 읽는 줄)를 그대로, 없으면 patch_set 으로 폴백.
    attempts = getattr(defense, "patch_attempts", None) or []
    if attempts:
        for line in attempts:
            applied = "[applied]" in str(line)
            sink.emit("patch", actor=DEFENDER, episode=episode, round=round, phase=2,
                      payload={"detail": str(line), "applied": applied})
    else:
        for p in getattr(defense, "patch_set", []) or []:
            sink.emit("patch", actor=DEFENDER, episode=episode, round=round, phase=2,
                      payload={"kind": getattr(p, "kind", ""), "target": getattr(p, "target", ""),
                               "summary": getattr(p, "summary", ""), "applied": True})
    sink.emit("defense_turn", actor=DEFENDER, episode=episode, round=round, phase=2,
              payload={
                  "patch_applied": bool(getattr(defense, "patch_applied", False)),
                  "end_reason": _enum_val(getattr(defense, "end_reason", None)),
                  "detected": len(getattr(defense, "detected", []) or []),
                  "patches": len(getattr(defense, "patch_set", []) or []),
                  "healthcheck_passed": bool(getattr(defense, "healthcheck_passed", False)),
                  "note": getattr(defense, "patch_note", "") or "",
                  "error": getattr(defense, "error", "") or "",
                  "elapsed_sec": getattr(defense, "elapsed_sec", 0.0),
              })


def _emit_verdict(sink: EventSink, episode: int, round: int, verification) -> None:
    sink.emit("verdict", actor=JUDGE, episode=episode, round=round, phase=3,
              payload={
                  "verdict": _enum_val(getattr(verification, "verdict", None)),
                  "method": getattr(verification, "method", "") or "",
                  "detail": getattr(verification, "detail", "") or "",
              })


def _enum_val(x) -> Optional[str]:
    """Enum 이면 .value, 문자열이면 그대로, None 이면 None."""
    if x is None:
        return None
    return getattr(x, "value", x)


__all__ = ["EventSink", "jsonl_event_sink", "record_round_events",
           "ATTACKER", "DEFENDER", "JUDGE"]
