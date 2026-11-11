"""공격 턴 중 공격자 /journal 을 폴링해 attack_journal.jsonl 로 미러(실시간 저널).

attack_turn 은 블로킹 HTTP 라 라운드가 끝나야 대본(스텝)이 VM C로 온다. 그 사이 별도
스레드가 공격자 저널을 증분 폴링해 라운드 종료 전에도 대시보드 '공격 저널'에 명령이 흐르게
한다. 공격자가 /journal 을 안 줘도(구버전·실패) 조용히 무동작 — 저널은 보조 기능이다.

출력 레코드는 events.jsonl 과 같은 모양(type=attack_step)이라 대시보드 journalRow 가 그대로
렌더한다. 라운드 종료 시의 record_round_events 는 events.jsonl 에 쓰므로 소스가 분리돼
중복이 없다(저널 탭=attack_journal.jsonl, 이벤트 로그=events.jsonl).
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Callable, Optional


class AttackJournalStreamer:
    """with 블록 동안 공격자 저널을 attack_journal.jsonl 로 미러한다(데몬 스레드)."""

    def __init__(self, attacker, out_dir: Optional[str], *, episode: int, round: int,
                 interval: float = 1.5, log: Optional[Callable[[str], None]] = None) -> None:
        self.attacker = attacker
        self.path = (Path(out_dir) / "attack_journal.jsonl") if out_dir else None
        self.episode = episode
        self.round = round
        self.interval = interval
        self.log = log or (lambda m: None)
        self._stop = threading.Event()
        self._thr: Optional[threading.Thread] = None
        self._since = 0

    def __enter__(self) -> "AttackJournalStreamer":
        if self.path is not None and callable(getattr(self.attacker, "journal", None)):
            self._thr = threading.Thread(target=self._loop, name="attack-journal", daemon=True)
            self._thr.start()
        return self

    def __exit__(self, *exc) -> bool:
        self._stop.set()
        if self._thr is not None:
            self._thr.join(timeout=3.0)
            self._drain()                    # 턴 종료 직전 마지막 증분 한 번 더
        return False

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self._drain()

    def _drain(self) -> None:
        try:
            res = self.attacker.journal(self._since) or {}
        except Exception:                    # noqa: BLE001 — 폴링 실패가 턴을 깨면 안 됨
            return
        entries = res.get("entries") or []
        if entries:
            self._write(entries)
        nxt = res.get("next")
        if isinstance(nxt, int):
            self._since = max(self._since, nxt)
        elif entries:
            self._since += len(entries)

    def _write(self, entries: list) -> None:
        lines = []
        for e in entries:
            lines.append(json.dumps({
                "ts": e.get("ts") or time.time(),
                "episode": self.episode,
                "round": e.get("round") or self.round,
                "actor": "attacker",
                "type": "attack_step",
                "payload": {
                    "tool": e.get("tool", ""), "args": e.get("args") or [],
                    "success": bool(e.get("ok")), "blocked": bool(e.get("blocked")),
                    "intent": e.get("intent", ""), "seq": e.get("seq"),
                },
            }, ensure_ascii=False))
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except OSError:
            pass


__all__ = ["AttackJournalStreamer"]
