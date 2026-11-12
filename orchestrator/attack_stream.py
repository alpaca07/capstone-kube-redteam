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
import os
import threading
import time
from pathlib import Path
from typing import Callable, Optional


class AttackJournalStreamer:
    """with 블록 동안 공격자 저널(attack_journal.jsonl)과 탐색 그래프(attack_graph/<ep>-<rnd>.json)를
    턴 중 실시간 미러한다(데몬 스레드). 그래프는 라운드 종료 시 round_detail 이 최종본으로 덮어쓴다 —
    같은 경로·포맷이라 매끄럽게 이어진다."""

    def __init__(self, attacker, out_dir: Optional[str], *, episode: int, round: int,
                 interval: float = 1.5, log: Optional[Callable[[str], None]] = None,
                 run_id: str = "") -> None:
        self.attacker = attacker
        self.path = (Path(out_dir) / "attack_journal.jsonl") if out_dir else None
        self.graph_path = (Path(out_dir) / "attack_graph" / f"{episode}-{round}.json") if out_dir else None
        self.episode = episode
        self.round = round
        self.run_id = run_id              # 실행 식별자 — 레코드에 박아 대시보드가 회차별 분리
        self.interval = interval
        self.log = log or (lambda m: None)
        self._stop = threading.Event()
        self._thr: Optional[threading.Thread] = None
        self._since = 0

    def __enter__(self) -> "AttackJournalStreamer":
        has_journal = callable(getattr(self.attacker, "journal", None))
        has_graph = callable(getattr(self.attacker, "graph", None))
        if (self.path or self.graph_path) and (has_journal or has_graph):
            self._thr = threading.Thread(target=self._loop, name="attack-stream", daemon=True)
            self._thr.start()
        return self

    def __exit__(self, *exc) -> bool:
        self._stop.set()
        if self._thr is not None:
            self._thr.join(timeout=3.0)
            self._drain()                    # 턴 종료 직전 마지막 증분 한 번 더
            self._drain_graph()
        return False

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            self._drain()
            self._drain_graph()

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
                "run_id": self.run_id,
                "episode": self.episode,
                "round": e.get("round") or self.round,
                "actor": "attacker",
                "type": "attack_step",
                "payload": {
                    "tool": e.get("tool", ""), "args": e.get("args") or [],
                    "success": bool(e.get("ok")), "blocked": bool(e.get("blocked")),
                    "intent": e.get("intent", ""), "intent_label": e.get("intent_label", ""),
                    "seq": e.get("seq"),
                },
            }, ensure_ascii=False))
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write("\n".join(lines) + "\n")
        except OSError:
            pass

    def _drain_graph(self) -> None:
        """현재 탐색 그래프 스냅샷을 라이브 파일로 미러 — 대시보드가 노드 생성을 실시간으로 본다.
        노드가 생긴 뒤에만 쓴다(빈 읽기로 기존 파일을 지우지 않게). 회차가 어긋나면 건너뜀."""
        if self.graph_path is None or not callable(getattr(self.attacker, "graph", None)):
            return
        try:
            res = self.attacker.graph() or {}
        except Exception:                    # noqa: BLE001 — 폴링 실패가 턴을 깨면 안 됨
            return
        ep = res.get("episode")
        if ep is not None and ep != self.episode:   # 다음 회차 그래프를 이번 파일에 쓰지 않게
            return
        snap = res.get("graph") or {}
        if not (snap.get("nodes")):                 # 아직 노드 없음 — 기존 파일 보존
            return
        self._write_graph(snap)

    def _write_graph(self, snap: dict) -> None:
        payload = {"episode": self.episode, "round": self.round, "ts": time.time(), "graph": snap}
        try:
            self.graph_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.graph_path.with_suffix(".json.tmp")
            with tmp.open("w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False)
            os.replace(str(tmp), str(self.graph_path))   # 원자적 교체(대시보드가 반쪽 읽지 않게)
        except OSError:
            pass


__all__ = ["AttackJournalStreamer"]
