"""정답 타임라인(TruthLog) — god-view, 방어자에겐 절대 비공개.

라운드마다 '실제로 무슨 공격이 일어났나'를 심판만 아는 사실로 기록한다. 출처는 god-view:
검증 결과(어느 플래그가 실제 도달됐나) + 값 대조(④) + 감사/Falco 로그(기법 발생). 이게
탐지 정확도(TP/FP/FN)와 MTTD 판정의 '정답지'. 방어자 자기보고와 대조하는 기준선.

채점기(scorer)가 이 로그를 읽어 방어자의 detected[]와 맞대본다. 방어자는 이 로그를 못 본다.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional


@dataclass(frozen=True)
class TruthEvent:
    """이 라운드에 god-view가 확인한 공격 사건 하나."""
    technique: str                 # MITRE ATT&CK 기법 ID (예: T1078)
    flag_id: Optional[str] = None  # 연결된 플래그(있으면)
    detail: str = ""
    channels: tuple[str, ...] = ()  # 크라운 반출 통로(app·db) — 표시 전용, 판정엔 안 쓰임


@dataclass
class TruthEntry:
    """한 라운드의 god-view 사실 기록."""
    episode: int
    round: int
    events: list[TruthEvent] = field(default_factory=list)
    flags_reached: list[str] = field(default_factory=list)   # god-view 확정 플래그
    timestamp: float = field(default_factory=time.time)

    def techniques(self) -> set[str]:
        return {e.technique for e in self.events}


class TruthLog:
    """god-view 사실 원장(작은 인터페이스로 질의). 회차·라운드 단위 조회."""

    def __init__(self) -> None:
        self._entries: list[TruthEntry] = []

    def record(self, entry: TruthEntry) -> None:
        self._entries.append(entry)

    def entries(self, episode: Optional[int] = None) -> list[TruthEntry]:
        if episode is None:
            return list(self._entries)
        return [e for e in self._entries if e.episode == episode]

    def techniques_in_round(self, episode: int, round: int) -> set[str]:
        out: set[str] = set()
        for e in self._entries:
            if e.episode == episode and e.round == round:
                out |= e.techniques()
        return out

    def techniques_up_to(self, episode: int, round: int) -> set[str]:
        """회차 내 round까지 누적 발생한 기법(한 번 일어난 공격은 이후에도 '사실')."""
        out: set[str] = set()
        for e in self._entries:
            if e.episode == episode and e.round <= round:
                out |= e.techniques()
        return out

    def flags_up_to(self, episode: int, round: int) -> set[str]:
        out: set[str] = set()
        for e in self._entries:
            if e.episode == episode and e.round <= round:
                out |= set(e.flags_reached)
        return out

    def crown_channels_up_to(self, episode: int, round: int) -> dict[str, set[str]]:
        """round까지 누적 '어느 크라운(flag_id)이 어느 통로로 빠졌나' — 표시 전용.

        한 크라운이 여러 통로(app·db)로 빠지면 통로가 합쳐진다. flags_up_to 와 별개 축:
        판정은 flags_up_to 가, 통로 표시는 이 맵이 담당(심판 결정엔 영향 없음)."""
        out: dict[str, set[str]] = {}
        for e in self._entries:
            if e.episode != episode or e.round > round:
                continue
            for ev in e.events:
                if ev.flag_id and ev.channels:
                    out.setdefault(ev.flag_id, set()).update(ev.channels)
        return out

    def first_occurrence_round(self, episode: int) -> dict[str, int]:
        """회차에서 각 기법이 '처음 발생'한 라운드 — MTTD 계산 기준선."""
        first: dict[str, int] = {}
        for e in sorted(self._entries, key=lambda x: x.round):
            if e.episode != episode:
                continue
            for t in e.techniques():
                first.setdefault(t, e.round)
        return first


__all__ = ["TruthEvent", "TruthEntry", "TruthLog"]
