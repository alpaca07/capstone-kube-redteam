"""공격 히스토리 — 턴 내 맥락 + 라운드 간 요약.

ReAct 루프가 매 스텝 (thought, action, observation)을 기록하고, 다음 프롬프트에 최근 맥락을
넣어 '뭐가 막혔나' 기억하고 적응하게 한다. summarize()는 라운드 간 기억(다음 라운드 프롬프트로).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from .actions import AttackAction
from .execute_action import Observation


@dataclass
class HistoryEntry:
    step: int
    thought: str
    tool: str
    args: list
    success: bool
    blocked: bool
    exit_code: int
    stdout_excerpt: str = ""
    flag_found: Optional[str] = None


class AttackHistory:
    def __init__(self, prior_summary: str = "") -> None:
        self.entries: list[HistoryEntry] = []
        self.prior_summary = prior_summary          # 지난 라운드 요약(라운드 간 기억)

    def record(self, action: AttackAction, obs: Observation) -> None:
        self.entries.append(HistoryEntry(
            step=obs.step, thought=action.thought, tool=action.tool, args=list(action.args),
            success=obs.success, blocked=obs.blocked, exit_code=obs.exit_code,
            stdout_excerpt=(obs.stdout[:300] if obs.stdout else obs.stderr[:300]),
            flag_found=obs.flag_found))

    def render(self, *, max_entries: int = 12) -> str:
        """프롬프트용 최근 맥락(길면 최근 것만)."""
        lines: list[str] = []
        if self.prior_summary:
            lines.append(f"[지난 라운드 요약] {self.prior_summary}")
        for e in self.entries[-max_entries:]:
            status = "BLOCKED" if e.blocked else ("OK" if e.success else f"FAIL(rc={e.exit_code})")
            cmd = (e.tool + " " + " ".join(e.args)).strip()
            out = e.stdout_excerpt.replace("\n", " ")[:200]
            lines.append(f"#{e.step} [{status}] {cmd}\n    → {out}")
        return "\n".join(lines) if lines else "(아직 행동 없음 — 정찰부터 시작하라)"

    def summarize(self, *, max_steps: int = 6, excerpt: int = 140) -> str:
        """이번 라운드 요약(다음 라운드로 넘길 기억). 단순 카운트가 아니라 '성공한 행동 + 그 관측'
        을 담아, 다음 라운드가 발견(엔드포인트·크레덴셜 등)을 실제로 이어받게 한다."""
        if not self.entries:
            return "행동 없음"
        blocked = sum(1 for e in self.entries if e.blocked)
        failed = sum(1 for e in self.entries if not e.success and not e.blocked)
        flags = [e.flag_found for e in self.entries if e.flag_found]
        lines = [f"{len(self.entries)}개 행동(실패 {failed}·차단 {blocked})."]
        useful = [e for e in self.entries if e.success and not e.blocked]
        if useful:
            lines.append("주요 관측(성공한 행동):")
            for e in useful[-max_steps:]:
                cmd = (e.tool + " " + " ".join(e.args)).strip()
                out = (e.stdout_excerpt or "").replace("\n", " ").strip()[:excerpt]
                lines.append(f"- {cmd} → {out}")
        if flags:
            lines.append(f"플래그 획득: {flags}")
        return "\n".join(lines)


__all__ = ["HistoryEntry", "AttackHistory"]
