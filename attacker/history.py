"""공격 히스토리 — 턴 내 맥락 + 라운드 간 요약.

ReAct 루프가 매 스텝 (thought, action, observation)을 기록하고, 다음 프롬프트에 최근 맥락을
넣어 '뭐가 막혔나' 기억하고 적응하게 한다. summarize()는 라운드 간 기억(다음 라운드 프롬프트로).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from .actions import AttackAction
from .execute_action import Observation

# 저장 발췌 길이 — Observation.stdout 이 이미 _OBS_STDOUT(=2000)로 상한을 두므로 그대로 보존.
# (과거 300자 컷은 페이지 본문 하단의 DB 커넥션 스트링 같은 '유출 지점'을 잘라먹어, 공격자가
#  위키를 가져오고도 크레덴셜을 못 보고 비밀번호를 추측하다 실패하는 실제 병목이었다.)
_RECORD_CHARS = 2000

# 크레덴셜·플래그 후보 — 정찰 중 한 번이라도 관측되면 render 상단에 고정(sticky)해, 여러 스텝
# 뒤에 활용하려 할 때 창(window) 밖으로 밀려 사라지지 않게 한다. DB 커넥션 스트링·키=값·FLAG 만
# (http(s) 서비스 URL 은 일부러 제외 — 노이즈 방지).
_SECRET_PAT = re.compile(
    r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s\"'<>`]+"
    r"|FLAG\{[^}\s]*\}"
    r"|(?:password|passwd|pwd|PGPASSWORD|token|secret|api[_-]?key|authorization|bearer)"
    r"\s*[=:]\s*[^\s\"'<>`&]+",
    re.IGNORECASE)


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
            stdout_excerpt=(obs.stdout[:_RECORD_CHARS] if obs.stdout else obs.stderr[:_RECORD_CHARS]),
            flag_found=obs.flag_found))

    def _pinned_secrets(self, *, max_items: int = 6, clip: int = 200) -> list[str]:
        """전체 히스토리에서 크레덴셜·플래그 후보를 추출(중복 제거, 등장 순)."""
        seen: list[str] = []
        for e in self.entries:
            for m in _SECRET_PAT.findall(e.stdout_excerpt or ""):
                v = m.strip()[:clip]
                if v and v not in seen:
                    seen.append(v)
                    if len(seen) >= max_items:
                        return seen
        return seen

    def render(self, *, max_entries: int = 12, recent_full: int = 2,
               full_chars: int = 1500, old_chars: int = 200) -> str:
        """프롬프트용 최근 맥락. 방금 실행한 명령의 출력(최근 recent_full개)은 넉넉히 보여줘,
        페이지 본문·크레덴셜이 하단에 있어도 모델이 실제로 읽게 한다(과거 200자 컷이 병목이었음).
        오래된 관측은 짧게. 정찰 중 본 크레덴셜·플래그 후보는 상단에 고정해 창 밖으로 사라지지 않게."""
        lines: list[str] = []
        if self.prior_summary:
            lines.append(f"[지난 라운드 요약] {self.prior_summary}")
        pinned = self._pinned_secrets()
        if pinned:
            lines.append("[핵심 발견(크레덴셜·플래그 후보 — 정찰 중 관측됨, 활용하라)]\n"
                         + "\n".join(f"  • {p}" for p in pinned))
        window = self.entries[-max_entries:]
        n = len(window)
        for idx, e in enumerate(window):
            status = "BLOCKED" if e.blocked else ("OK" if e.success else f"FAIL(rc={e.exit_code})")
            cmd = (e.tool + " " + " ".join(e.args)).strip()
            budget = full_chars if idx >= n - recent_full else old_chars
            out = e.stdout_excerpt.replace("\n", " ")[:budget]
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
