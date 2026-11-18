"""하네스 저장소 실 구현 — 승급된 오버레이를 VM C 로컬 파일에 영속화.

HarnessStore 이음새 구현(방식 가: VM C 보유). 기반 프롬프트는 레포의 공격 프롬프트 파일에서
읽고(git 로 VM 간 동기), 승급 오버레이만 이 스토어가 JSON 으로 쌓는다. read() 가 둘을 합쳐
Harness(기반 불변 + 오버레이)로 돌려주면, refine 의 시험실행·라이브 턴이 그 합본을
system_prompt_override 로 VM A 에 주입한다. 기반은 절대 수정 안 함 → 오버레이만 지우면 롤백.

상태 파일(overlays.json)은 VM C 로컬·gitignore(실험 산출물). 기반은 읽기 전용 소스.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Callable, Optional

from refiner.models import Harness, HarnessEdit


class FileHarnessStore:
    """오버레이를 JSON 파일에 쌓는 HarnessStore. 기반 프롬프트는 파일/문자열에서."""

    def __init__(self, state_path, *, base_prompt_path=None,
                 base_prompt: Optional[str] = None,
                 log: Optional[Callable[[str], None]] = None) -> None:
        self.state_path = Path(state_path)           # 오버레이 JSON(VM C 로컬)
        self.base_prompt_path = Path(base_prompt_path) if base_prompt_path else None
        self._base_prompt = base_prompt              # 명시 기반(테스트/override). None이면 파일에서
        self._log = log or (lambda m: None)

    # ── 기반 프롬프트 ──
    def _base(self) -> str:
        if self._base_prompt is not None:
            return self._base_prompt
        if self.base_prompt_path and self.base_prompt_path.is_file():
            return self.base_prompt_path.read_text(encoding="utf-8")
        self._log("기반 프롬프트 소스 없음 → 빈 기반(override 생략, VM A 라이브 프롬프트 사용)")
        return ""

    # ── 오버레이 I/O ──
    def _load_overlays(self) -> list[HarnessEdit]:
        if not self.state_path.is_file():
            return []
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (ValueError, OSError):
            self._log(f"오버레이 상태 파일 파싱 실패 → 빈 목록: {self.state_path}")
            return []
        out: list[HarnessEdit] = []
        for d in raw if isinstance(raw, list) else []:
            if not isinstance(d, dict) or not d.get("overlay_text"):
                continue
            out.append(HarnessEdit(
                id=d.get("id", f"e{len(out) + 1}"),
                component=d.get("component", "system_prompt"),
                kind=d.get("kind", "invariant"),
                rationale=d.get("rationale", ""),
                overlay_text=d["overlay_text"],
                priority=float(d.get("priority", 0.0) or 0.0),
            ))
        return out

    def _save_overlays(self, overlays: list[HarnessEdit]) -> None:
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        self.state_path.write_text(
            json.dumps([asdict(e) for e in overlays], ensure_ascii=False, indent=2),
            encoding="utf-8")

    # ── HarnessStore 이음새 ──
    def read(self) -> Harness:
        return Harness(base_prompt=self._base(), overlays=tuple(self._load_overlays()))

    def promote(self, edit: HarnessEdit) -> None:
        overlays = self._load_overlays()
        overlays.append(edit)
        self._save_overlays(overlays)
        self._log(f"오버레이 승급: {edit.id} ({edit.kind}) — 누적 {len(overlays)}개")

    # ── 실험 운영(ablation·리셋) ──
    def clear(self) -> None:
        """승급 오버레이 전체 비움(기반은 불변). ablation·새 실험 시작용."""
        self._save_overlays([])
        self._log("오버레이 전체 비움(기반 보존)")

    def overlays(self) -> list[HarnessEdit]:
        return self._load_overlays()


__all__ = ["FileHarnessStore"]
