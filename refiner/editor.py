"""편집자 어댑터 — 정렬 모델(두 번째 엔드포인트)로 공격 하네스 수정안 생성·순위.

Editor 이음새 실 구현. god-view 에피소드 요약(digest)과 현재 하네스 프롬프트를 정렬 모델에
보여주고, 공격력을 올릴 프롬프트 수정안 N개를 JSON으로 받는다. 각 수정안은 invariant(일반
실패 교정)·domain(대상 지식 보강)으로 태깅되고, 모델이 매긴 priority(기대효과 0~1)를 들고
온다. rank()는 그 priority로 정렬만 — 추가 LLM 호출 없이 상위 k 선별(정렬 모델 호출 1회로 최소).

정렬 모델은 공격 전략·MITRE 태깅·프롬프트 개선까지 거부 없이 하되 실제 페이로드 직접 생성은
거부한다(실측 확인). 하네스 수정안은 메타 수준 프롬프트 개선이라 거부 영역 밖.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Callable, Optional

from common.llm_json import LLMJsonError, extract_and_load
from refiner.models import Component, Harness, HarnessEdit

_PROMPT_PATH = Path(__file__).resolve().parent / "prompts" / "editor_system.txt"


def _load_prompt() -> str:
    return _PROMPT_PATH.read_text(encoding="utf-8")


class RefinerEditor:
    """Editor 이음새 구현 — propose(정렬 모델 1회 호출) + rank(priority 정렬)."""

    def __init__(self, llm, *, system_prompt: Optional[str] = None,
                 log: Optional[Callable[[str], None]] = None) -> None:
        self.llm = llm                                 # OllamaClient(정렬 모델, 편집 엔드포인트)
        self.system_prompt = system_prompt or _load_prompt()
        self._log = log or (lambda m: None)

    def propose(self, digest: dict, harness: Harness, *, n: int) -> list[HarnessEdit]:
        user = self._build_user(digest, harness, n)
        text = self.llm.chat_text(self.system_prompt, user)
        return self._parse(text, n)

    def rank(self, digest: dict, edits: list[HarnessEdit]) -> list[HarnessEdit]:
        # priority 높은 것부터. 동점은 입력 순서 유지(안정 정렬).
        return sorted(edits, key=lambda e: e.priority, reverse=True)

    # ── 내부 ──
    def _build_user(self, digest: dict, harness: Harness, n: int) -> str:
        return (
            "[직전 교전 god-view 요약]\n"
            f"{json.dumps(digest, ensure_ascii=False, indent=2)}\n\n"
            "[현재 공격 시스템 프롬프트]\n"
            f"{harness.effective_prompt()}\n\n"
            f"위 결과를 바탕으로 공격 깊이를 늘릴 프롬프트 수정안을 정확히 {n}개, "
            'system_prompt 의 JSON 객체 {"edits":[...]} 형식으로만 출력하라.'
        )

    def _parse(self, text: str, n: int) -> list[HarnessEdit]:
        try:
            obj = extract_and_load(text)
        except (LLMJsonError, ValueError):
            self._log("편집자 출력 JSON 파싱 실패 → 수정안 0개")
            return []
        if isinstance(obj, dict):
            items = obj.get("edits")
        elif isinstance(obj, list):
            items = obj                                # 객체 대신 배열로 준 경우도 허용
        else:
            items = None
        if not isinstance(items, list):
            self._log("편집자 출력에 edits 배열이 없음 → 수정안 0개")
            return []

        valid_components = set(Component.ALL)
        out: list[HarnessEdit] = []
        for it in items:
            if not isinstance(it, dict):
                continue
            overlay = (it.get("overlay_text") or "").strip()
            if not overlay:
                continue                               # 빈 수정안은 버림
            comp = it.get("component", Component.SYSTEM_PROMPT)
            if comp not in valid_components:
                comp = Component.SYSTEM_PROMPT
            kind = it.get("kind", "invariant")
            if kind not in ("invariant", "domain"):
                kind = "invariant"
            try:
                priority = float(it.get("priority", 0.0))
            except (TypeError, ValueError):
                priority = 0.0
            out.append(HarnessEdit(
                id=f"e{len(out) + 1}", component=comp, kind=kind,
                rationale=(it.get("rationale") or "").strip(),
                overlay_text=overlay, priority=priority))
            if len(out) >= n:
                break
        return out


__all__ = ["RefinerEditor"]
