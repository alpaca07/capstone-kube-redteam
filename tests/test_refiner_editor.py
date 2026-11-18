"""편집자 어댑터(RefinerEditor) 테스트 — 정렬 LLM 출력 파싱·순위(fake LLM).

자체 러너: python3 tests/test_refiner_editor.py
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from refiner.editor import RefinerEditor
from refiner.models import Component, Harness, HarnessEdit


class FakeLLM:
    """chat_text 가 미리 심은 응답을 돌려주고, 받은 (system,user)를 기록."""
    def __init__(self, reply: str):
        self.reply = reply
        self.calls: list[tuple[str, str]] = []
    def chat_text(self, system: str, user: str, **kw) -> str:
        self.calls.append((system, user))
        return self.reply


_H = Harness(base_prompt="BASE_PROMPT")
_DIGEST = {"score": 2.0, "crowns": [], "techniques": ["T1046"], "blocked": ["kubectl get secrets"]}


def _editor(reply: str) -> RefinerEditor:
    return RefinerEditor(FakeLLM(reply))


# ───────────── 파싱 ─────────────
def test_propose_parses_object_with_edits():
    reply = ('{"edits":[{"component":"system_prompt","kind":"domain",'
             '"rationale":"관측된 5432 포트 노려라","overlay_text":"postgres 5432 직접 시도",'
             '"priority":0.8}]}')
    edits = _editor(reply).propose(_DIGEST, _H, n=4)
    assert len(edits) == 1
    e = edits[0]
    assert e.id == "e1" and e.component == Component.SYSTEM_PROMPT
    assert e.kind == "domain" and e.priority == 0.8
    assert "postgres 5432" in e.overlay_text


def test_propose_handles_fenced_messy_json():
    reply = ('좋아, 제안이야:\n```json\n{"edits":[{"component":"system_prompt",'
             '"kind":"invariant","rationale":"r","overlay_text":"막힌 경로 반복 금지",'
             '"priority":0.5}]}\n```\n이상.')
    edits = _editor(reply).propose(_DIGEST, _H, n=4)
    assert len(edits) == 1 and edits[0].overlay_text == "막힌 경로 반복 금지"


def test_propose_respects_n_cap():
    items = ",".join(
        f'{{"component":"system_prompt","kind":"invariant","rationale":"r{i}",'
        f'"overlay_text":"지침{i}","priority":0.{i}}}' for i in range(1, 6))
    edits = _editor('{"edits":[' + items + ']}').propose(_DIGEST, _H, n=2)
    assert len(edits) == 2                              # 5개 왔어도 n=2 로 컷
    assert [e.id for e in edits] == ["e1", "e2"]


def test_propose_skips_empty_overlay():
    reply = ('{"edits":[{"component":"system_prompt","kind":"invariant",'
             '"rationale":"빈것","overlay_text":"   ","priority":0.9},'
             '{"component":"system_prompt","kind":"domain","rationale":"유효",'
             '"overlay_text":"유효 지침","priority":0.3}]}')
    edits = _editor(reply).propose(_DIGEST, _H, n=4)
    assert len(edits) == 1 and edits[0].overlay_text == "유효 지침"
    assert edits[0].id == "e1"                          # 빈것 건너뛰고 id 연속


def test_propose_invalid_component_and_kind_fall_back():
    reply = ('{"edits":[{"component":"weird","kind":"nonsense",'
             '"rationale":"r","overlay_text":"지침","priority":"높음"}]}')
    e = _editor(reply).propose(_DIGEST, _H, n=4)[0]
    assert e.component == Component.SYSTEM_PROMPT        # 잘못된 component → 폴백
    assert e.kind == "invariant"                        # 잘못된 kind → 폴백
    assert e.priority == 0.0                            # 숫자 아닌 priority → 0.0


def test_propose_garbage_returns_empty():
    assert _editor("여기 JSON 없음 미안").propose(_DIGEST, _H, n=4) == []


def test_propose_sends_digest_and_prompt_to_llm():
    llm = FakeLLM('{"edits":[]}')
    RefinerEditor(llm).propose(_DIGEST, _H, n=3)
    _sys, user = llm.calls[0]
    assert "BASE_PROMPT" in user                        # 현재 프롬프트 포함
    assert "T1046" in user                              # digest 포함
    assert "3개" in user                                # 요청 개수 전달


# ───────────── 순위 ─────────────
def test_rank_sorts_by_priority_desc():
    edits = [
        HarnessEdit("e1", Component.SYSTEM_PROMPT, "invariant", "r", "a", priority=0.2),
        HarnessEdit("e2", Component.SYSTEM_PROMPT, "domain", "r", "b", priority=0.9),
        HarnessEdit("e3", Component.SYSTEM_PROMPT, "invariant", "r", "c", priority=0.5),
    ]
    ranked = _editor("{}").rank(_DIGEST, edits)
    assert [e.id for e in ranked] == ["e2", "e3", "e1"]


# ───────────── 자체 러너 ─────────────
def _run() -> int:
    tests = [v for k, v in sorted(globals().items())
             if k.startswith("test_") and callable(v)]
    passed = failed = 0
    for t in tests:
        try:
            t()
            print(f"  \033[32m✓\033[0m {t.__name__}")
            passed += 1
        except Exception as e:  # noqa: BLE001
            import traceback
            print(f"  \033[31m✗\033[0m {t.__name__}: {type(e).__name__}: {e}")
            traceback.print_exc()
            failed += 1
    print(f"\n{passed} passed, {failed} failed  (총 {len(tests)})")
    return 1 if failed else 0


if __name__ == "__main__":
    print("── 편집자 어댑터(RefinerEditor) 테스트 ──")
    sys.exit(_run())
