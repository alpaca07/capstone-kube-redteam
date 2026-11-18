"""하네스 저장소(FileHarnessStore) 테스트 — 오버레이 영속화·기반 합성.

자체 러너: python3 tests/test_refiner_store.py
"""
from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from refiner.models import Component, HarnessEdit
from refiner.store import FileHarnessStore


def _edit(eid, text, pr=0.0):
    return HarnessEdit(id=eid, component=Component.SYSTEM_PROMPT, kind="domain",
                       rationale="r", overlay_text=text, priority=pr)


def _store(tmp, **kw):
    return FileHarnessStore(os.path.join(tmp, "overlays.json"), **kw)


def test_read_empty_when_no_state_file():
    with tempfile.TemporaryDirectory() as tmp:
        h = _store(tmp, base_prompt="BASE").read()
        assert h.base_prompt == "BASE" and h.overlays == ()


def test_promote_then_read_roundtrips_in_order():
    with tempfile.TemporaryDirectory() as tmp:
        s = _store(tmp, base_prompt="BASE")
        s.promote(_edit("e1", "지침A"))
        s.promote(_edit("e2", "지침B"))
        h = s.read()
        assert [e.id for e in h.overlays] == ["e1", "e2"]
        assert [e.overlay_text for e in h.overlays] == ["지침A", "지침B"]
        # 합본 프롬프트에 기반 + 두 오버레이가 다 들어가야.
        eff = h.effective_prompt()
        assert "BASE" in eff and "지침A" in eff and "지침B" in eff


def test_promote_persists_across_instances():
    with tempfile.TemporaryDirectory() as tmp:
        _store(tmp, base_prompt="BASE").promote(_edit("e1", "지침A", pr=0.7))
        # 새 인스턴스가 같은 파일에서 읽음.
        h = _store(tmp, base_prompt="BASE").read()
        assert len(h.overlays) == 1 and h.overlays[0].priority == 0.7


def test_clear_resets_overlays_keeps_base():
    with tempfile.TemporaryDirectory() as tmp:
        s = _store(tmp, base_prompt="BASE")
        s.promote(_edit("e1", "지침A"))
        s.clear()
        h = s.read()
        assert h.overlays == () and h.base_prompt == "BASE"


def test_base_from_path():
    with tempfile.TemporaryDirectory() as tmp:
        bp = os.path.join(tmp, "base.txt")
        with open(bp, "w", encoding="utf-8") as f:
            f.write("파일기반")
        h = _store(tmp, base_prompt_path=bp).read()
        assert h.base_prompt == "파일기반"


def test_explicit_base_prompt_overrides_path():
    with tempfile.TemporaryDirectory() as tmp:
        bp = os.path.join(tmp, "base.txt")
        with open(bp, "w", encoding="utf-8") as f:
            f.write("파일기반")
        h = _store(tmp, base_prompt="명시기반", base_prompt_path=bp).read()
        assert h.base_prompt == "명시기반"


def test_missing_base_source_empty():
    with tempfile.TemporaryDirectory() as tmp:
        h = _store(tmp).read()                       # 기반 소스 없음
        assert h.base_prompt == ""                   # → override 생략(VM A 라이브 프롬프트)


def test_skips_malformed_overlay_entries():
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "overlays.json")
        with open(path, "w", encoding="utf-8") as f:
            f.write('[{"overlay_text":"유효"},{"no_text":1},"쓰레기"]')
        h = FileHarnessStore(path, base_prompt="BASE").read()
        assert len(h.overlays) == 1 and h.overlays[0].overlay_text == "유효"


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
    print("── 하네스 저장소(FileHarnessStore) 테스트 ──")
    sys.exit(_run())
