"""LLM 클라이언트 테스트 — DGX 연결 로직을 fake transport로(네트워크 없이).

    python3 tests/test_llm_client.py
"""
from __future__ import annotations

import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.llm_client import LLMError, OllamaClient  # noqa: E402


def _fake(response, cap):
    def _t(method, url, body, timeout):
        cap.update(method=method, url=url, body=body, timeout=timeout)
        return response
    return _t


def test_chat_builds_request_and_parses():
    cap: dict = {}
    resp = {"choices": [{"message": {"role": "assistant", "content": "hi"}}]}
    c = OllamaClient("http://dgx:11434/v1/", "qwen-jb", transport=_fake(resp, cap))
    out = c.chat([{"role": "user", "content": "yo"}])
    assert out == "hi"
    assert cap["method"] == "POST"
    assert cap["url"] == "http://dgx:11434/v1/chat/completions"   # trailing slash 정리
    assert cap["body"]["model"] == "qwen-jb"                      # 모델 선택 = 필드
    assert cap["body"]["temperature"] == 0.0                      # 기본 재현성
    assert cap["body"]["stream"] is False


def test_temperature_and_options_override():
    cap: dict = {}
    resp = {"choices": [{"message": {"content": "a"}}]}
    c = OllamaClient("http://x/v1", "m", transport=_fake(resp, cap))
    c.chat([{"role": "user", "content": "x"}], temperature=0.7, max_tokens=64, stop=["\n\n"])
    assert cap["body"]["temperature"] == 0.7
    assert cap["body"]["max_tokens"] == 64
    assert cap["body"]["stop"] == ["\n\n"]


def test_chat_text_helper():
    cap: dict = {}
    c = OllamaClient("http://x/v1", "m",
                     transport=_fake({"choices": [{"message": {"content": "ok"}}]}, cap))
    assert c.chat_text("sys", "usr") == "ok"
    roles = [m["role"] for m in cap["body"]["messages"]]
    assert roles == ["system", "user"]


def test_list_models():
    cap: dict = {}
    resp = {"data": [{"id": "qwen-jb"}, {"id": "qwen"}]}
    c = OllamaClient("http://dgx:11434/v1", "m", transport=_fake(resp, cap))
    assert c.list_models() == ["qwen-jb", "qwen"]
    assert cap["method"] == "GET" and cap["url"] == "http://dgx:11434/v1/models"


def test_bad_response_raises():
    c = OllamaClient("http://x/v1", "m", transport=_fake({"oops": 1}, {}))
    try:
        c.chat([{"role": "user", "content": "x"}])
    except LLMError:
        return
    raise AssertionError("형식 이상인데 예외 안 남")


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
    print("── LLM 클라이언트 테스트 ──")
    sys.exit(_run())
