"""OllamaClient 요청 body 구성 테스트 — 특히 사고 모드 off(reasoning_effort).

Qwen3 계열은 Ollama /v1 에서 native think:false 가 무시되고 reasoning_effort='none' 이라야
사고가 꺼진다(안 끄면 content 가 빈 채 finish=length 로 와 파싱 전멸). 공격자·방어자가 같은
클라이언트를 쓰므로 기본값으로 박아 둘 다 커버한다.
"""
from common.llm_client import OllamaClient


def _client_capturing(body_sink, **kw):
    def transport(method, url, body, timeout):
        body_sink.clear()
        body_sink.update(body or {})
        return {"choices": [{"message": {"content": "{}"}, "finish_reason": "stop"}]}
    return OllamaClient("http://dgx:11434/v1", "qwen3.8:27b", transport=transport, **kw)


def test_reasoning_effort_none_by_default_on_chat_text():
    # 방어자 경로(chat_text, extra 안 넘김)도 기본으로 사고 off 가 실려야 한다.
    body = {}
    _client_capturing(body).chat_text("sys", "usr")
    assert body.get("reasoning_effort") == "none", body


def test_reasoning_effort_present_on_chat_meta():
    body = {}
    _client_capturing(body).chat_text_meta("sys", "usr")
    assert body.get("reasoning_effort") == "none", body


def test_extra_can_override_reasoning_effort():
    # 필요하면 호출자가 extra 로 덮어쓸 수 있다(끄기 해제 등).
    body = {}
    _client_capturing(body).chat_text_meta("sys", "usr", extra={"reasoning_effort": "high"})
    assert body.get("reasoning_effort") == "high", body


def test_reasoning_effort_none_param_omits_field():
    # 생성자에서 None 으로 주면 필드 자체를 싣지 않는다(기존 동작 보존 경로).
    body = {}
    _client_capturing(body, reasoning_effort=None).chat_text("s", "u")
    assert "reasoning_effort" not in body, body
