"""DGX Ollama LLM 클라이언트 — 공격/방어 하네스가 공유하는 '연결 수단'.

교수님이 Hermes로 하라던 그 역할(DGX IP:포트에 붙어 모델 선택)을 우리 코드로 흡수한 것.
Hermes 같은 범용 에이전트를 통째로 쓰면 리플레이 기록·검증을 못 하므로, 연결만 직접 한다.

- OpenAI 호환 엔드포인트(/v1/chat/completions) 사용 — base_url=http://<DGX_IP>:11434/v1.
- 모델 선택 = 요청의 model 필드 하나. 공격=탈옥 Qwen / 방어=일반 Qwen, 같은 서버.
- temperature=0 기본(재현성). transport 주입으로 네트워크 없이 테스트.
- 실제 주소·모델명은 config.yaml(gitignore)에서 주입 — 코드엔 안 박음.
"""
from __future__ import annotations

from typing import Callable, Optional

# transport: (method, url, json_body|None, timeout) -> 응답 dict
Transport = Callable[[str, str, Optional[dict], float], dict]


class LLMError(RuntimeError):
    """LLM 호출/응답 오류."""


class LLMTimeout(LLMError):
    """LLM 호출이 제한시간을 넘김. 공격 ReAct 루프는 이걸 '정상 타임아웃'으로 받아
    대본을 보존한 채 턴을 끝낸다(장애 아님 — 설계 의도)."""


def requests_transport(api_key: str = "") -> Transport:
    """기본 전송 — requests. requests는 지연 import(미설치 시 호출 때만 에러)."""
    def _t(method: str, url: str, body: Optional[dict], timeout: float) -> dict:
        import requests
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        try:
            r = requests.request(method, url, json=body, headers=headers, timeout=timeout)
        except requests.exceptions.Timeout as e:   # 연결/읽기 타임아웃 → 전용 예외로
            raise LLMTimeout(f"LLM 호출 타임아웃({timeout}s): {url}") from e
        r.raise_for_status()
        return r.json()
    return _t


class OllamaClient:
    """DGX의 Ollama(OpenAI 호환)에 붙는 얇은 클라이언트. 하네스가 머리로 호출."""

    def __init__(self, base_url: str, model: str, *, api_key: str = "",
                 temperature: float = 0.0, timeout: float = 120.0,
                 max_tokens: Optional[int] = None,
                 transport: Optional[Transport] = None) -> None:
        self.base_url = base_url.rstrip("/")     # 예: http://211.x.x.x:11434/v1
        self.model = model
        self.temperature = temperature
        self.timeout = timeout
        self.max_tokens = max_tokens             # 생성 상한(호출마다 override 가능, 없으면 이 기본값)
        self.transport = transport or requests_transport(api_key)

    def chat(self, messages: list[dict], *, temperature: Optional[float] = None,
             max_tokens: Optional[int] = None, stop: Optional[list[str]] = None,
             extra: Optional[dict] = None, timeout: Optional[float] = None) -> str:
        """messages(OpenAI 형식) → assistant 응답 텍스트. stream 안 씀(결과를 한 번에).

        timeout: 이 호출만의 상한(초). 없으면 생성자 self.timeout. 공격 ReAct 루프가
        '남은 턴 예산'을 넘겨, 단일 호출이 예산을 넘기지 않게 한다.
        """
        body: dict = {
            "model": self.model,
            "messages": messages,
            "temperature": self.temperature if temperature is None else temperature,
            "stream": False,
        }
        eff_max = max_tokens if max_tokens is not None else self.max_tokens
        if eff_max is not None:
            body["max_tokens"] = eff_max
        if stop is not None:
            body["stop"] = stop
        if extra:
            body.update(extra)
        data = self.transport("POST", f"{self.base_url}/chat/completions", body,
                              self.timeout if timeout is None else timeout)
        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"예상치 못한 chat 응답 형식: {data!r}") from e

    def chat_text(self, system: str, user: str, **kw) -> str:
        """system+user 한 쌍 편의 호출."""
        return self.chat([{"role": "system", "content": system},
                          {"role": "user", "content": user}], **kw)

    def list_models(self) -> list[str]:
        """엔드포인트에 올라간 모델 이름 목록(/v1/models). DGX 연결·모델 확인용."""
        data = self.transport("GET", f"{self.base_url}/models", None, self.timeout)
        try:
            return [m["id"] for m in data.get("data", [])]
        except (KeyError, TypeError) as e:
            raise LLMError(f"예상치 못한 models 응답 형식: {data!r}") from e


__all__ = ["Transport", "LLMError", "LLMTimeout", "requests_transport", "OllamaClient"]
