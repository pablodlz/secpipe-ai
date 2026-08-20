"""Providers CONCRETOS do AIProviderPort via urllib (stdlib, SEM SDK) — para o modo headless (ÚNICA exceção
com chave, opt-in). Anthropic Messages API e OpenAI-compatible (base_url configurável => OpenAI/vLLM/Ollama/
LM Studio/llama.cpp; modelo LOCAL = grátis, zero egress externo).

SEGURANÇA: chave lida SÓ de env; nunca em __repr__, nunca em URL/query, redigida em erro; só https (http só
localhost). Sem dep nova. urlopen: S310/B310 ignorados a nível de PROJETO (URL validada, sem dado do repo)."""
from __future__ import annotations

import http.client
import json
import os
import ssl
import urllib.error
import urllib.request
from collections.abc import Mapping

from secpipe.adapters._http import open_no_redirect, scheme_ok

_ANTHROPIC_URL = "https://api.anthropic.com/v1/messages"
_ANTHROPIC_VERSION = "2023-06-01"


def _post(url: str, payload: Mapping[str, object], headers: Mapping[str, str], timeout: int) -> dict[str, object]:
    if not scheme_ok(url):   # https; http só localhost (por hostname, não prefixo)
        raise ValueError("apenas https (http so em localhost)")
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", **headers})
    ctx = ssl.create_default_context()
    try:
        with open_no_redirect(req, timeout=timeout, context=ctx) as resp:   # não segue redirect (não vaza a chave)
            data = json.loads(resp.read(5_000_000).decode("utf-8", "replace"))
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code} do provedor de IA") from None  # sem corpo/headers (evita vazar)
    except (urllib.error.URLError, TimeoutError, ValueError, http.client.HTTPException) as exc:
        raise RuntimeError(f"falha de rede/parse: {type(exc).__name__}") from None
    if not isinstance(data, dict):
        raise RuntimeError("resposta de IA inesperada")
    return data


class AnthropicProvider:
    """Anthropic Messages API. Chave em ANTHROPIC_API_KEY ou SECPIPE_AI_API_KEY (SÓ env)."""
    name = "anthropic"

    def __init__(self, *, model: str = "claude-sonnet-4-5", timeout: int = 60) -> None:
        self.model = model
        self.timeout = timeout

    def _key(self) -> str:
        return os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("SECPIPE_AI_API_KEY") or ""

    def available(self) -> bool:
        return bool(self._key())

    def complete(self, prompt: str) -> str:
        payload = {"model": self.model, "max_tokens": 2048,
                   "messages": [{"role": "user", "content": prompt}]}
        headers = {"x-api-key": self._key(), "anthropic-version": _ANTHROPIC_VERSION}
        data = _post(_ANTHROPIC_URL, payload, headers, self.timeout)
        content = data.get("content")
        if isinstance(content, list) and content and isinstance(content[0], dict):
            return str(content[0].get("text", ""))
        return ""

    def __repr__(self) -> str:
        return f"AnthropicProvider(model={self.model!r})"  # NUNCA a chave


class OpenAICompatibleProvider:
    """OpenAI-compatible /chat/completions (base_url configurável => OpenAI, ou LOCAL Ollama/vLLM/etc)."""
    name = "openai"

    def __init__(self, *, base_url: str = "https://api.openai.com/v1", model: str = "gpt-4o-mini",
                 timeout: int = 60) -> None:
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def _key(self) -> str:
        return os.environ.get("OPENAI_API_KEY") or os.environ.get("SECPIPE_AI_API_KEY") or ""

    def available(self) -> bool:
        # local (Ollama/llama.cpp) costuma não exigir chave -> disponível se o base_url é local
        return bool(self._key()) or self.base_url.startswith(("http://localhost", "http://127.0.0.1"))

    def complete(self, prompt: str) -> str:
        payload = {"model": self.model, "messages": [{"role": "user", "content": prompt}]}
        headers = {"Authorization": f"Bearer {self._key()}"} if self._key() else {}
        data = _post(f"{self.base_url}/chat/completions", payload, headers, self.timeout)
        choices = data.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            msg = choices[0].get("message")
            if isinstance(msg, dict):
                return str(msg.get("content", ""))
        return ""

    def __repr__(self) -> str:
        return f"OpenAICompatibleProvider(base_url={self.base_url!r}, model={self.model!r})"  # NUNCA a chave
