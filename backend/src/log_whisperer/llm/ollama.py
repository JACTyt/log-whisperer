"""Local models through Ollama (default provider: privacy, no API key)."""

import os
from typing import Any

import httpx
import ollama

from log_whisperer.llm.base import (
    ChatTurn, LLMError, Message, ProviderUnavailable, ToolCall, ToolSpec, parse_json_object,
)


class OllamaProvider:
    name = "ollama"

    def __init__(self, model: str, host: str | None = None, timeout: float = 900):
        self.model = model
        self.host = host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.client = ollama.Client(host=self.host, timeout=timeout)

    def _call(self, **kwargs) -> Any:
        try:
            return self.client.chat(model=self.model, options={"temperature": 0}, **kwargs)
        except ollama.ResponseError as exc:
            if exc.status_code == 404:
                raise ProviderUnavailable(f"Ollama model {self.model!r} not found; run `ollama pull {self.model}`") from exc
            raise LLMError(f"Ollama error: {exc}") from exc
        except (ConnectionError, OSError, httpx.TransportError) as exc:
            raise ProviderUnavailable(f"Ollama not reachable at {self.host}: {exc}") from exc

    def generate_json(self, system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
        resp = self._call(messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                          format=schema)
        return parse_json_object(resp.message.content)

    def chat(self, messages: list[Message], tools: list[ToolSpec], schema: dict[str, Any] | None = None) -> ChatTurn:
        wire = []
        for m in messages:
            msg: dict[str, Any] = {"role": m.role, "content": m.content}
            if m.role == "tool":
                msg["tool_name"] = m.tool_name
            if m.tool_calls:
                msg["tool_calls"] = [{"function": {"name": c.name, "arguments": c.arguments}} for c in m.tool_calls]
            wire.append(msg)
        specs = [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                   "parameters": t.parameters}} for t in tools]
        kwargs: dict[str, Any] = {"messages": wire, "tools": specs}
        if schema is not None:
            kwargs["format"] = schema
        resp = self._call(**kwargs)
        calls = [ToolCall(id=f"call_{i}", name=c.function.name, arguments=dict(c.function.arguments or {}))
                 for i, c in enumerate(resp.message.tool_calls or [])]
        return ChatTurn(content=resp.message.content or None, tool_calls=calls)
