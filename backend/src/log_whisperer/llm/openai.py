"""OpenAI chat-completions adapter."""

import json
import os
from typing import Any

import openai

from log_whisperer.llm.base import (
    ChatTurn, LLMError, Message, ProviderUnavailable, ToolCall, ToolSpec, parse_json_object,
)


class OpenAIProvider:
    name = "openai"

    def __init__(self, model: str):
        if not os.environ.get("OPENAI_API_KEY"):
            raise ProviderUnavailable("OPENAI_API_KEY is not set")
        self.model = model
        self.client = openai.OpenAI()

    def _create(self, **kwargs) -> Any:
        try:
            return self.client.chat.completions.create(model=self.model, **kwargs)
        except openai.AuthenticationError as exc:
            raise ProviderUnavailable(f"OpenAI authentication failed: {exc}") from exc
        except openai.APIConnectionError as exc:
            raise ProviderUnavailable(f"OpenAI API not reachable: {exc}") from exc
        except openai.APIStatusError as exc:
            raise LLMError(f"OpenAI API error {exc.status_code}: {exc}") from exc

    @staticmethod
    def _format(schema: dict[str, Any]) -> dict[str, Any]:
        return {"type": "json_schema", "json_schema": {"name": "output", "schema": schema, "strict": True}}

    def generate_json(self, system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
        resp = self._create(messages=[{"role": "system", "content": system}, {"role": "user", "content": user}],
                            response_format=self._format(schema))
        return parse_json_object(resp.choices[0].message.content)

    def chat(self, messages: list[Message], tools: list[ToolSpec], schema: dict[str, Any] | None = None) -> ChatTurn:
        wire: list[dict[str, Any]] = []
        for m in messages:
            if m.role == "tool":
                wire.append({"role": "tool", "tool_call_id": m.tool_call_id, "content": m.content})
            elif m.role == "assistant" and m.tool_calls:
                wire.append({"role": "assistant", "content": m.content or None, "tool_calls": [
                    {"id": c.id, "type": "function",
                     "function": {"name": c.name, "arguments": json.dumps(c.arguments)}} for c in m.tool_calls]})
            else:
                wire.append({"role": m.role, "content": m.content})
        kwargs: dict[str, Any] = {"messages": wire}
        if tools:
            kwargs["tools"] = [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                                 "parameters": t.parameters}} for t in tools]
        if schema is not None:
            kwargs["response_format"] = self._format(schema)
        msg = self._create(**kwargs).choices[0].message
        calls = []
        for c in msg.tool_calls or []:
            try:
                args = json.loads(c.function.arguments or "{}")
            except ValueError as exc:
                raise LLMError(f"invalid tool arguments from model: {exc}") from exc
            calls.append(ToolCall(id=c.id, name=c.function.name, arguments=args))
        return ChatTurn(content=msg.content, tool_calls=calls)
