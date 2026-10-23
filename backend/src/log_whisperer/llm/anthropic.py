"""Claude via the Anthropic API.

Structured output uses `output_config.format` (forced tool_choice is rejected on current models).
Refusals fall back server-side to another model (`fallbacks: "default"`).
"""

import os
from typing import Any

import anthropic

from log_whisperer.llm.base import (
    ChatTurn, LLMError, Message, ProviderUnavailable, ToolCall, ToolSpec, parse_json_object,
)

FALLBACK_BETA = "server-side-fallback-2026-07-01"


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str = "claude-opus-5-5", effort: str = "medium", max_tokens: int = 16000):
        if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
            raise ProviderUnavailable("ANTHROPIC_API_KEY is not set")
        self.model = model
        self.effort = effort
        self.max_tokens = max_tokens
        self.client = anthropic.Anthropic()

    def _create(self, **kwargs) -> Any:
        try:
            resp = self.client.beta.messages.create(
                model=self.model, max_tokens=self.max_tokens,
                betas=[FALLBACK_BETA], fallbacks="default", **kwargs,
            )
        except anthropic.AuthenticationError as exc:
            raise ProviderUnavailable(f"Anthropic authentication failed: {exc.message}") from exc
        except anthropic.APIConnectionError as exc:
            raise ProviderUnavailable(f"Anthropic API not reachable: {exc}") from exc
        except anthropic.APIStatusError as exc:
            raise LLMError(f"Anthropic API error {exc.status_code}: {exc.message}") from exc
        if resp.stop_reason == "refusal":
            category = getattr(resp.stop_details, "category", None) if resp.stop_details else None
            raise LLMError(f"model declined the request (category={category})")
        if resp.stop_reason == "max_tokens":
            raise LLMError("response truncated at max_tokens")
        return resp

    def generate_json(self, system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
        resp = self._create(
            system=system,
            messages=[{"role": "user", "content": user}],
            output_config={"effort": self.effort, "format": {"type": "json_schema", "schema": schema}},
        )
        return parse_json_object(next((b.text for b in resp.content if b.type == "text"), ""))

    def chat(self, messages: list[Message], tools: list[ToolSpec], schema: dict[str, Any] | None = None) -> ChatTurn:
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        wire: list[dict[str, Any]] = []
        for m in messages:
            if m.role == "system":
                continue
            if m.role == "assistant":
                content = m.raw if m.raw is not None else (
                    [{"type": "text", "text": m.content}] if m.content else []
                ) + [{"type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments} for c in m.tool_calls]
                wire.append({"role": "assistant", "content": content})
            elif m.role == "tool":
                block = {"type": "tool_result", "tool_use_id": m.tool_call_id, "content": m.content}
                # all results of one assistant turn go into a single user message
                if wire and wire[-1]["role"] == "user" and isinstance(wire[-1]["content"], list) \
                        and wire[-1]["content"] and wire[-1]["content"][0].get("type") == "tool_result":
                    wire[-1]["content"].append(block)
                else:
                    wire.append({"role": "user", "content": [block]})
            else:
                wire.append({"role": "user", "content": m.content})
        output_config: dict[str, Any] = {"effort": self.effort}
        if schema is not None:
            output_config["format"] = {"type": "json_schema", "schema": schema}
        resp = self._create(
            system=system or anthropic.NOT_GIVEN,
            messages=wire,
            tools=[{"name": t.name, "description": t.description, "input_schema": t.parameters, "strict": True}
                   for t in tools] or anthropic.NOT_GIVEN,
            output_config=output_config,
        )
        text = "".join(b.text for b in resp.content if b.type == "text") or None
        calls = [ToolCall(id=b.id, name=b.name, arguments=dict(b.input)) for b in resp.content if b.type == "tool_use"]
        raw = [b.model_dump(exclude_none=True) for b in resp.content]
        return ChatTurn(content=text, tool_calls=calls, raw=raw)
