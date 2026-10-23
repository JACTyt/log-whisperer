"""Scripted provider for deterministic offline tests."""

from typing import Any

from log_whisperer.llm.base import ChatTurn, LLMError, Message, ToolSpec


class FakeProvider:
    name = "fake"

    def __init__(self, json_responses: list[Any] | None = None, chat_turns: list[ChatTurn] | None = None,
                 model: str = "fake-model"):
        self.model = model
        self.json_responses = list(json_responses or [])
        self.chat_turns = list(chat_turns or [])
        self.calls: list[tuple[str, Any]] = []

    def generate_json(self, system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("generate_json", {"system": system, "user": user, "schema": schema}))
        if not self.json_responses:
            raise LLMError("FakeProvider: no scripted JSON response left")
        resp = self.json_responses.pop(0)
        if isinstance(resp, Exception):
            raise resp
        return resp

    def chat(self, messages: list[Message], tools: list[ToolSpec], schema: dict[str, Any] | None = None) -> ChatTurn:
        self.calls.append(("chat", {"messages": list(messages), "tools": tools, "schema": schema}))
        if not self.chat_turns:
            raise LLMError("FakeProvider: no scripted chat turn left")
        return self.chat_turns.pop(0)
