"""Provider-neutral LLM interface (DESIGN §9)."""

import json
import re
from dataclasses import dataclass, field
from typing import Any, Literal, Protocol

_FENCE = re.compile(r"^\s*```(?:json)?\s*(.*?)\s*```\s*$", re.S)


class LLMError(Exception):
    """The provider answered, but not with something usable."""


class ProviderUnavailable(LLMError):
    """The provider cannot be reached or is not configured."""


def parse_json_object(text: str | None) -> dict[str, Any]:
    """Parse a JSON object, tolerating markdown fences and prose around it (common with local models)."""
    raw = (text or "").strip()
    if m := _FENCE.match(raw):
        raw = m.group(1)
    try:
        data = json.loads(raw)
    except ValueError:
        start, end = raw.find("{"), raw.rfind("}")
        try:
            data = json.loads(raw[start:end + 1]) if start != -1 and end > start else None
        except ValueError:
            data = None
        if data is None:
            raise LLMError(f"model returned invalid JSON: {raw[:200]!r}") from None
    if not isinstance(data, dict):
        raise LLMError("model returned JSON that is not an object")
    return data


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict[str, Any]  # JSON schema of the arguments object


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class Message:
    role: Literal["system", "user", "assistant", "tool"]
    content: str = ""
    tool_call_id: str | None = None
    tool_name: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: Any = None  # provider-native assistant content, replayed unchanged (e.g. thinking blocks)


@dataclass
class ChatTurn:
    content: str | None
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: Any = None


class LLMProvider(Protocol):
    name: str
    model: str

    def generate_json(self, system: str, user: str, schema: dict[str, Any]) -> dict[str, Any]:
        """One-shot generation constrained to `schema`; returns the parsed object."""
        ...

    def chat(self, messages: list[Message], tools: list[ToolSpec],
             schema: dict[str, Any] | None = None) -> ChatTurn:
        """One assistant turn; may request tool calls. With `schema`, final text is JSON."""
        ...
