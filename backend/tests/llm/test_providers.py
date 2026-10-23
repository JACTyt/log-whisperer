import os

import pytest

from log_whisperer.config import Settings
from log_whisperer.llm import ProviderUnavailable, get_provider
from log_whisperer.llm.fake import FakeProvider
from log_whisperer.llm.base import ChatTurn, LLMError


def test_factory_ollama_default():
    p = get_provider(Settings())
    assert (p.name, p.model) == ("ollama", "gemma4:26b-a4b")
    assert get_provider(Settings(), model="gemma4:e4b").model == "gemma4:e4b"


def test_factory_unknown():
    with pytest.raises(ValueError):
        get_provider(Settings(), provider="nope")


def test_anthropic_requires_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    with pytest.raises(ProviderUnavailable, match="ANTHROPIC_API_KEY"):
        get_provider(Settings(), provider="anthropic")


def test_anthropic_default_model(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test")
    assert get_provider(Settings(), provider="anthropic").model == "claude-opus-5-5"


def test_openai_requires_key_and_model(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "test")
    with pytest.raises(ProviderUnavailable, match="openai_model"):
        get_provider(Settings(), provider="openai")
    monkeypatch.delenv("OPENAI_API_KEY")
    with pytest.raises(ProviderUnavailable, match="OPENAI_API_KEY"):
        get_provider(Settings(), provider="openai", model="m")


def test_fake_provider_order():
    f = FakeProvider([{"a": 1}, LLMError("boom")], [ChatTurn(content="hi")])
    assert f.generate_json("s", "u", {}) == {"a": 1}
    with pytest.raises(LLMError):
        f.generate_json("s", "u", {})
    assert f.chat([], []).content == "hi"
    assert len(f.calls) == 3


@pytest.mark.parametrize("text", ['{"a": 1}', '```json\n{"a": 1}\n```', 'Sure! {"a": 1} hope that helps'])
def test_parse_json_object_tolerant(text):
    from log_whisperer.llm.base import parse_json_object

    assert parse_json_object(text) == {"a": 1}


@pytest.mark.parametrize("text", ["", "nope", "[1, 2]", "{broken"])
def test_parse_json_object_errors(text):
    from log_whisperer.llm.base import parse_json_object

    with pytest.raises(LLMError):
        parse_json_object(text)


def test_ollama_unreachable_is_provider_unavailable():
    from log_whisperer.llm.ollama import OllamaProvider

    p = OllamaProvider("x", host="http://127.0.0.1:9", timeout=2)
    with pytest.raises(ProviderUnavailable):
        p.generate_json("s", "u", {"type": "object"})


@pytest.mark.live
def test_live_ollama_json():
    p = get_provider(Settings(), model=os.environ.get("LOGW_TEST_OLLAMA_MODEL", "gemma4:26b-a4b"))
    out = p.generate_json("Reply in JSON.", "Give {\"ok\": true}",
                          {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]})
    assert out["ok"] is True
