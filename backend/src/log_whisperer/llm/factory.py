from log_whisperer.config import Settings
from log_whisperer.llm.base import LLMProvider, ProviderUnavailable

PROVIDERS = ("ollama", "anthropic", "openai")


def get_provider(settings: Settings, provider: str | None = None, model: str | None = None) -> LLMProvider:
    cfg = settings.llm
    name = provider or cfg.provider
    if name == "ollama":
        from log_whisperer.llm.ollama import OllamaProvider

        return OllamaProvider(model or cfg.model or cfg.ollama_model)
    if name == "anthropic":
        from log_whisperer.llm.anthropic import AnthropicProvider

        return AnthropicProvider(model or cfg.anthropic_model, effort=cfg.anthropic_effort)
    if name == "openai":
        from log_whisperer.llm.openai import OpenAIProvider

        chosen = model or cfg.openai_model
        if not chosen:
            raise ProviderUnavailable("no OpenAI model configured; set [llm] openai_model or pass --model")
        return OpenAIProvider(chosen)
    if name == "fake":
        from log_whisperer.llm.fake import FakeProvider

        return FakeProvider()
    raise ValueError(f"unknown provider {name!r}; choose from {', '.join(PROVIDERS)}")
