"""Direct Anthropic provider."""

from __future__ import annotations

from langchain_anthropic import ChatAnthropic

from peekaboo.config.settings import Settings


def build_chat(settings: Settings, model: str, *, temperature: float = 0.0):
    key = settings.anthropic.api_key
    if not key:
        raise RuntimeError("ANTHROPIC__API_KEY not configured")
    return ChatAnthropic(model=model, api_key=key, temperature=temperature)
