"""OpenRouter provider."""

from __future__ import annotations

from langchain_openai import ChatOpenAI, OpenAIEmbeddings

from peekaboo.config.settings import Settings


def build_chat(settings: Settings, model: str, *, temperature: float = 0.0):
    key = settings.openrouter.api_key
    if not key:
        raise RuntimeError("OPENROUTER__API_KEY not configured")
    return ChatOpenAI(
        model=model,
        api_key=key,
        base_url=settings.openrouter.base_url,
        temperature=temperature,
        default_headers={
            "HTTP-Referer": settings.openrouter.site_url or "",
            "X-Title": settings.openrouter.site_name,
        },
    )


def build_embeddings(settings: Settings, model: str):
    key = settings.openrouter.api_key
    if not key:
        raise RuntimeError("OPENROUTER__API_KEY not configured")
    return OpenAIEmbeddings(
        model=model,
        api_key=key,
        base_url=settings.openrouter.base_url,
    )
