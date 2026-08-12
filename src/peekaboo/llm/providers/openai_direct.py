"""Direct OpenAI provider."""

from __future__ import annotations

from langchain_openai import ChatOpenAI, OpenAIEmbeddings

from peekaboo.config.settings import Settings


def build_chat(settings: Settings, model: str, *, temperature: float = 0.0):
    key = settings.openai.api_key
    if not key:
        raise RuntimeError("OPENAI__API_KEY not configured")
    return ChatOpenAI(model=model, api_key=key, temperature=temperature)


def build_embeddings(settings: Settings, model: str):
    key = settings.openai.api_key
    if not key:
        raise RuntimeError("OPENAI__API_KEY not configured")
    return OpenAIEmbeddings(model=model, api_key=key)
