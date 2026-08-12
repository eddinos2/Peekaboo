"""Multi-provider model registry."""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.embeddings import Embeddings

from peekaboo.config.settings import Settings
from peekaboo.llm.catalog import parse_model_ref
from peekaboo.llm.providers import anthropic_direct, openai_direct, openrouter


class ModelRegistry:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._chat_cache: dict[str, BaseChatModel] = {}
        self._embed_cache: dict[str, Embeddings] = {}

    def _resolve_model_id(self, purpose: str) -> str:
        models = self.settings.models
        return getattr(models, purpose, models.default)

    def chat_for(self, purpose: str = "default", *, temperature: float = 0.0) -> BaseChatModel:
        ref = self._resolve_model_id(purpose)
        cache_key = f"{ref}:{temperature}"
        if cache_key in self._chat_cache:
            return self._chat_cache[cache_key]

        provider, model_id = parse_model_ref(ref)
        if provider == "openrouter":
            llm = openrouter.build_chat(self.settings, model_id, temperature=temperature)
        elif provider == "openai":
            llm = openai_direct.build_chat(self.settings, model_id, temperature=temperature)
        elif provider == "anthropic":
            llm = anthropic_direct.build_chat(self.settings, model_id, temperature=temperature)
        else:
            llm = openrouter.build_chat(self.settings, ref, temperature=temperature)

        self._chat_cache[cache_key] = llm
        return llm

    def embeddings(self) -> Embeddings:
        ref = self.settings.models.embedding
        if ref in self._embed_cache:
            return self._embed_cache[ref]
        provider, model_id = parse_model_ref(ref)
        if provider == "openrouter":
            emb = openrouter.build_embeddings(self.settings, model_id)
        elif provider == "openai":
            emb = openai_direct.build_embeddings(self.settings, model_id)
        else:
            emb = openrouter.build_embeddings(self.settings, ref)
        self._embed_cache[ref] = emb
        return emb

    def health_check(self) -> tuple[bool, list[str]]:
        issues: list[str] = []
        if not self.settings.openrouter.api_key and not self.settings.openai.api_key:
            issues.append("No LLM API key: set OPENROUTER__API_KEY or OPENAI__API_KEY")
        return len(issues) == 0, issues
