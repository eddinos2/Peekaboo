"""Unit tests for model registry."""

from peekaboo.config.settings import Settings
from peekaboo.llm.catalog import parse_model_ref
from peekaboo.llm.registry import ModelRegistry


def test_parse_model_ref():
    provider, model = parse_model_ref("openrouter/anthropic/claude-sonnet-4")
    assert provider == "openrouter"
    assert "claude" in model


def test_registry_health_no_keys(monkeypatch):
    monkeypatch.setenv("OPENROUTER__API_KEY", "")
    monkeypatch.setenv("OPENAI__API_KEY", "")
    settings = Settings()
    settings.openrouter.api_key = None
    settings.openai.api_key = None
    reg = ModelRegistry(settings)
    ok, issues = reg.health_check()
    assert not ok
