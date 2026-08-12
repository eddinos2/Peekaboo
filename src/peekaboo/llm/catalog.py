"""Model catalog and cost specs."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ModelSpec:
    id: str
    provider: str
    cost_per_mtok_input: float = 0.0
    cost_per_mtok_output: float = 0.0
    supports_embedding: bool = False


def parse_model_ref(ref: str) -> tuple[str, str]:
    """Parse 'openrouter/anthropic/claude-sonnet-4' → ('openrouter', rest)."""
    parts = ref.split("/", 1)
    if len(parts) == 1:
        return "openrouter", parts[0]
    return parts[0], parts[1]


DEFAULT_SPECS: dict[str, ModelSpec] = {
    "openrouter": ModelSpec("openrouter", "openrouter", 3.0, 15.0),
    "openai": ModelSpec("openai", "openai", 2.5, 10.0),
    "anthropic": ModelSpec("anthropic", "anthropic", 3.0, 15.0),
    "azure": ModelSpec("azure", "azure", 2.5, 10.0),
}
