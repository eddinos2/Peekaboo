"""Pydantic settings — config.json + env overrides."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class OpenRouterSettings(BaseSettings):
    api_key: str | None = None
    base_url: str = "https://openrouter.ai/api/v1"
    site_url: str | None = None
    site_name: str = "Peekaboo"


class OpenAISettings(BaseSettings):
    api_key: str | None = None


class AnthropicSettings(BaseSettings):
    api_key: str | None = None


class AzureSettings(BaseSettings):
    endpoint: str | None = None
    tenant_id: str | None = None
    client_id: str | None = None
    client_secret: str | None = None


class ModelMapSettings(BaseSettings):
    default: str = "openrouter/anthropic/claude-sonnet-4"
    gather_info: str = "openrouter/openai/gpt-4.1-mini"
    platform_internals: str = "openrouter/openai/gpt-4.1-mini"
    reverse_engineering: str = "openrouter/openai/o3-mini"
    researcher: str = "openrouter/anthropic/claude-sonnet-4"
    embedding: str = "openrouter/openai/text-embedding-3-small"
    chat: str = "openrouter/anthropic/claude-sonnet-4"


class ToolPathsSettings(BaseSettings):
    ipsw: str | None = None
    ghidra: str | None = None
    ghidra_project_dir: str | None = None
    ida: str | None = None
    bindiff: str | None = None
    seven_zip: str | None = None


class PathSettings(BaseSettings):
    data_root: Path | None = None
    db_dir: Path | None = None
    reports_dir: Path | None = None
    temp_dir: Path | None = None
    logs_dir: Path | None = None


class ConcurrencySettings(BaseSettings):
    cve_workers: int = 4
    kb_downloads: int = 2
    re_workers: int = 4
    llm_eval_parallel: int = 2


class IOSSettings(BaseSettings):
    default_device: str = "iPhone16,1"
    appledb_base_url: str = "https://api.appledb.dev"


class FuzzSettings(BaseSettings):
    """Patch-targeted grammar fuzzing (Peekaboo toolkit)."""

    enabled: bool = True
    max_executions: int = 48
    seed: int = 42768
    save_all: bool = False
    enrich_rca: bool = True
    boost_confidence_max: float = 0.12


class VPhoneSettings(BaseSettings):
    """vphone-cli virtual iPhone lab integration."""

    enabled: bool = True
    cli_path: str | None = None
    library_root: Path | None = None
    variant: Literal["less", "regular", "dev", "jb", "exp"] = "exp"
    vm_prefix: str = "peekaboo"
    ssh_port: int = 22222
    ssh_user: str = "mobile"
    ssh_password: str = "alpine"
    auto_provision: bool = False
    validate_on_pipeline: bool = True
    ipsw_cache_enabled: bool = True


class RESettings(BaseSettings):
    backend: Literal["auto", "ghidra", "ida", "simple"] = "auto"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_nested_delimiter="__",
        env_file=".env",
        extra="ignore",
    )

    openrouter: OpenRouterSettings = Field(default_factory=OpenRouterSettings)
    openai: OpenAISettings = Field(default_factory=OpenAISettings)
    anthropic: AnthropicSettings = Field(default_factory=AnthropicSettings)
    azure: AzureSettings = Field(default_factory=AzureSettings)
    models: ModelMapSettings = Field(default_factory=ModelMapSettings)
    tools: ToolPathsSettings = Field(default_factory=ToolPathsSettings)
    paths: PathSettings = Field(default_factory=PathSettings)
    concurrency: ConcurrencySettings = Field(default_factory=ConcurrencySettings)
    ios: IOSSettings = Field(default_factory=IOSSettings)
    vphone: VPhoneSettings = Field(default_factory=VPhoneSettings)
    fuzz: FuzzSettings = Field(default_factory=FuzzSettings)
    re: RESettings = Field(default_factory=RESettings)

    @classmethod
    def from_json_file(cls, path: Path) -> Settings:
        import json

        if not path.exists():
            return cls()
        data = json.loads(path.read_text(encoding="utf-8"))
        return cls.model_validate(data)

    def to_json_dict(self) -> dict:
        return self.model_dump(mode="json")


def default_config_template() -> dict:
    return Settings().to_json_dict()
