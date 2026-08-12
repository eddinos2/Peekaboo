"""Configuration file bootstrap."""

from __future__ import annotations

import json
from pathlib import Path

from peekaboo.config.settings import Settings, default_config_template


def config_path(data_root: Path) -> Path:
    return data_root / "config.json"


def load_settings(data_root: Path) -> Settings:
    """Load config.json, then let env vars and .env override (especially secrets)."""
    path = config_path(data_root)
    if path.exists():
        file_settings = Settings.from_json_file(path)
        env_settings = Settings()
        merged = file_settings.model_dump()
        env_dump = env_settings.model_dump()
        for section, values in env_dump.items():
            if isinstance(values, dict):
                section_merged = merged.get(section, {})
                if not isinstance(section_merged, dict):
                    section_merged = {}
                for key, val in values.items():
                    if val is not None and val != "":
                        section_merged[key] = val
                merged[section] = section_merged
            elif values is not None:
                merged[section] = values
        return Settings.model_validate(merged)
    return Settings()


def write_default_config(data_root: Path) -> Path:
    data_root.mkdir(parents=True, exist_ok=True)
    path = config_path(data_root)
    if not path.exists():
        path.write_text(
            json.dumps(default_config_template(), indent=2),
            encoding="utf-8",
        )
    return path
