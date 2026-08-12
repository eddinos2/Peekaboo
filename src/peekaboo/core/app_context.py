"""Dependency injection bundle."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from peekaboo.config.settings import Settings
from peekaboo.core.progress import ProgressReporter
from peekaboo.llm.registry import ModelRegistry
from peekaboo.persistence.store import PersistenceStore
from peekaboo.platforms.base import Platform
from peekaboo.re.factory import REBackendFactory


@dataclass
class AppContext:
    settings: Settings
    paths: dict[str, Path]
    platform: Platform | None
    models: ModelRegistry
    store: PersistenceStore
    re_factory: REBackendFactory
    progress: ProgressReporter

    @property
    def data_root(self) -> Path:
        return self.paths["data_root"]

    @property
    def temp_dir(self) -> Path:
        return self.paths["temp_dir"]

    @property
    def reports_dir(self) -> Path:
        return self.paths["reports_dir"]
