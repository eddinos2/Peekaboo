"""Build AppContext from settings."""

from __future__ import annotations

from peekaboo.config.settings import Settings
from peekaboo.core.app_context import AppContext
from peekaboo.core.paths import ensure_dirs, resolve_paths
from peekaboo.core.progress import ProgressReporter
from peekaboo.llm.registry import ModelRegistry
from peekaboo.persistence.store import PersistenceStore
from peekaboo.platforms.base import Platform
from peekaboo.re.factory import REBackendFactory


def build_context(
    settings: Settings,
    platform: Platform | None = None,
) -> AppContext:
    paths = resolve_paths(settings)
    ensure_dirs(paths)
    store = PersistenceStore(paths["db_dir"])
    models = ModelRegistry(settings)
    re_factory = REBackendFactory(settings)
    return AppContext(
        settings=settings,
        paths=paths,
        platform=platform,
        models=models,
        store=store,
        re_factory=re_factory,
        progress=ProgressReporter(),
    )
