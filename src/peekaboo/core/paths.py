"""Application directories and path resolution."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from peekaboo.config.settings import Settings


def resolve_data_root(settings: Settings) -> Path:
    env = os.environ.get("PEEKABOO_HOME")
    if env:
        return Path(env).expanduser().resolve()
    if settings.paths.data_root:
        return settings.paths.data_root.expanduser().resolve()
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return (base / "peekaboo").resolve()
    return (Path.home() / ".local" / "share" / "peekaboo").resolve()


def resolve_paths(settings: Settings) -> dict[str, Path]:
    root = resolve_data_root(settings)
    return {
        "data_root": root,
        "db_dir": (settings.paths.db_dir or root / "db").expanduser().resolve(),
        "reports_dir": (settings.paths.reports_dir or root / "reports").expanduser().resolve(),
        "temp_dir": (settings.paths.temp_dir or root / "_temp").expanduser().resolve(),
        "logs_dir": (settings.paths.logs_dir or root / "logs").expanduser().resolve(),
    }


def ensure_dirs(paths: dict[str, Path]) -> None:
    for key, path in paths.items():
        if key != "data_root":
            path.mkdir(parents=True, exist_ok=True)


def resource_path(name: str) -> Path:
    """Locate bundled resources (wheel or dev tree)."""
    pkg = Path(__file__).resolve().parent.parent
    candidates = [
        pkg / "_resources" / name,
        pkg.parent.parent / "resources" / name,
    ]
    for c in candidates:
        if c.exists():
            return c
    return candidates[-1]
