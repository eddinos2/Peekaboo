"""Reuse IPSW files from vphone-cli cache (~/.vphone/ipsws)."""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from peekaboo.config.settings import VPhoneSettings
from peekaboo.validation.vphone.client import vphone_ipsw_cache_dir


def find_cached_ipsw(
    build: str,
    device: str | None,
    settings: VPhoneSettings,
) -> Path | None:
    """Locate a completed .ipsw in vphone cache matching build (+ optional device)."""
    cache = vphone_ipsw_cache_dir(settings)
    if not cache.exists():
        return None

    build_upper = build.upper()
    device_token = (device or "").replace(",", "_")

    candidates: list[Path] = []
    for path in cache.rglob("*.ipsw"):
        if not path.is_file():
            continue
        name = path.name
        if build_upper not in name.upper():
            continue
        if device and device.replace(",", ", ") not in name and device_token not in name:
            # vphone often uses iPhone17,3 — allow build-only match as fallback
            if not re.search(rf"_{re.escape(build_upper)}_", name, re.I):
                continue
        candidates.append(path)

    if not candidates:
        # Build-only fallback (vphone tested env uses 17,3 not 16,1)
        for path in cache.rglob("*.ipsw"):
            if path.is_file() and build_upper in path.name.upper():
                candidates.append(path)

    if not candidates:
        return None
    return max(candidates, key=lambda p: p.stat().st_size)


def materialize_ipsw(
    cached: Path,
    dest_dir: Path,
    *,
    build: str,
) -> Path:
    """Copy or symlink cached IPSW into Peekaboo work dir."""
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / cached.name
    if dest.exists() or dest.is_symlink():
        return dest
    try:
        dest.symlink_to(cached)
    except OSError:
        shutil.copy2(cached, dest)
    return dest
