"""Resolve iOS builds via ipsw CLI (fallback when AppleDB is slow)."""

from __future__ import annotations

import re

from peekaboo.platforms.ios.appledb import BuildInfo
from peekaboo.tools.process import run


def is_stable_build(build: str) -> bool:
    """Release builds are uppercase alnum; seeds/betas include lowercase."""
    return bool(build) and build.isalnum() and build == build.upper()


def is_stable_ipsw_url(url: str) -> bool:
    """Prefer FCS/restores over SpringSeed/Seed CDN paths."""
    lowered = url.lower()
    return "seed" not in lowered and "beta" not in lowered


async def resolve_ipsw_url(device: str, version: str, *, ipsw_bin: str) -> BuildInfo | None:
    """Use `ipsw download ipsw --urls` to resolve version → build + URL."""
    result = await run(
        ipsw_bin,
        "download",
        "ipsw",
        "--device",
        device,
        "--version",
        version,
        "--urls",
        timeout=120.0,
    )
    url = ""
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.startswith("http") and line.endswith(".ipsw"):
            url = line
            break
    if not url or not is_stable_ipsw_url(url):
        return None

    # iPhone16,1_26.6_23G71_Restore.ipsw
    fname = url.rsplit("/", 1)[-1]
    m = re.match(r".+_([\d.]+)_([A-Za-z0-9]+)_Restore\.ipsw", fname)
    if not m:
        return None
    ver, build = m.group(1), m.group(2)
    if not is_stable_build(build):
        return None
    return BuildInfo(version=ver, build=build, device=device, ipsw_url=url)


def pre_version_candidates(fixed_version: str) -> list[str]:
    """Ordered guesses for the release immediately before fixed_version."""
    parts = fixed_version.split(".")
    if len(parts) < 2:
        return []

    major, minor = int(parts[0]), int(parts[1])
    candidates: list[str] = []

    if len(parts) >= 3:
        patch = int(parts[2])
        for p in range(patch - 1, 0, -1):
            candidates.append(f"{major}.{minor}.{p}")
        if minor > 0:
            prev_minor = minor - 1
            candidates.extend(
                [
                    f"{major}.{prev_minor}.2",
                    f"{major}.{prev_minor}.1",
                    f"{major}.{prev_minor}",
                ]
            )
    elif minor > 0:
        prev_minor = minor - 1
        candidates.extend(
            [
                f"{major}.{prev_minor}.2",
                f"{major}.{prev_minor}.1",
                f"{major}.{prev_minor}",
            ]
        )
    else:
        candidates.append(f"{major - 1}.9")

    seen: set[str] = set()
    ordered: list[str] = []
    for ver in candidates:
        if ver not in seen:
            seen.add(ver)
            ordered.append(ver)
    return ordered


async def resolve_pre_version(fixed_version: str) -> str:
    """Pick immediate prior patch version on same major train."""
    candidates = pre_version_candidates(fixed_version)
    return candidates[0] if candidates else fixed_version
