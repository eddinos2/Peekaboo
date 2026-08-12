"""AppleDB API client."""

from __future__ import annotations

from dataclasses import dataclass

import httpx


@dataclass
class BuildInfo:
    version: str
    build: str
    device: str
    ipsw_url: str


async def fetch_build_info(
    version: str,
    device: str,
    *,
    base_url: str = "https://api.appledb.dev",
    ipsw_bin: str | None = None,
) -> BuildInfo | None:
    """Resolve iOS version string to build + IPSW URL via AppleDB, ipsw CLI fallback."""
    if ipsw_bin:
        from peekaboo.platforms.ios.ipsw_resolve import resolve_ipsw_url

        ipsw_result = await resolve_ipsw_url(device, version, ipsw_bin=ipsw_bin)
        if ipsw_result:
            return ipsw_result

    async with httpx.AsyncClient(timeout=180.0) as client:
        index_resp = await client.get(f"{base_url}/ios/iOS/main.json")
        if index_resp.status_code != 200:
            return None
        builds = index_resp.json()
        matching = [b for b in builds if version in str(b.get("version", ""))]
        if not matching:
            matching = [b for b in builds if version.split(".")[0] in str(b.get("version", ""))]
        for entry in reversed(matching):
            build = entry.get("build") or entry.get("buildID")
            if not build:
                continue
            detail_resp = await client.get(f"{base_url}/ios/iOS;{build}.json")
            if detail_resp.status_code != 200:
                continue
            detail = detail_resp.json()
            url = _ipsw_url_for_device(detail, device)
            if url:
                return BuildInfo(version=version, build=build, device=device, ipsw_url=url)
    return None


async def fetch_previous_build(
    current_build: str,
    device: str,
    *,
    base_url: str = "https://api.appledb.dev",
) -> BuildInfo | None:
    from peekaboo.platforms.ios.ipsw_resolve import is_stable_build, is_stable_ipsw_url

    async with httpx.AsyncClient(timeout=60.0) as client:
        index_resp = await client.get(f"{base_url}/ios/iOS/main.json")
        if index_resp.status_code != 200:
            return None
        builds = index_resp.json()
        build_ids = [b.get("build") or b.get("buildID") for b in builds]
        build_ids = [b for b in build_ids if b]
        if current_build not in build_ids:
            return None
        idx = build_ids.index(current_build)
        for prev_build in reversed(build_ids[:idx]):
            if not is_stable_build(prev_build):
                continue
            detail_resp = await client.get(f"{base_url}/ios/iOS;{prev_build}.json")
            if detail_resp.status_code != 200:
                continue
            detail = detail_resp.json()
            url = _ipsw_url_for_device(detail, device)
            version = detail.get("version", "")
            if url and is_stable_ipsw_url(url):
                return BuildInfo(version=version, build=prev_build, device=device, ipsw_url=url)
    return None


def _ipsw_url_for_device(detail: dict, device: str) -> str | None:
    for src in detail.get("sources", []):
        if device in (src.get("deviceMap") or []):
            for link in src.get("links") or []:
                url = link.get("url", "")
                if url.endswith(".ipsw"):
                    return url
    for src in detail.get("sources", []):
        for link in src.get("links") or []:
            url = link.get("url", "")
            if url.endswith(".ipsw"):
                return url
    return None
