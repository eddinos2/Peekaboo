"""CVE → platform resolution."""

from __future__ import annotations

import asyncio

import structlog

from peekaboo.core.app_context import AppContext
from peekaboo.platforms.base import Platform, PlatformProvider, UnsupportedPlatform, UnknownPlatform
from peekaboo.platforms.ios.provider import IOSProvider
from peekaboo.platforms.linux.provider import LinuxProvider
from peekaboo.platforms.windows.provider import WindowsProvider

log = structlog.get_logger(__name__)


def providers() -> tuple[PlatformProvider, ...]:
    return (IOSProvider(), LinuxProvider(), WindowsProvider())


def provider_by_name(name: str) -> PlatformProvider:
    target = name.lower()
    for p in providers():
        if p.name.lower() == target:
            return p
    raise UnknownPlatform(f"unknown platform {name!r}; registered: {[p.name for p in providers()]}")


async def _native_round(cve_id: str, ctx: AppContext) -> tuple[PlatformProvider, Platform] | None:
    plugins = providers()
    tasks = [asyncio.create_task(p.matches_native(cve_id, ctx)) for p in plugins]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    matched: list[tuple[PlatformProvider, Platform]] = []
    for p, result in zip(plugins, results):
        if isinstance(result, BaseException):
            log.debug("matches_native_error", provider=p.name, error=str(result))
            continue
        if result is None:
            continue
        matched.append((p, result))
    if not matched:
        return None
    if len(matched) > 1:
        log.warning("multiple_providers_native_match", cve=cve_id, matched=[m[0].name for m in matched])
    return matched[0]


def _nvd_round(cve_id: str, ctx: AppContext) -> tuple[PlatformProvider, Platform] | None:
    from peekaboo.platforms.nvd import cpes_for

    cpes = cpes_for(cve_id)
    if not cpes:
        return None
    for p in providers():
        plat = p.matches_nvd(cpes, ctx)
        if plat is not None:
            log.info("nvd_fallback_match", cve=cve_id, provider=p.name)
            return p, plat
    return None


async def resolve_for_cve_async(
    cve_id: str,
    ctx: AppContext,
    *,
    platform_override: str | None = None,
) -> tuple[PlatformProvider, Platform]:
    if platform_override:
        provider = provider_by_name(platform_override)
        plat = await provider.matches_native(cve_id, ctx)
        if plat is not None:
            return provider, plat
        nvd = _nvd_round(cve_id, ctx)
        if nvd and nvd[0] is provider:
            return nvd
        return provider, provider.resolve(ctx)

    native = await _native_round(cve_id, ctx)
    if native:
        return native

    log.info("native_match_missed_falling_back_to_nvd", cve=cve_id)
    nvd = _nvd_round(cve_id, ctx)
    if nvd:
        return nvd

    raise UnsupportedPlatform(
        f"no provider claims {cve_id!r}. Pass --platform ios|linux|windows to force."
    )


def resolve_for_cve(
    cve_id: str,
    ctx: AppContext,
    *,
    platform_override: str | None = None,
) -> tuple[PlatformProvider, Platform]:
    return asyncio.run(resolve_for_cve_async(cve_id, ctx, platform_override=platform_override))
