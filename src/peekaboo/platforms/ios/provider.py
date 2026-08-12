"""iOS platform provider."""

from __future__ import annotations

import re

import click

from peekaboo.core.app_context import AppContext
from peekaboo.platforms.ios.advisory import find_advisory_for_cve
from peekaboo.platforms.ios.ipsw_tools import resolve_ipsw_bin
from peekaboo.platforms.ios.platform import IOSPlatform
class IOSProvider:
    name = "ios"

    def cli_group(self) -> click.Group:
        from peekaboo.platforms.ios.cli import ios_group

        return ios_group

    def health_check(self, ctx: AppContext) -> tuple[bool, list[str]]:
        issues: list[str] = []
        try:
            resolve_ipsw_bin(ctx.settings.tools.ipsw)
        except RuntimeError as exc:
            issues.append(str(exc))
        re_ok, re_issues = ctx.re_factory.health_check()
        issues.extend(re_issues)
        return len(issues) == 0 and re_ok, issues

    async def matches_native(self, cve_id: str, ctx: AppContext) -> IOSPlatform | None:
        advisory = await find_advisory_for_cve(cve_id)
        if advisory:
            return IOSPlatform(device=ctx.settings.ios.default_device)
        return None

    def matches_nvd(self, cpes: list[str], ctx: AppContext) -> IOSPlatform | None:
        pattern = re.compile(r"apple:(iphone_os|ipados)", re.I)
        if any(pattern.search(c) for c in cpes):
            return IOSPlatform(device=ctx.settings.ios.default_device)
        return None

    def resolve(self, ctx: AppContext, **overrides) -> IOSPlatform:
        device = overrides.get("device") or ctx.settings.ios.default_device
        return IOSPlatform(device=device)
