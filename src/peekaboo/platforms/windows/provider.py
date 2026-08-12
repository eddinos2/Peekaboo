"""Windows platform provider scaffold."""

from __future__ import annotations

import re

import click

from peekaboo.core.app_context import AppContext
from peekaboo.platforms.windows.platform import WindowsVersionedPlatform


class WindowsProvider:
    name = "windows"

    def cli_group(self) -> click.Group:
        from peekaboo.platforms.windows.cli import windows_group

        return windows_group

    def health_check(self, ctx: AppContext) -> tuple[bool, list[str]]:
        issues = ["Windows E2E gather requires Windows host — artifacts mode available on macOS"]
        re_ok, re_issues = ctx.re_factory.health_check()
        issues.extend(re_issues)
        return re_ok, issues

    async def matches_native(self, cve_id: str, ctx: AppContext) -> WindowsVersionedPlatform | None:
        return None

    def matches_nvd(self, cpes: list[str], ctx: AppContext) -> WindowsVersionedPlatform | None:
        pattern = re.compile(r"microsoft:windows", re.I)
        if any(pattern.search(c) for c in cpes):
            return WindowsVersionedPlatform()
        return None

    def resolve(self, ctx: AppContext, **overrides) -> WindowsVersionedPlatform:
        return WindowsVersionedPlatform()
