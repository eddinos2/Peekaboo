"""Linux platform provider."""

from __future__ import annotations

import re

import click

from peekaboo.core.app_context import AppContext
from peekaboo.platforms.linux.platform import LinuxDistroPlatform
from peekaboo.platforms.linux.usn import find_ubuntu_advisory


class LinuxProvider:
    name = "linux"

    def cli_group(self) -> click.Group:
        from peekaboo.platforms.linux.cli import linux_group

        return linux_group

    def health_check(self, ctx: AppContext) -> tuple[bool, list[str]]:
        re_ok, re_issues = ctx.re_factory.health_check()
        return re_ok, re_issues

    async def matches_native(self, cve_id: str, ctx: AppContext) -> LinuxDistroPlatform | None:
        advisory = await find_ubuntu_advisory(cve_id)
        if advisory:
            return LinuxDistroPlatform()
        return None

    def matches_nvd(self, cpes: list[str], ctx: AppContext) -> LinuxDistroPlatform | None:
        pattern = re.compile(r"canonical:ubuntu|debian:debian", re.I)
        if any(pattern.search(c) for c in cpes):
            return LinuxDistroPlatform()
        return None

    def resolve(self, ctx: AppContext, **overrides) -> LinuxDistroPlatform:
        return LinuxDistroPlatform()
