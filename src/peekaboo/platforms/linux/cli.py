"""Linux CLI commands."""

from __future__ import annotations

import asyncio

import click

from peekaboo.config import load_settings, write_default_config
from peekaboo.config.settings import Settings
from peekaboo.core.bootstrap import build_context
from peekaboo.core.orchestrator import run_cve
from peekaboo.core.paths import resolve_data_root
from peekaboo.platforms.linux.platform import LinuxDistroPlatform


def _settings() -> Settings:
    root = resolve_data_root(Settings())
    write_default_config(root)
    return load_settings(root)


@click.group(name="linux")
def linux_group() -> None:
    """Linux CVE analysis commands."""


@linux_group.command("cve")
@click.argument("cve_id")
@click.option("--pre", "pre_artifacts", type=click.Path(exists=True), default=None)
@click.option("--post", "post_artifacts", type=click.Path(exists=True), default=None)
def linux_cve(
    cve_id: str,
    pre_artifacts: str | None,
    post_artifacts: str | None,
) -> None:
    """Analyze a Linux CVE (Ubuntu 24.04)."""
    settings = _settings()
    platform = LinuxDistroPlatform()
    ctx = build_context(settings, platform=platform)
    result = asyncio.run(
        run_cve(ctx, cve_id.upper(), pre_artifacts=pre_artifacts, post_artifacts=post_artifacts)
    )
    click.echo(f"Reports generated: {len(result.reports)}")


@linux_group.command("health-check")
def linux_health_check() -> None:
    from peekaboo.platforms.linux.provider import LinuxProvider

    settings = _settings()
    ctx = build_context(settings)
    ok, issues = LinuxProvider().health_check(ctx)
    if ok:
        click.echo("Linux health-check: OK")
    else:
        for issue in issues:
            click.echo(f"  - {issue}")
        raise SystemExit(1)
