"""Windows CLI commands."""

from __future__ import annotations

import asyncio

import click

from peekaboo.config import load_settings, write_default_config
from peekaboo.config.settings import Settings
from peekaboo.core.bootstrap import build_context
from peekaboo.core.orchestrator import run_cve
from peekaboo.core.paths import resolve_data_root
from peekaboo.platforms.windows.platform import WindowsVersionedPlatform


def _settings() -> Settings:
    root = resolve_data_root(Settings())
    write_default_config(root)
    return load_settings(root)


@click.group(name="windows")
def windows_group() -> None:
    """Windows CVE analysis commands (scaffold)."""


@windows_group.command("cve")
@click.argument("cve_id")
@click.option("--pre", "pre_artifacts", type=click.Path(exists=True), default=None)
@click.option("--post", "post_artifacts", type=click.Path(exists=True), default=None)
def windows_cve(
    cve_id: str,
    pre_artifacts: str | None,
    post_artifacts: str | None,
) -> None:
    """Analyze a Windows CVE (artifacts mode on macOS)."""
    settings = _settings()
    platform = WindowsVersionedPlatform()
    ctx = build_context(settings, platform=platform)
    result = asyncio.run(
        run_cve(ctx, cve_id.upper(), pre_artifacts=pre_artifacts, post_artifacts=post_artifacts)
    )
    click.echo(f"Reports generated: {len(result.reports)}")


@windows_group.command("health-check")
def windows_health_check() -> None:
    from peekaboo.platforms.windows.provider import WindowsProvider

    settings = _settings()
    ctx = build_context(settings)
    ok, issues = WindowsProvider().health_check(ctx)
    click.echo("Windows health-check (scaffold):")
    for issue in issues:
        click.echo(f"  - {issue}")
    if not ok:
        raise SystemExit(1)
