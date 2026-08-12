"""iOS CLI commands."""

from __future__ import annotations

import asyncio

import click

from peekaboo.core.bootstrap import build_context
from peekaboo.core.orchestrator import run_cve
from peekaboo.config import load_settings, write_default_config
from peekaboo.core.paths import resolve_data_root
from peekaboo.config.settings import Settings
from peekaboo.platforms.ios.platform import IOSPlatform
from peekaboo.validation.vphone.validate import vphone_status


def _settings() -> Settings:
    root = resolve_data_root(Settings())
    write_default_config(root)
    return load_settings(root)


@click.group(name="ios")
def ios_group() -> None:
    """iOS CVE analysis commands."""


@ios_group.command("cve")
@click.argument("cve_id")
@click.option("--device", default=None, help="Apple device identifier (e.g. iPhone16,1)")
@click.option("--pre", "pre_artifacts", type=click.Path(exists=True), default=None)
@click.option("--post", "post_artifacts", type=click.Path(exists=True), default=None)
@click.option("--skip-vphone", is_flag=True, help="Skip vphone-cli validation stage")
@click.option("--skip-fuzz", is_flag=True, help="Skip targeted fuzz stage")
def ios_cve(
    cve_id: str,
    device: str | None,
    pre_artifacts: str | None,
    post_artifacts: str | None,
    skip_vphone: bool,
    skip_fuzz: bool,
) -> None:
    """Analyze an iOS CVE."""
    settings = _settings()
    platform = IOSPlatform(device=device or settings.ios.default_device)
    ctx = build_context(settings, platform=platform)
    ctx.platform = platform

    result = asyncio.run(
        run_cve(
            ctx,
            cve_id.upper(),
            pre_artifacts=pre_artifacts,
            post_artifacts=post_artifacts,
            skip_vphone=skip_vphone,
            skip_fuzz=skip_fuzz,
        )
    )
    if result.errors:
        for err in result.errors:
            click.echo(f"Error: {err}", err=True)
    click.echo(f"Reports generated: {len(result.reports)}")


@ios_group.command("health-check")
def ios_health_check() -> None:
    """Check iOS-specific prerequisites."""
    from peekaboo.platforms.ios.provider import IOSProvider

    settings = _settings()
    ctx = build_context(settings)
    ok, issues = IOSProvider().health_check(ctx)
    vphone_ok, vphone_issues, vphone_info = asyncio.run(vphone_status(settings.vphone))
    if ok:
        click.echo("iOS health-check: OK")
    else:
        click.echo("iOS health-check: FAILED")
        for issue in issues:
            click.echo(f"  - {issue}")
    if vphone_ok:
        click.echo("vphone-cli: OK (optional dynamic validation)")
    else:
        click.echo("vphone-cli: optional — not ready")
        for line in vphone_info[:2]:
            click.echo(f"  {line}")
        for issue in vphone_issues[:2]:
            click.echo(f"  - {issue}")
    if not ok:
        raise SystemExit(1)
