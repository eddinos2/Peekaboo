"""vphone-cli CLI commands."""

from __future__ import annotations

import asyncio
import subprocess
from pathlib import Path

import click

from peekaboo.config import load_settings, write_default_config
from peekaboo.config.settings import Settings
from peekaboo.core.bootstrap import build_context
from peekaboo.core.paths import resolve_data_root
from peekaboo.validation.vphone.client import VPhoneClient, resolve_vphone_bin, vphone_library_root
from peekaboo.validation.vphone.provision import provision_cve_vms
from peekaboo.validation.vphone.validate import run_vphone_validation, vphone_status


def _settings() -> Settings:
    root = resolve_data_root(Settings())
    write_default_config(root)
    return load_settings(root)


@click.group(name="vphone")
def vphone_group() -> None:
    """vphone-cli virtual iPhone lab integration."""


@vphone_group.command("status")
def vphone_status_cmd() -> None:
    """Check vphone-cli installation and Peekaboo lab state."""
    settings = _settings()
    ok, issues, info = asyncio.run(vphone_status(settings.vphone))
    for line in info:
        click.echo(line)
    if ok:
        click.echo("vphone-cli: OK")
    else:
        click.echo("vphone-cli: NOT READY")
        for issue in issues:
            click.echo(f"  - {issue}")
        raise SystemExit(1)


@vphone_group.command("setup")
@click.option("--build/--no-build", default=True, help="Clone and build vphone-cli if missing")
@click.option("--tap-brew/--no-tap-brew", default=True, help="Try brew tap zqxwce/tap first")
def vphone_setup_cmd(build: bool, tap_brew: bool) -> None:
    """Install vphone-cli dependencies and build the binary."""
    lib = vphone_library_root(Settings().vphone)
    lib.mkdir(parents=True, exist_ok=True)
    build_dir = lib / "build"

    if tap_brew:
        click.echo("Trying Homebrew tap zqxwce/tap …")
        subprocess.run(["brew", "tap", "zqxwce/tap"], check=False)
        r = subprocess.run(["brew", "install", "zqxwce/tap/vphone-cli"], check=False)
        if r.returncode == 0:
            click.echo(f"Installed via brew: {resolve_vphone_bin(None)}")
            click.echo("Next: configure SIP/AMFI (see vphone-cli README), then: peekaboo vphone provision")
            return

    if not build:
        click.echo("Install manually: https://github.com/Lakr233/vphone-cli")
        raise SystemExit(1)

    repo = build_dir / "vphone-cli"
    if not repo.exists():
        click.echo("Cloning vphone-cli …")
        subprocess.run(
            [
                "git",
                "clone",
                "--recurse-submodules",
                "https://github.com/Lakr233/vphone-cli.git",
                str(repo),
            ],
            check=True,
        )

    click.echo("Running setup_tools.sh + build.sh (may take several minutes) …")
    subprocess.run(["./scripts/setup_tools.sh"], cwd=repo, check=True)
    subprocess.run(["./scripts/build.sh"], cwd=repo, check=True)

    app_bin = repo / ".build" / "vphone-cli.app" / "Contents" / "MacOS" / "vphone-cli"
    if app_bin.exists():
        dest = lib / "vphone-cli"
        if dest.exists() or dest.is_symlink():
            dest.unlink()
        dest.symlink_to(app_bin)
        click.echo(f"Built: {dest}")
    click.echo("")
    click.echo("Host prerequisites (one-time):")
    click.echo("  1. Recovery: csrutil disable && csrutil allow-research-guests enable")
    click.echo("  2. macOS: sudo nvram boot-args=\"amfi_get_out_of_my_way=1 -v\" && reboot")
    click.echo("  3. peekaboo vphone provision --cve CVE-2026-43818")


@vphone_group.command("provision")
@click.option("--cve", required=True, help="CVE to provision pre/post VMs for")
@click.option("--device", default=None, help="iOS device identifier")
@click.option("--variant", default=None, type=click.Choice(["less", "regular", "dev", "jb", "exp"]))
@click.pass_context
def vphone_provision_cmd(ctx: click.Context, cve: str, device: str | None, variant: str | None) -> None:
    """Create peekaboo pre/post vphone VMs for a CVE build pair (long-running)."""
    settings = _settings()
    if variant:
        settings = settings.model_copy(
            update={"vphone": settings.vphone.model_copy(update={"variant": variant, "auto_provision": True})}
        )
    else:
        settings = settings.model_copy(
            update={"vphone": settings.vphone.model_copy(update={"auto_provision": True})}
        )

    from peekaboo.platforms.ios.platform import IOSPlatform

    platform = IOSPlatform(device=device or settings.ios.default_device)
    ctx_app = build_context(settings, platform=platform)
    ctx_app.platform = platform

    async def _run() -> None:
        from peekaboo.schemas import CveDetails, PipelineState

        state = PipelineState(cve_details=CveDetails(cve=cve.upper(), platform="ios"))
        enriched = await platform.enrich_cve(state, ctx_app)
        details = enriched["cve_details"]
        client = VPhoneClient(settings.vphone)
        vm_pre, vm_post, notes = await provision_cve_vms(client, details, settings.vphone)
        click.echo(f"Pre VM:  {vm_pre}")
        click.echo(f"Post VM: {vm_post}")
        for note in notes:
            click.echo(f"  {note}")

    asyncio.run(_run())


@vphone_group.command("validate")
@click.option("--cve", required=True)
@click.pass_context
def vphone_validate_cmd(ctx: click.Context, cve: str) -> None:
    """Run vphone dynamic validation against cached Peekaboo report."""
    settings = _settings()
    ctx_app = build_context(settings)
    reports = ctx_app.store.list_reports(cve.upper())
    if not reports:
        click.echo(f"No cached report for {cve}", err=True)
        raise SystemExit(1)
    report = reports[0]

    async def _run():
        from peekaboo.schemas import CveDetails

        details = CveDetails(cve=report.cve, platform=report.platform)
        cached = ctx_app.store.get_cached_report(cve.upper())
        if cached and cached.metadata.get("cve_details"):
            details = CveDetails.model_validate(cached.metadata["cve_details"])
        return await run_vphone_validation(ctx_app, details, report, report.poc)

    result = asyncio.run(_run())
    click.echo(f"Status: {result.status}")
    for note in result.notes:
        click.echo(f"  {note}")
