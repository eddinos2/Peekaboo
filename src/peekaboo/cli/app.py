"""Main CLI entry point."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import click
from dotenv import load_dotenv

from peekaboo.config import load_settings, write_default_config
from peekaboo.config.settings import Settings
from peekaboo.core.bootstrap import build_context
from peekaboo.core.logging import setup_logging
from peekaboo.core.orchestrator import run_cve
from peekaboo.core.paths import resolve_data_root
from peekaboo.core.report_compare import compare_reports
from peekaboo.platforms.resolver import provider_by_name, resolve_for_cve_async
from peekaboo.cli.vphone import vphone_group
from peekaboo.cli.fuzz import fuzz_group
from peekaboo.validation.vphone.validate import vphone_status


@click.group()
@click.option("-L", "--log-level", default="info", help="Log level: debug, info, warning")
@click.pass_context
def main(ctx: click.Context, log_level: str) -> None:
    """Peekaboo — poly-platform CVE patch-diff analyzer."""
    # Load project .env if present (does not override existing env vars)
    load_dotenv(Path.cwd() / ".env")
    root = resolve_data_root(Settings())
    write_default_config(root)
    settings = load_settings(root)
    paths = {"data_root": root, "logs_dir": root / "logs"}
    (root / "logs").mkdir(parents=True, exist_ok=True)
    setup_logging(root / "logs", log_level)
    ctx.ensure_object(dict)
    ctx.obj["settings"] = settings
    ctx.obj["data_root"] = root


@main.command("init")
@click.pass_context
def init_cmd(ctx: click.Context) -> None:
    """Write default config.json to data root."""
    root = ctx.obj["data_root"]
    path = write_default_config(root)
    click.echo(f"Config written to {path}")


@main.command("health-check")
@click.pass_context
def health_check_cmd(ctx: click.Context) -> None:
    """Validate prerequisites."""
    settings = ctx.obj["settings"]
    ctx_app = build_context(settings)
    ok, issues = ctx_app.models.health_check()
    re_ok, re_issues = ctx_app.re_factory.health_check()
    all_ok = ok and re_ok
    if ok:
        click.echo("LLM: OK")
    else:
        click.echo("LLM: FAILED")
        for i in issues:
            click.echo(f"  - {i}")
    if re_ok:
        click.echo(f"RE backend ({ctx_app.re_factory.resolve().name}): OK")
    else:
        click.echo("RE backend: FAILED")
        for i in re_issues:
            click.echo(f"  - {i}")
    vphone_ok, vphone_issues, _ = asyncio.run(vphone_status(settings.vphone))
    if vphone_ok:
        click.echo("vphone-cli: OK")
    else:
        click.echo("vphone-cli: optional — not ready (peekaboo vphone setup)")
        for i in vphone_issues[:2]:
            click.echo(f"  - {i}")
    if not all_ok:
        raise SystemExit(1)


@main.command("cve")
@click.argument("cve_id")
@click.option("--platform", "platform_name", default=None, help="Force platform: ios, linux, windows")
@click.option("--pre", "pre_artifacts", type=click.Path(exists=True), default=None)
@click.option("--post", "post_artifacts", type=click.Path(exists=True), default=None)
@click.pass_context
def cve_cmd(
    ctx: click.Context,
    cve_id: str,
    platform_name: str | None,
    pre_artifacts: str | None,
    post_artifacts: str | None,
) -> None:
    """Analyze a CVE (auto-detect platform)."""
    settings = ctx.obj["settings"]
    ctx_app = build_context(settings)
    provider, platform = asyncio.run(
        resolve_for_cve_async(cve_id.upper(), ctx_app, platform_override=platform_name)
    )
    ctx_app.platform = platform
    click.echo(f"Platform: {provider.name} / {platform.name}")
    result = asyncio.run(
        run_cve(ctx_app, cve_id.upper(), pre_artifacts=pre_artifacts, post_artifacts=post_artifacts)
    )
    click.echo(f"Reports: {len(result.reports)} | Errors: {len(result.errors)}")
    for r in result.reports:
        _print_report_summary(r)
    for err in result.errors:
        click.echo(f"  Error: {err}", err=True)


@main.command("artifacts")
@click.argument("cve_id")
@click.option("--platform", required=True, type=click.Choice(["ios", "linux", "windows"]))
@click.option("--pre", required=True, type=click.Path(exists=True))
@click.option("--post", required=True, type=click.Path(exists=True))
@click.pass_context
def artifacts_cmd(
    ctx: click.Context,
    cve_id: str,
    platform: str,
    pre: str,
    post: str,
) -> None:
    """Analyze CVE from local pre/post artifact directories."""
    settings = ctx.obj["settings"]
    ctx_app = build_context(settings)
    provider = provider_by_name(platform)
    plat = provider.resolve(ctx_app)
    ctx_app.platform = plat
    result = asyncio.run(run_cve(ctx_app, cve_id.upper(), pre_artifacts=pre, post_artifacts=post))
    click.echo(f"Reports: {len(result.reports)}")
    for r in result.reports:
        _print_report_summary(r)


def _print_report_summary(r) -> None:
    from peekaboo.schemas import Report

    if not isinstance(r, Report):
        return
    if r.export_path:
        click.echo(f"  Export pack: {r.export_path}")
        click.echo(f"  Cinema: file://{r.export_path}/cinema.html")
    if r.poc:
        click.echo(f"  PoC: {r.poc.title} (conf={r.poc.poc_confidence:.2f})")
    click.echo(f"  Confidence: {r.confidence:.2f} | review={'yes' if r.confidence_breakdown.human_review_recommended else 'no'}")


@main.command("cached")
@click.option("--cve", default=None)
@click.pass_context
def cached_cmd(ctx: click.Context, cve: str | None) -> None:
    """List cached reports."""
    settings = ctx.obj["settings"]
    ctx_app = build_context(settings)
    reports = ctx_app.store.list_reports(cve)
    for r in reports:
        click.echo(f"{r.cve} | {r.file_name} | conf={r.confidence:.2f}")


@main.command("export")
@click.option("--cve", required=True, help="CVE ID to export")
@click.option("--output", "-o", type=click.Path(), default=None, help="Output directory")
@click.pass_context
def export_cmd(ctx: click.Context, cve: str, output: str | None) -> None:
    """Export cinema HTML + PoC pack for a cached report."""
    from peekaboo.export.pack import export_pack

    settings = ctx.obj["settings"]
    ctx_app = build_context(settings)
    reports = ctx_app.store.list_reports(cve.upper())
    if not reports:
        click.echo(f"No cached reports for {cve}", err=True)
        raise SystemExit(1)

    dest = Path(output) if output else ctx_app.reports_dir / "exports"
    for report in reports:
        out = export_pack(dest, report, poc=report.poc)
        click.echo(f"Exported: {out}")
        click.echo(f"  cinema.html, report.md, poc/ (if available)")


@main.command("compare-reports")
@click.argument("report_a", type=click.Path(exists=True))
@click.argument("report_b", type=click.Path(exists=True))
def compare_reports_cmd(report_a: str, report_b: str) -> None:
    """Compare two saved report JSON files."""
    from peekaboo.schemas import Report

    a = Report.model_validate(json.loads(open(report_a).read()))
    b = Report.model_validate(json.loads(open(report_b).read()))
    click.echo(compare_reports(a, b))


def _register_platform_groups() -> None:
    from peekaboo.platforms.resolver import providers

    for p in providers():
        main.add_command(p.cli_group())


_register_platform_groups()
main.add_command(vphone_group)
main.add_command(fuzz_group)
