"""Standalone fuzz CLI commands."""

from __future__ import annotations

import asyncio

import click

from peekaboo.config import load_settings, write_default_config
from peekaboo.config.settings import Settings
from peekaboo.core.bootstrap import build_context
from peekaboo.core.paths import resolve_data_root
from peekaboo.fuzz.engine import run_targeted_campaign
from peekaboo.platforms.ios.platform import IOSPlatform
from peekaboo.schemas import CveDetails, PipelineState


def _settings() -> Settings:
    root = resolve_data_root(Settings())
    write_default_config(root)
    return load_settings(root)


@click.group(name="fuzz")
def fuzz_group() -> None:
    """Patch-targeted grammar fuzzing (Peekaboo toolkit)."""


@fuzz_group.command("run")
@click.option("--cve", required=True)
@click.option("--device", default=None)
@click.option("--executions", default=None, type=int)
def fuzz_run_cmd(cve: str, device: str | None, executions: int | None) -> None:
    """Run a targeted fuzz campaign for a CVE (uses advisory + RE cache if available)."""
    settings = _settings()
    if executions:
        settings = settings.model_copy(
            update={"fuzz": settings.fuzz.model_copy(update={"max_executions": executions})}
        )
    platform = IOSPlatform(device=device or settings.ios.default_device)
    ctx = build_context(settings, platform=platform)

    async def _run():
        state = PipelineState(cve_details=CveDetails(cve=cve.upper(), platform="ios"))
        enriched = await platform.enrich_cve(state, ctx)
        details = enriched["cve_details"]
        # Minimal artifact stub for strategy — full run uses pipeline artifacts
        from peekaboo.schemas import Artifact, Candidate, FunctionChange

        art = Artifact(
            candidate=Candidate(name=details.component or "ImageIO", component_match=True),
            changed_functions=[FunctionChange(address=0x1000, name="parse", similarity=0.4)],
        )
        return await run_targeted_campaign(ctx, details, [art])

    campaign = asyncio.run(_run())
    click.echo(f"Status: {campaign.status} | interesting: {campaign.interesting_count}/{campaign.executions}")
    click.echo(f"Corpus: {campaign.corpus_dir}")
    if campaign.rca_addendum:
        click.echo(f"RCA addendum: {campaign.rca_addendum[:200]}...")
