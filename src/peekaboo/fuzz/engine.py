"""Patch-targeted fuzz campaign engine."""

from __future__ import annotations

import random
import uuid
from pathlib import Path

import structlog

from peekaboo.config.settings import FuzzSettings
from peekaboo.core.app_context import AppContext
from peekaboo.fuzz.llm_bridge import enrich_rca_from_fuzz, suggest_fuzz_strategy
from peekaboo.fuzz.mutators.imageio_heic import base_heic_seed, mutate_heic
from peekaboo.fuzz.oracle import execute_component_input
from peekaboo.schemas import Artifact, CveDetails, FuzzCampaignResult, FuzzFinding

log = structlog.get_logger(__name__)


async def run_targeted_campaign(
    ctx: AppContext,
    details: CveDetails,
    artifacts: list[Artifact],
    *,
    settings: FuzzSettings | None = None,
    corpus_dir: Path | None = None,
) -> FuzzCampaignResult:
    """Run bounded grammar-aware fuzz guided by LLM + component map."""
    cfg = settings or ctx.settings.fuzz
    if not cfg.enabled:
        return FuzzCampaignResult(status="skipped", notes=["fuzz disabled"])

    if not artifacts:
        return FuzzCampaignResult(status="skipped", notes=["no artifacts to fuzz"])

    art = artifacts[0]
    strategy = await suggest_fuzz_strategy(ctx, details, art)
    ops = strategy.get("ops") or [None]
    rng = random.Random(cfg.seed)

    work = corpus_dir or (ctx.temp_dir / details.cve / "fuzz")
    work.mkdir(parents=True, exist_ok=True)

    seed = base_heic_seed()
    if "image" not in details.component.lower() and "imageio" not in details.component.lower():
        seed = b"\x00" * 64 + b"\xff" * 32

    findings: list[FuzzFinding] = []
    executions = 0
    suffix = ".heic" if "image" in details.component.lower() else ".bin"

    ctx.progress.info(f"Fuzz campaign: {cfg.max_executions} execs, component={details.component}")

    for i in range(cfg.max_executions):
        op = ops[i % len(ops)] if ops else None
        mutated, op_name = mutate_heic(seed, rng, op=op)
        executions += 1
        signal = await execute_component_input(mutated, details.component, suffix=suffix)

        if signal.interesting or cfg.save_all:
            fid = f"F{i:04d}-{uuid.uuid4().hex[:6]}"
            sample_path = work / f"{fid}{suffix}"
            sample_path.write_bytes(mutated)
            finding = FuzzFinding(
                id=fid,
                mutation=op_name,
                sample_path=str(sample_path),
                interesting=signal.interesting,
                crashed=signal.crashed,
                timed_out=signal.timed_out,
                returncode=signal.returncode,
                signal_summary=_signal_summary(signal),
            )
            findings.append(finding)
            if signal.interesting:
                ctx.progress.advance(f"Interesting input: {fid} ({op_name})")

    interesting = [f for f in findings if f.interesting]
    campaign = FuzzCampaignResult(
        status="completed",
        component=details.component,
        target_file=art.candidate.name,
        executions=executions,
        interesting_count=len(interesting),
        findings=findings,
        corpus_dir=str(work),
        llm_strategy_summary="; ".join(strategy.get("mutation_hints", [])[:3]),
        strategy=strategy,
    )

    triage = await enrich_rca_from_fuzz(ctx, details, campaign)
    campaign.llm_triage = triage
    campaign.rca_addendum = triage.get("rca_addendum", "")
    campaign.hypothesis_alignment = float(triage.get("hypothesis_alignment", 0.0))

    ctx.progress.success(
        f"Fuzz done: {len(interesting)}/{executions} interesting "
        f"(align={campaign.hypothesis_alignment:.2f})"
    )
    return campaign


def _signal_summary(signal) -> str:
    parts = []
    if signal.crashed:
        parts.append("crash")
    if signal.timed_out:
        parts.append("timeout")
    if signal.returncode not in (0, -1):
        parts.append(f"rc={signal.returncode}")
    if signal.stderr:
        parts.append(signal.stderr[:80].replace("\n", " "))
    return ", ".join(parts) or "ok"
