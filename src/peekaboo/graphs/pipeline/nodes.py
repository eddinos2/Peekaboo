"""Pipeline graph nodes."""

from __future__ import annotations

import difflib
from pathlib import Path

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from peekaboo.analysis.confidence import compute_confidence, parse_llm_confidence
from peekaboo.analysis.poc_generator import generate_poc_blueprint
from peekaboo.core.app_context import AppContext
from peekaboo.platforms.ios.component_map import load_component_map, rank_changed_files
from peekaboo.export.pack import export_pack
from peekaboo.schemas import (
    Artifact,
    Candidate,
    CveDetails,
    FunctionChange,
    GatherResult,
    PipelineState,
    Report,
    Stage,
    ValidationResult,
)
from peekaboo.fuzz.engine import run_targeted_campaign
from peekaboo.fuzz.llm_bridge import build_vuln_research_fuzz_context
from peekaboo.validation.vphone.validate import run_vphone_validation, vphone_status

log = structlog.get_logger(__name__)


async def cve_info_node(state: PipelineState, ctx: AppContext) -> dict:
    if ctx.platform is None:
        return {"errors": ["No platform on context"], "stage": Stage.DONE}
    cve = state.cve_details.cve if state.cve_details else ""
    cached = ctx.store.get_cached_report(cve)
    if cached and not state.artifacts_mode:
        ctx.progress.success(f"Cache hit for {cached.cve}")
        return {"reports": [cached], "stage": Stage.FINALIZE}

    if state.artifacts_mode:
        ctx.progress.info("Artifacts mode — skipping advisory fetch")
        details = state.cve_details or CveDetails(cve=cve, platform=ctx.platform.name)
        details = details.model_copy(update={
            "platform": ctx.platform.name,
            "component": details.component or "libxpc",
            "description": details.description or "Local artifacts analysis (demo/manual mode)",
        })
        return {"cve_details": details, "stage": Stage.CVE_INFO}

    ctx.progress.info("Enriching CVE from platform advisory source")
    enriched = await ctx.platform.enrich_cve(state, ctx)
    return {"cve_details": enriched.get("cve_details"), "stage": Stage.CVE_INFO}


async def gather_node(state: PipelineState, ctx: AppContext) -> dict:
    if ctx.platform is None:
        return {"errors": ["No platform"], "stage": Stage.DONE}
    try:
        gather = await ctx.platform.gather_artifacts(state, ctx)
    except Exception as exc:
        log.exception("gather_failed")
        return {"errors": [str(exc)], "stage": Stage.GATHER}
    return {"gather": gather, "stage": Stage.GATHER}


async def platform_internals_node(state: PipelineState, ctx: AppContext) -> dict:
    gather = state.gather
    details = state.cve_details
    if not gather or not details:
        return {"errors": ["Missing gather or CVE details"], "stage": Stage.DONE}

    rules = load_component_map() if details.platform == "ios" else {}
    if rules:
        ranked = rank_changed_files(gather.changed_files, details.component, rules)
        candidates = [
            Candidate(
                name=Path(f).name,
                path=f,
                relevancy_score=score,
                component_match=score >= 0.7,
                auto_re=auto_re,
                description=f"Changed file from patch inventory (score={score:.2f})",
            )
            for f, score, auto_re in ranked[:10]
            if auto_re
        ]
    else:
        llm = ctx.models.chat_for("platform_internals")
        meta = ctx.platform.candidate_metadata(details) if ctx.platform else {}
        prompt = (
            f"Rank these changed files for CVE {details.cve}.\n"
            f"Metadata: {meta}\n"
            f"Files: {gather.changed_files[:30]}\n"
            "Return top 5 most likely vulnerable files, one per line."
        )
        resp = await llm.ainvoke([HumanMessage(content=prompt)])
        names = [ln.strip("- •\t ") for ln in resp.content.splitlines() if ln.strip()][:5]
        candidates = [
            Candidate(name=Path(n).name, path=n, relevancy_score=0.8, description="LLM-ranked")
            for n in names
        ]

    if not candidates and gather.changed_files:
        candidates = [
            Candidate(name=Path(f).name, path=f, relevancy_score=0.5)
            for f in gather.changed_files[:5]
        ]

    for c in candidates:
        ctx.store.save_file_description(
            f"{details.cve}:{c.name}",
            c.description or c.name,
            {"cve": details.cve, "file": c.name},
        )

    ctx.progress.info(f"Selected {len(candidates)} candidates")
    return {"candidates": candidates, "stage": Stage.PLATFORM_INTERNALS}


async def reverse_engineering_node(state: PipelineState, ctx: AppContext) -> dict:
    gather = state.gather
    if not gather:
        return {"errors": ["No gather result"], "stage": Stage.DONE}

    backend = ctx.re_factory.resolve()
    pre_dir = Path(gather.pre_artifacts_dir)
    post_dir = Path(gather.post_artifacts_dir)
    work = ctx.temp_dir / (state.cve_details.cve if state.cve_details else "unknown") / "re"
    artifacts: list[Artifact] = []

    for cand in state.candidates[:3]:
        pre_bin = _find_binary(pre_dir, cand.name)
        post_bin = _find_binary(post_dir, cand.name)
        if not pre_bin or not post_bin:
            continue
        ctx.progress.info(f"RE diff: {cand.name} via {backend.name}")
        try:
            diff = await backend.diff_pair(pre_bin, post_bin, work / cand.name)
            changed_funcs = [
                FunctionChange(address=addr, name=name, similarity=sim)
                for addr, name, sim in diff.changed_functions[:20]
            ]
            if changed_funcs:
                addrs = [f.address for f in changed_funcs[:5]]
                pre_decomp = await backend.decompile_functions(pre_bin, addrs, work / cand.name / "pre")
                post_decomp = await backend.decompile_functions(post_bin, addrs, work / cand.name / "post")
                for fc in changed_funcs:
                    fc.pre_decompile = pre_decomp.get(fc.address, "")
                    fc.post_decompile = post_decomp.get(fc.address, "")

            artifacts.append(
                Artifact(
                    candidate=cand,
                    primary_binary=str(pre_bin),
                    secondary_binary=str(post_bin),
                    changed_functions=changed_funcs,
                )
            )
        except Exception as exc:
            log.warning("re_failed", file=cand.name, error=str(exc))

    return {"artifacts": artifacts, "stage": Stage.REVERSE_ENGINEERING}


async def fuzz_node(state: PipelineState, ctx: AppContext) -> dict:
    details = state.cve_details
    if state.skip_fuzz or state.artifacts_mode or not ctx.settings.fuzz.enabled:
        return {
            "fuzz": None,
            "stage": Stage.FUZZ,
        }
    if not details or not state.artifacts:
        return {"fuzz": None, "stage": Stage.FUZZ}

    try:
        campaign = await run_targeted_campaign(ctx, details, state.artifacts)
    except Exception as exc:
        log.exception("fuzz_failed")
        return {
            "fuzz": None,
            "errors": [f"fuzz: {exc}"],
            "stage": Stage.FUZZ,
        }
    return {"fuzz": campaign, "stage": Stage.FUZZ}


async def vulnerability_research_node(state: PipelineState, ctx: AppContext) -> dict:
    details = state.cve_details
    if not details:
        return {"errors": ["No CVE details"], "stage": Stage.DONE}

    llm = ctx.models.chat_for("researcher")
    backend_name = ctx.re_factory.resolve().name
    reports: list[Report] = []

    for art in state.artifacts:
        if not art.changed_functions:
            continue
        top_fn = max(art.changed_functions, key=lambda f: 1.0 - f.similarity)
        diff_text = "\n".join(
            difflib.unified_diff(
                top_fn.pre_decompile.splitlines(),
                top_fn.post_decompile.splitlines(),
                lineterm="",
            )
        )
        fuzz_ctx = build_vuln_research_fuzz_context(state.fuzz)
        prompt = (
            f"Analyze this patch diff for {details.cve} ({details.platform}).\n"
            f"Component: {details.component}\nImpact: {details.impact}\n"
            f"File: {art.candidate.name}\nFunction: {top_fn.name}\n"
            f"Pre-patch:\n{top_fn.pre_decompile[:8000]}\n"
            f"Post-patch:\n{top_fn.post_decompile[:8000]}\n"
        )
        if fuzz_ctx:
            prompt += f"\n{fuzz_ctx}\n"
        if state.fuzz and state.fuzz.rca_addendum:
            prompt += f"\nFuzz triage addendum:\n{state.fuzz.rca_addendum}\n"
        prompt += (
            "Respond with:\n"
            "1) Executive summary (2-3 sentences)\n"
            "2) Root cause analysis\n"
            "3) Confidence: 0.0-1.0 (your assessment of analysis quality)"
        )
        resp = await llm.ainvoke([
            SystemMessage(content="You are a vulnerability researcher writing RCA reports."),
            HumanMessage(content=prompt),
        ])
        content = resp.content if isinstance(resp.content, str) else str(resp.content)
        llm_score = parse_llm_confidence(content)

        breakdown = compute_confidence(
            component_match=art.candidate.component_match,
            relevancy_score=art.candidate.relevancy_score,
            function_similarity=top_fn.similarity,
            re_backend=backend_name,
            llm_score=llm_score,
            has_decompile=bool(top_fn.pre_decompile),
        )
        if state.fuzz and state.fuzz.hypothesis_alignment > 0:
            boost = min(
                ctx.settings.fuzz.boost_confidence_max,
                state.fuzz.hypothesis_alignment * ctx.settings.fuzz.boost_confidence_max,
            )
            breakdown = breakdown.model_copy(
                update={
                    "overall": min(1.0, breakdown.overall + boost),
                    "notes": breakdown.notes
                    + [f"Fuzz alignment boost +{boost:.2f}"],
                }
            )

        root_cause = content
        if state.fuzz and state.fuzz.rca_addendum:
            root_cause = f"{content}\n\n## Fuzz-enriched analysis\n{state.fuzz.rca_addendum}"

        report = Report(
            cve=details.cve,
            platform=details.platform,
            file_name=art.candidate.name,
            function_name=top_fn.name,
            function_address=top_fn.address,
            confidence=breakdown.overall,
            confidence_breakdown=breakdown,
            summary=content[:800],
            root_cause=root_cause,
            pre_decompile=top_fn.pre_decompile,
            post_decompile=top_fn.post_decompile,
            diff_text=diff_text,
            model=ctx.settings.models.researcher,
        )
        reports.append(report)

    return {"reports": reports, "stage": Stage.VULNERABILITY_RESEARCH}


async def validate_node(state: PipelineState, ctx: AppContext) -> dict:
    """vphone-cli readiness + optional dynamic validation hook."""
    if state.skip_vphone or state.artifacts_mode:
        return {
            "validation": ValidationResult(status="skipped", notes=["vphone skipped for this run"]),
            "stage": Stage.VALIDATE,
        }

    details = state.cve_details
    if not details or details.platform != "ios":
        return {"validation": ValidationResult(status="skipped"), "stage": Stage.VALIDATE}

    settings = ctx.settings.vphone
    if not settings.enabled:
        return {
            "validation": ValidationResult(status="skipped", notes=["vphone disabled"]),
            "stage": Stage.VALIDATE,
        }

    ctx.progress.info("Checking vphone-cli lab readiness")
    ok, issues, info = await vphone_status(settings)
    notes = info + issues
    validation = ValidationResult(
        status="skipped" if not ok else "skipped",
        notes=notes,
    )
    if ok:
        ctx.progress.success("vphone-cli available — dynamic validation after PoC generation")
        validation.notes.append("Will attempt crash compare if peekaboo VMs are provisioned")
    else:
        ctx.progress.warn("vphone-cli not ready — static analysis only")
        for issue in issues[:3]:
            ctx.progress.warn(issue)

    return {"validation": validation, "stage": Stage.VALIDATE}


async def finalize_node(state: PipelineState, ctx: AppContext) -> dict:
    exports_dir = ctx.reports_dir / "exports"
    exports_dir.mkdir(parents=True, exist_ok=True)
    art_by_file = {a.candidate.name: a for a in state.artifacts}
    final_reports: list[Report] = []

    repro = (
        f"peekaboo cached --cve {state.cve_details.cve}"
        if state.cve_details
        else "peekaboo cached"
    )

    for report in _dedupe_reports(state.reports):
        art = art_by_file.get(report.file_name)
        poc = report.poc
        if art and not poc:
            ctx.progress.info(f"Generating PoC blueprint: {report.file_name}")
            try:
                poc = await generate_poc_blueprint(ctx, state.cve_details, art, report, fuzz=state.fuzz)
                if poc:
                    report = report.model_copy(update={"poc": poc})
                    ctx.progress.success(f"PoC blueprint ready (conf={poc.poc_confidence:.2f})")
                else:
                    ctx.progress.warn("PoC validation failed — export continues without PoC")
            except Exception as exc:
                log.warning("poc_generation_failed", error=str(exc))
                ctx.progress.warn(f"PoC generation failed: {exc}")

        validation = state.validation
        details = state.cve_details
        if (
            not state.skip_vphone
            and not state.artifacts_mode
            and details
            and details.platform == "ios"
            and ctx.settings.vphone.enabled
            and poc
        ):
            ctx.progress.info("Running vphone dynamic validation")
            try:
                dyn = await run_vphone_validation(ctx, details, report, poc)
                validation = dyn
                if dyn.status == "passed":
                    boosted = min(1.0, report.confidence + dyn.confidence_boost)
                    poc = poc.model_copy(
                        update={"poc_confidence": min(1.0, poc.poc_confidence + dyn.confidence_boost)}
                    )
                    report = report.model_copy(update={"confidence": boosted})
                    ctx.progress.success(f"vphone validation passed (+{dyn.confidence_boost:.2f} conf)")
                elif dyn.status == "error":
                    ctx.progress.warn(f"vphone validation error: {dyn.notes[-1] if dyn.notes else 'unknown'}")
                else:
                    ctx.progress.info(f"vphone validation: {dyn.status}")
            except Exception as exc:
                log.warning("vphone_validate_failed", error=str(exc))
                validation = ValidationResult(status="error", notes=[str(exc)])

        out = export_pack(
            exports_dir,
            report,
            details=state.cve_details,
            poc=poc,
            repro_command=repro,
            validation=validation,
            fuzz=state.fuzz,
        )
        report = report.model_copy(update={"export_path": str(out)})
        ctx.store.save_report(report)
        _save_report_file(ctx, report)
        ctx.progress.success(
            f"Export: {report.cve} / {report.file_name} "
            f"(conf={report.confidence:.2f}, poc={'yes' if poc else 'no'})"
        )
        final_reports.append(report)

    return {"reports": final_reports, "stage": Stage.FINALIZE}


def _dedupe_reports(reports: list[Report]) -> list[Report]:
    seen: dict[tuple[str, str, int], Report] = {}
    for r in reports:
        seen[(r.cve, r.file_name, r.function_address)] = r
    return list(seen.values())


def _find_binary(directory: Path, name: str) -> Path | None:
    if not directory.exists():
        return None
    for p in directory.rglob("*"):
        if p.is_file() and name in p.name:
            return p
    return None


def _save_report_file(ctx: AppContext, report: Report) -> None:
    fname = f"{report.cve}_{report.file_name}_{report.function_address:x}.md"
    path = ctx.reports_dir / fname
    path.write_text(report.to_markdown(), encoding="utf-8")
