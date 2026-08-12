"""Pipeline orchestrator."""

from __future__ import annotations

import uuid

import structlog

from peekaboo.core.app_context import AppContext
from peekaboo.core.logging import bind_cve, clear_cve
from peekaboo.graphs.pipeline.graph import build_pipeline_graph
from peekaboo.schemas import CveDetails, PipelineState

log = structlog.get_logger(__name__)


async def run_cve(
    ctx: AppContext,
    cve_id: str,
    *,
    pre_artifacts: str | None = None,
    post_artifacts: str | None = None,
    skip_vphone: bool = False,
    skip_fuzz: bool = False,
) -> PipelineState:
    if ctx.platform is None:
        raise RuntimeError("No platform resolved on AppContext")

    run_id = bind_cve(cve_id, uuid.uuid4().hex[:12])
    log.info("cve_run_start", cve=cve_id, platform=ctx.platform.name, run_id=run_id)

    initial = PipelineState(
        cve_details=CveDetails(cve=cve_id, platform=ctx.platform.name),
        run_id=run_id,
        platform_name=ctx.platform.name,
        artifacts_mode=bool(pre_artifacts and post_artifacts),
        pre_artifacts_path=pre_artifacts or "",
        post_artifacts_path=post_artifacts or "",
        skip_vphone=skip_vphone,
        skip_fuzz=skip_fuzz,
    )

    graph = build_pipeline_graph(ctx)
    try:
        result = await graph.ainvoke(initial)
        if isinstance(result, PipelineState):
            final = result
        else:
            final = PipelineState.model_validate(result)
    finally:
        clear_cve()

    log.info(
        "cve_run_complete",
        cve=cve_id,
        reports=len(final.reports),
        errors=len(final.errors),
    )
    return final
