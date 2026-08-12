"""Top-level LangGraph pipeline."""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from peekaboo.core.app_context import AppContext
from peekaboo.graphs.pipeline import nodes
from peekaboo.graphs.pipeline.routing import route_after_stage
from peekaboo.schemas import PipelineState


def build_pipeline_graph(ctx: AppContext):
    graph = StateGraph(PipelineState)

    async def cve_info(s: PipelineState) -> dict:
        return await nodes.cve_info_node(s, ctx)

    async def gather(s: PipelineState) -> dict:
        return await nodes.gather_node(s, ctx)

    async def platform_internals(s: PipelineState) -> dict:
        return await nodes.platform_internals_node(s, ctx)

    async def reverse_engineering(s: PipelineState) -> dict:
        return await nodes.reverse_engineering_node(s, ctx)

    async def fuzz(s: PipelineState) -> dict:
        return await nodes.fuzz_node(s, ctx)

    async def vulnerability_research(s: PipelineState) -> dict:
        return await nodes.vulnerability_research_node(s, ctx)

    async def validate(s: PipelineState) -> dict:
        return await nodes.validate_node(s, ctx)

    async def finalize(s: PipelineState) -> dict:
        return await nodes.finalize_node(s, ctx)

    graph.add_node("cve_info", cve_info)
    graph.add_node("gather", gather)
    graph.add_node("platform_internals", platform_internals)
    graph.add_node("reverse_engineering", reverse_engineering)
    graph.add_node("fuzz", fuzz)
    graph.add_node("vulnerability_research", vulnerability_research)
    graph.add_node("validate", validate)
    graph.add_node("finalize", finalize)

    graph.set_entry_point("cve_info")

    for node_name in [
        "cve_info", "gather", "platform_internals",
        "reverse_engineering", "fuzz", "vulnerability_research", "validate",
    ]:
        graph.add_conditional_edges(node_name, route_after_stage, {
            "gather": "gather",
            "platform_internals": "platform_internals",
            "reverse_engineering": "reverse_engineering",
            "fuzz": "fuzz",
            "vulnerability_research": "vulnerability_research",
            "validate": "validate",
            "finalize": "finalize",
            "__end__": END,
        })

    graph.add_edge("finalize", END)
    return graph.compile()
