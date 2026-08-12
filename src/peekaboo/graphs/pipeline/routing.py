"""Deterministic pipeline router."""

from __future__ import annotations

from peekaboo.schemas import PipelineState, Stage


def route_after_stage(state: PipelineState) -> str:
    if state.errors and state.stage not in (Stage.FINALIZE, Stage.DONE):
        return "finalize"
    mapping = {
        Stage.CVE_INFO: "gather",
        Stage.GATHER: "platform_internals",
        Stage.PLATFORM_INTERNALS: "reverse_engineering",
        Stage.REVERSE_ENGINEERING: "fuzz",
        Stage.FUZZ: "vulnerability_research",
        Stage.VULNERABILITY_RESEARCH: "validate",
        Stage.VALIDATE: "finalize",
        Stage.FINALIZE: "__end__",
        Stage.DONE: "__end__",
    }
    return mapping.get(state.stage, "__end__")
