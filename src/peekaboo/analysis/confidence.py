"""Confidence scoring from pipeline signals."""

from __future__ import annotations

from peekaboo.schemas import ConfidenceBreakdown, Report


def compute_confidence(
    *,
    component_match: bool,
    relevancy_score: float,
    function_similarity: float,
    re_backend: str,
    llm_score: float | None = None,
    has_decompile: bool,
) -> ConfidenceBreakdown:
    """Deterministic confidence from evidence — not LLM hand-waving."""
    component = relevancy_score if component_match else relevancy_score * 0.5
    function_diff = max(0.0, min(1.0, 1.0 - function_similarity))

    backend_quality = {
        "ida": 0.95,
        "ghidra": 0.85,
        "simple": 0.45,
    }.get(re_backend, 0.5)

    decompile_quality = 0.8 if has_decompile and re_backend != "simple" else (0.5 if has_decompile else 0.2)

    llm = llm_score if llm_score is not None else 0.65
    llm = max(0.0, min(1.0, llm))

    # Weighted aggregate
    overall = (
        component * 0.25
        + function_diff * 0.25
        + decompile_quality * 0.20
        + backend_quality * 0.15
        + llm * 0.15
    )
    overall = round(max(0.0, min(1.0, overall)), 3)

    human_review = (
        overall < 0.6
        or re_backend == "simple"
        or not component_match
        or function_diff < 0.1
    )

    notes: list[str] = []
    if re_backend == "simple":
        notes.append("RE backend is byte-level only — install Ghidra for higher fidelity")
    if not component_match:
        notes.append("Changed file did not strongly match advisory component label")
    if function_diff < 0.15:
        notes.append("Function-level change is subtle — manual diff review advised")
    if overall >= 0.75 and not human_review:
        notes.append("Evidence chain is coherent — suitable for guided lab validation")

    return ConfidenceBreakdown(
        overall=overall,
        component_match=round(component, 3),
        function_diff=round(function_diff, 3),
        decompile_quality=round(decompile_quality, 3),
        re_backend_quality=round(backend_quality, 3),
        llm_assessment=round(llm, 3),
        human_review_recommended=human_review,
        notes=notes,
    )


def parse_llm_confidence(content: str) -> float | None:
    """Extract self-reported confidence from LLM response if present."""
    import re

    for pattern in [
        r"confidence[:\s]+([0-9]*\.?[0-9]+)",
        r"([0-9]*\.?[0-9]+)\s*/\s*1(?:\.0)?\s*confidence",
    ]:
        m = re.search(pattern, content, re.I)
        if m:
            val = float(m.group(1))
            return val if val <= 1.0 else val / 100.0
    return None
