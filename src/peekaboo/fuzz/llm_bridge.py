"""Bidirectional LLM ↔ fuzz enrichment."""

from __future__ import annotations

import json
import re

import structlog
from langchain_core.messages import HumanMessage, SystemMessage

from peekaboo.core.app_context import AppContext
from peekaboo.fuzz.mutators.imageio_heic import llm_ops_from_hints
from peekaboo.schemas import Artifact, CveDetails, FuzzFinding, FuzzCampaignResult

log = structlog.get_logger(__name__)

STRATEGY_SYSTEM = """You are an elite fuzz strategist for patch-diff security research.
Given CVE context, changed function decompilation, and patch diff, output JSON ONLY:
{
  "mutation_hints": ["string — specific mutation strategies aligned to root cause hypothesis"],
  "priority_fields": ["string — parser fields or code paths to stress"],
  "oracle_signals": ["string — crash/log patterns that confirm the hypothesis"],
  "harness_notes": "string — how to trigger the vulnerable path"
}
Do not invent addresses. Be conservative if evidence is weak."""

TRIAGE_SYSTEM = """You triage fuzz findings for a patch-diff RCA pipeline.
Output JSON ONLY:
{
  "summary": "2-3 sentences for vulnerability researcher",
  "hypothesis_alignment": 0.0-1.0,
  "recommended_inputs": ["index or short id of top findings"],
  "rca_addendum": "paragraph to append to root cause analysis"
}"""


async def suggest_fuzz_strategy(
    ctx: AppContext,
    details: CveDetails,
    art: Artifact,
) -> dict:
    """LLM → fuzz: mutation strategy from RE context (pre-RCA)."""
    top_fn = max(art.changed_functions, key=lambda f: 1.0 - f.similarity) if art.changed_functions else None
    if not top_fn:
        return {"mutation_hints": ["generic bitflip"], "priority_fields": [], "oracle_signals": [], "harness_notes": ""}

    llm = ctx.models.chat_for("reverse_engineering", temperature=0.2)
    payload = json.dumps(
        {
            "cve": details.cve,
            "component": details.component,
            "impact": details.impact,
            "file": art.candidate.name,
            "function": top_fn.name,
            "pre_decompile": top_fn.pre_decompile[:3000],
            "post_decompile": top_fn.post_decompile[:3000],
        },
        indent=2,
    )
    try:
        resp = await llm.ainvoke([SystemMessage(content=STRATEGY_SYSTEM), HumanMessage(content=payload)])
        raw = resp.content if isinstance(resp.content, str) else str(resp.content)
        data = json.loads(_extract_json(raw))
        data["ops"] = llm_ops_from_hints(data.get("mutation_hints", []))
        return data
    except Exception as exc:
        log.warning("fuzz_strategy_llm_failed", error=str(exc))
        return {"mutation_hints": [], "ops": llm_ops_from_hints([]), "priority_fields": [], "oracle_signals": []}


async def enrich_rca_from_fuzz(
    ctx: AppContext,
    details: CveDetails,
    campaign: FuzzCampaignResult,
    *,
    existing_rca: str = "",
) -> dict:
    """Fuzz → LLM: triage findings into RCA addendum."""
    if not campaign.findings:
        return {"summary": "", "hypothesis_alignment": 0.0, "rca_addendum": ""}

    llm = ctx.models.chat_for("researcher", temperature=0.1)
    findings_blob = [
        {
            "id": f.id,
            "mutation": f.mutation,
            "interesting": f.interesting,
            "signal": f.signal_summary,
        }
        for f in campaign.findings[:15]
    ]
    payload = json.dumps(
        {
            "cve": details.cve,
            "component": details.component,
            "existing_rca_excerpt": existing_rca[:2000],
            "findings": findings_blob,
            "stats": {
                "executions": campaign.executions,
                "interesting": campaign.interesting_count,
            },
        },
        indent=2,
    )
    try:
        resp = await llm.ainvoke([SystemMessage(content=TRIAGE_SYSTEM), HumanMessage(content=payload)])
        raw = resp.content if isinstance(resp.content, str) else str(resp.content)
        return json.loads(_extract_json(raw))
    except Exception as exc:
        log.warning("fuzz_triage_llm_failed", error=str(exc))
        return {
            "summary": f"{campaign.interesting_count} interesting inputs from {campaign.executions} executions",
            "hypothesis_alignment": 0.3 if campaign.interesting_count else 0.0,
            "rca_addendum": "",
        }


def build_vuln_research_fuzz_context(campaign: FuzzCampaignResult | None) -> str:
    if not campaign or not campaign.findings:
        return ""
    lines = [
        "Fuzz campaign (patch-targeted):",
        f"- Executions: {campaign.executions}, interesting: {campaign.interesting_count}",
    ]
    for f in campaign.top_findings(5):
        lines.append(f"- [{f.id}] {f.mutation}: {f.signal_summary}")
    if campaign.llm_strategy_summary:
        lines.append(f"Strategy: {campaign.llm_strategy_summary}")
    return "\n".join(lines)


def _extract_json(text: str) -> str:
    m = re.search(r"\{[\s\S]*\}", text)
    return m.group(0) if m else text
