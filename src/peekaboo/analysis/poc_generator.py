"""Senior-engineering PoC blueprint generator."""

from __future__ import annotations

import json
import re

import structlog
from langchain_core.messages import HumanMessage, SystemMessage
from pydantic import ValidationError

from peekaboo.core.app_context import AppContext
from peekaboo.schemas import Artifact, CveDetails, PoCBlueprint, Report, FuzzCampaignResult

log = structlog.get_logger(__name__)

POC_SYSTEM = """You are a senior vulnerability researcher writing a MINIMAL proof-of-concept BLUEPRINT.

Rules (strict):
1. Output ONLY valid JSON matching the schema — no markdown fences.
2. Do NOT claim a working weaponized exploit. Write a lab-oriented reproduction blueprint.
3. Do NOT invent memory addresses, ROP gadgets, or offsets not present in the input.
4. `minimal_code` must be honest: use stubs, comments marking UNKNOWN, and assert preconditions.
5. Prefer Python or C pseudocode for harness structure — show INPUT construction and EXPECTED signals.
6. `limitations` must list what cannot be confirmed without device testing.
7. If evidence is weak, lower poc_confidence and say so in limitations.
8. reproduction_steps must be actionable for a security engineer with the target device/simulator.

JSON schema:
{
  "title": "string",
  "hypothesis": "string — one paragraph",
  "attack_vector": "string — e.g. malformed XPC dictionary, OOB write trigger",
  "trigger_surface": "string — API/IPC entry point",
  "prerequisites": ["string"],
  "reproduction_steps": ["string"],
  "verification_signals": ["string — crash log, errno, sanitizer, behavior change"],
  "minimal_code": "string — code with comments",
  "language": "python|c|pseudo",
  "limitations": ["string"],
  "poc_confidence": 0.0-1.0,
  "severity_notes": "string"
}"""


async def generate_poc_blueprint(
    ctx: AppContext,
    details: CveDetails,
    art: Artifact,
    report: Report,
    *,
    fuzz: FuzzCampaignResult | None = None,
) -> PoCBlueprint | None:
    top_fn = max(art.changed_functions, key=lambda f: 1.0 - f.similarity) if art.changed_functions else None
    if not top_fn:
        return None

    llm = ctx.models.chat_for("researcher", temperature=0.1)
    user_prompt = json.dumps({
        "cve": details.cve,
        "platform": details.platform,
        "component": details.component,
        "impact": details.impact,
        "advisory_description": details.description,
        "file": art.candidate.name,
        "function": top_fn.name,
        "function_address_hex": f"0x{top_fn.address:x}",
        "function_similarity": top_fn.similarity,
        "rca_summary": report.summary,
        "root_cause": report.root_cause[:4000],
        "pre_patch_excerpt": top_fn.pre_decompile[:2000],
        "post_patch_excerpt": top_fn.post_decompile[:2000],
        "patch_diff_excerpt": report.diff_text[:2000],
        "confidence_overall": report.confidence,
        "human_review_recommended": report.confidence_breakdown.human_review_recommended,
        "fuzz_findings": [
            {"id": f.id, "mutation": f.mutation, "signal": f.signal_summary}
            for f in (fuzz.top_findings(8) if fuzz else [])
        ],
    }, indent=2)

    resp = await llm.ainvoke([
        SystemMessage(content=POC_SYSTEM),
        HumanMessage(content=user_prompt),
    ])
    raw = resp.content if isinstance(resp.content, str) else str(resp.content)
    data = _extract_json(raw)
    if not data:
        log.warning("poc_json_parse_failed", cve=details.cve)
        return None

    try:
        poc = PoCBlueprint.model_validate(data)
    except ValidationError as exc:
        log.warning("poc_validation_failed", error=str(exc))
        return None

    return _sanitize_poc(poc, top_fn.address)


def _extract_json(text: str) -> dict | None:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\n?", "", text)
        text = re.sub(r"\n?```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None


def _sanitize_poc(poc: PoCBlueprint, known_addr: int) -> PoCBlueprint:
    """Reject fabricated precision — clamp confidence, flag suspicious claims."""
    limitations = list(poc.limitations)
    code = poc.minimal_code

    # Flag hardcoded addresses not matching analysis
    for match in re.finditer(r"0x[0-9a-fA-F]{4,}", code):
        addr_str = match.group(0)
        try:
            addr = int(addr_str, 16)
        except ValueError:
            continue
        if addr != known_addr and addr > 0x1000:
            limitations.append(
                f"Code references {addr_str} which was not verified in analysis — treat as placeholder"
            )

    if poc.poc_confidence > 0.85 and "UNKNOWN" in code.upper():
        poc = poc.model_copy(update={"poc_confidence": min(poc.poc_confidence, 0.75)})

    if not limitations:
        limitations.append("PoC blueprint requires on-device validation before any claim of exploitability")

    return poc.model_copy(update={"limitations": limitations})
