from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field


def append_list(existing: list, new: list) -> list:
    return existing + new


def merge_reports(existing: list, new: list) -> list:
    """Append new reports or update existing ones by (cve, file, address)."""
    if not new:
        return existing
    if not existing:
        return list(new)
    keyed = {
        (r.cve, r.file_name, r.function_address): r
        for r in existing
    }
    for r in new:
        keyed[(r.cve, r.file_name, r.function_address)] = r
    return list(keyed.values())


class Stage(str, Enum):
    CVE_INFO = "cve_info"
    GATHER = "gather"
    PLATFORM_INTERNALS = "platform_internals"
    REVERSE_ENGINEERING = "reverse_engineering"
    VULNERABILITY_RESEARCH = "vulnerability_research"
    VALIDATE = "validate"
    FUZZ = "fuzz"
    POC_GENERATION = "poc_generation"
    FINALIZE = "finalize"
    DONE = "done"


class CveDetails(BaseModel):
    cve: str
    platform: str = ""
    component: str = ""
    impact: str = ""
    description: str = ""
    fixed_version: str = ""
    pre_version: str = ""
    pre_build: str = ""
    post_build: str = ""
    advisory_url: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)


class Candidate(BaseModel):
    name: str
    path: str = ""
    pre_path: str = ""
    post_path: str = ""
    relevancy_score: float = 0.0
    similarity_score: float = 0.0
    description: str = ""
    component_match: bool = False
    auto_re: bool = True
    metadata: dict[str, Any] = Field(default_factory=dict)


class FunctionChange(BaseModel):
    address: int
    name: str = ""
    similarity: float = 0.0
    pre_decompile: str = ""
    post_decompile: str = ""
    security_score: float = 0.0


class ConfidenceBreakdown(BaseModel):
    overall: float = 0.0
    component_match: float = 0.0
    function_diff: float = 0.0
    decompile_quality: float = 0.0
    re_backend_quality: float = 0.0
    llm_assessment: float = 0.0
    human_review_recommended: bool = True
    notes: list[str] = Field(default_factory=list)


class PoCBlueprint(BaseModel):
    title: str = ""
    hypothesis: str = ""
    attack_vector: str = ""
    trigger_surface: str = ""
    prerequisites: list[str] = Field(default_factory=list)
    reproduction_steps: list[str] = Field(default_factory=list)
    verification_signals: list[str] = Field(default_factory=list)
    minimal_code: str = ""
    language: str = "python"
    limitations: list[str] = Field(default_factory=list)
    poc_confidence: float = 0.0
    severity_notes: str = ""

    def to_markdown(self) -> str:
        lines = [
            f"# PoC Blueprint: {self.title or 'Untitled'}",
            "",
            f"**PoC confidence:** {self.poc_confidence:.2f}",
            "",
            "## Hypothesis",
            self.hypothesis,
            "",
            "## Attack vector",
            self.attack_vector,
            "",
            "## Trigger surface",
            self.trigger_surface,
            "",
            "## Prerequisites",
            *[f"- {p}" for p in self.prerequisites],
            "",
            "## Reproduction steps",
            *[f"{i}. {s}" for i, s in enumerate(self.reproduction_steps, 1)],
            "",
            "## Verification signals",
            *[f"- {v}" for v in self.verification_signals],
            "",
            f"## Minimal code ({self.language})",
            "```",
            self.minimal_code,
            "```",
            "",
            "## Limitations",
            *[f"- {l}" for l in self.limitations],
            "",
            "## Severity notes",
            self.severity_notes,
        ]
        return "\n".join(lines)


class Artifact(BaseModel):
    candidate: Candidate
    primary_binary: str = ""
    secondary_binary: str = ""
    bindiff_db: str = ""
    changed_functions: list[FunctionChange] = Field(default_factory=list)


class Report(BaseModel):
    cve: str
    platform: str
    file_name: str = ""
    function_name: str = ""
    function_address: int = 0
    confidence: float = 0.0
    confidence_breakdown: ConfidenceBreakdown = Field(default_factory=ConfidenceBreakdown)
    summary: str = ""
    root_cause: str = ""
    pre_decompile: str = ""
    post_decompile: str = ""
    diff_text: str = ""
    model: str = ""
    cost_usd: float = 0.0
    poc: PoCBlueprint | None = None
    export_path: str = ""
    created_at: datetime = Field(default_factory=datetime.utcnow)
    metadata: dict[str, Any] = Field(default_factory=dict)

    def to_markdown(self) -> str:
        cb = self.confidence_breakdown
        lines = [
            f"# RCA Report: {self.cve}",
            "",
            f"**Platform:** {self.platform}",
            f"**File:** {self.file_name}",
            f"**Function:** {self.function_name} (`0x{self.function_address:x}`)",
            f"**Confidence:** {self.confidence:.2f}",
            f"**Human review:** {'recommended' if cb.human_review_recommended else 'not required'}",
            f"**Model:** {self.model}",
            "",
            "## Confidence breakdown",
            f"- Component match: {cb.component_match:.2f}",
            f"- Function change: {cb.function_diff:.2f}",
            f"- Decompile quality: {cb.decompile_quality:.2f}",
            f"- RE backend: {cb.re_backend_quality:.2f}",
            f"- LLM assessment: {cb.llm_assessment:.2f}",
            "",
        ]
        if cb.notes:
            lines.append("### Notes")
            lines.extend(f"- {n}" for n in cb.notes)
            lines.append("")
        lines.extend([
            "## Summary",
            self.summary,
            "",
            "## Root Cause",
            self.root_cause,
            "",
            "## Pre-patch",
            "```c",
            self.pre_decompile or "(none)",
            "```",
            "",
            "## Post-patch",
            "```c",
            self.post_decompile or "(none)",
            "```",
            "",
            "## Diff",
            "```diff",
            self.diff_text or "(none)",
            "```",
        ])
        if self.poc:
            lines.extend(["", "---", "", self.poc.to_markdown()])
        if self.export_path:
            lines.extend(["", f"**Export pack:** `{self.export_path}`"])
        return "\n".join(lines)


class GatherResult(BaseModel):
    pre_artifacts_dir: str = ""
    post_artifacts_dir: str = ""
    changed_files: list[str] = Field(default_factory=list)
    inventory_path: str = ""


class ValidationResult(BaseModel):
    """Outcome of optional vphone-cli dynamic validation."""

    status: Literal["passed", "failed", "skipped", "error"] = "skipped"
    backend: str = "vphone-cli"
    vm_pre: str = ""
    vm_post: str = ""
    pre_build: str = ""
    post_build: str = ""
    payload_path: str = ""
    pre_crash_detected: bool = False
    post_crash_detected: bool = False
    asymmetric: bool = False
    log_excerpt: str = ""
    confidence_boost: float = 0.0
    notes: list[str] = Field(default_factory=list)


class FuzzFinding(BaseModel):
    id: str = ""
    mutation: str = ""
    sample_path: str = ""
    interesting: bool = False
    crashed: bool = False
    timed_out: bool = False
    returncode: int = 0
    signal_summary: str = ""


class FuzzCampaignResult(BaseModel):
    status: str = "pending"
    component: str = ""
    target_file: str = ""
    executions: int = 0
    interesting_count: int = 0
    findings: list[FuzzFinding] = Field(default_factory=list)
    corpus_dir: str = ""
    llm_strategy_summary: str = ""
    strategy: dict[str, Any] = Field(default_factory=dict)
    llm_triage: dict[str, Any] = Field(default_factory=dict)
    rca_addendum: str = ""
    hypothesis_alignment: float = 0.0
    notes: list[str] = Field(default_factory=list)

    def top_findings(self, n: int = 5) -> list[FuzzFinding]:
        interesting = [f for f in self.findings if f.interesting]
        return interesting[:n] if interesting else self.findings[:n]


class PipelineState(BaseModel):
    cve_details: CveDetails | None = None
    stage: Stage = Stage.CVE_INFO
    gather: GatherResult | None = None
    candidates: Annotated[list[Candidate], append_list] = Field(default_factory=list)
    artifacts: Annotated[list[Artifact], append_list] = Field(default_factory=list)
    reports: Annotated[list[Report], merge_reports] = Field(default_factory=list)
    validation: ValidationResult | None = None
    fuzz: FuzzCampaignResult | None = None
    errors: Annotated[list[str], append_list] = Field(default_factory=list)
    run_id: str = ""
    platform_name: str = ""
    artifacts_mode: bool = False
    pre_artifacts_path: str = ""
    post_artifacts_path: str = ""
    skip_vphone: bool = False
    skip_fuzz: bool = False
