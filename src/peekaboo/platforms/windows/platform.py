"""Windows platform scaffold — full gather deferred until Windows host."""

from __future__ import annotations

from pathlib import Path

from peekaboo.core.app_context import AppContext
from peekaboo.platforms.base import RECategory, PlatformNotReady
from peekaboo.schemas import CveDetails, GatherResult, PipelineState


class WindowsVersionedPlatform:
    name = "windows"
    version = "windows_11_24h2"

    async def enrich_cve(self, state: PipelineState, ctx: AppContext) -> dict:
        cve = state.cve_details.cve if state.cve_details else ""
        details = CveDetails(
            cve=cve,
            platform=self.name,
            component="MSRC",
            description="Windows CVE — enrichment via MSRC deferred until Windows host available.",
            extra={"version": self.version},
        )
        return {"cve_details": details}

    async def gather_artifacts(self, state: PipelineState, ctx: AppContext) -> GatherResult:
        if state.artifacts_mode:
            pre = Path(state.pre_artifacts_path)
            post = Path(state.post_artifacts_path)
            changed = sorted({p.name for p in pre.rglob("*") if p.is_file()} |
                             {p.name for p in post.rglob("*") if p.is_file()})
            return GatherResult(
                pre_artifacts_dir=str(pre),
                post_artifacts_dir=str(post),
                changed_files=changed,
            )
        raise PlatformNotReady(
            "Windows automatic KB gather requires a Windows host with 7-Zip and Update Catalog access. "
            "Use artifacts mode: peekaboo windows cve CVE-XXXX --pre /path/pre --post /path/post "
            "See docs/Windows-Pipeline.md for the planned MSRC flow."
        )

    def candidate_metadata(self, cve: CveDetails) -> dict:
        return {"platform": self.name, "version": self.version}

    def classify_candidate(self, name: str) -> RECategory:
        if name.endswith((".exe", ".dll", ".sys")):
            return RECategory.BINARY
        return RECategory.SOURCE
