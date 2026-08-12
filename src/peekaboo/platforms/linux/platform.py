"""Linux/Ubuntu platform."""

from __future__ import annotations

from pathlib import Path

import structlog

from peekaboo.core.app_context import AppContext
from peekaboo.platforms.base import RECategory
from peekaboo.platforms.linux.usn import find_ubuntu_advisory
from peekaboo.schemas import CveDetails, GatherResult, PipelineState

log = structlog.get_logger(__name__)


class LinuxDistroPlatform:
    name = "linux"
    distro = "ubuntu_24.04"

    async def enrich_cve(self, state: PipelineState, ctx: AppContext) -> dict:
        cve = state.cve_details.cve if state.cve_details else ""
        ctx.progress.info(f"Fetching Ubuntu USN for {cve}")
        advisory = await find_ubuntu_advisory(cve)
        if not advisory:
            raise RuntimeError(f"No Ubuntu advisory found for {cve}")

        details = CveDetails(
            cve=cve,
            platform=self.name,
            component=advisory.usn_id,
            description=advisory.description,
            fixed_version=advisory.fixed_version,
            advisory_url=advisory.url,
            extra={"packages": advisory.packages, "distro": self.distro},
        )
        return {"cve_details": details}

    async def gather_artifacts(self, state: PipelineState, ctx: AppContext) -> GatherResult:
        if state.artifacts_mode:
            pre = Path(state.pre_artifacts_path)
            post = Path(state.post_artifacts_path)
            if not pre.exists() or not post.exists():
                raise RuntimeError("artifacts mode requires --pre and --post directories")
            pre_files = {p.name for p in pre.rglob("*.so")}
            post_files = {p.name for p in post.rglob("*.so")}
            changed = sorted(pre_files | post_files)
            return GatherResult(
                pre_artifacts_dir=str(pre),
                post_artifacts_dir=str(post),
                changed_files=changed,
            )

        raise RuntimeError(
            "Linux automatic package gather requires a Linux host or Docker. "
            "Use: peekaboo linux cve CVE-XXXX --pre /path/pre --post /path/post"
        )

    def candidate_metadata(self, cve: CveDetails) -> dict:
        return {
            "distro": self.distro,
            "packages": cve.extra.get("packages", []),
            "description": cve.description,
        }

    def classify_candidate(self, name: str) -> RECategory:
        if name.endswith((".c", ".h", ".cpp")):
            return RECategory.SOURCE
        return RECategory.BINARY
