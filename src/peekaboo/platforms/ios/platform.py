"""iOS platform implementation."""

from __future__ import annotations

import shutil
from pathlib import Path

import structlog

from peekaboo.core.app_context import AppContext
from peekaboo.platforms.base import RECategory
from peekaboo.platforms.ios.advisory import find_advisory_for_cve
from peekaboo.platforms.ios.appledb import fetch_build_info, fetch_previous_build
from peekaboo.platforms.ios.component_map import load_component_map, rank_changed_files
from peekaboo.platforms.ios.ipsw_tools import (
    diff_ipsw,
    download_ipsw,
    extract_dylib,
    parse_diff_markdown,
    resolve_ipsw_bin,
)
from peekaboo.schemas import CveDetails, GatherResult, PipelineState

log = structlog.get_logger(__name__)


class IOSPlatform:
    name = "ios"

    def __init__(self, device: str = "iPhone16,1") -> None:
        self.device = device

    async def enrich_cve(self, state: PipelineState, ctx: AppContext) -> dict:
        cve = state.cve_details.cve if state.cve_details else ""
        ctx.progress.info(f"Fetching Apple advisory for {cve}")
        advisory = await find_advisory_for_cve(cve)
        if not advisory:
            raise RuntimeError(f"No Apple advisory found for {cve}")

        ipsw_bin = None
        try:
            ipsw_bin = resolve_ipsw_bin(ctx.settings.tools.ipsw)
        except RuntimeError:
            pass

        component = advisory.component
        if component == "Unknown" and "image" in advisory.description.lower():
            component = "ImageIO"

        post = await fetch_build_info(
            advisory.fixed_version,
            self.device,
            base_url=ctx.settings.ios.appledb_base_url,
            ipsw_bin=ipsw_bin,
        )
        if not post:
            raise RuntimeError(f"Could not resolve build for iOS {advisory.fixed_version}")

        pre = None
        if ipsw_bin:
            from peekaboo.platforms.ios.ipsw_resolve import pre_version_candidates, resolve_ipsw_url

            for candidate in pre_version_candidates(advisory.fixed_version):
                pre = await resolve_ipsw_url(self.device, candidate, ipsw_bin=ipsw_bin)
                if pre and pre.build != post.build:
                    break
                pre = None
        if not pre:
            pre = await fetch_previous_build(
                post.build,
                self.device,
                base_url=ctx.settings.ios.appledb_base_url,
            )
        if not pre:
            raise RuntimeError(f"Could not resolve previous build before {post.build}")

        details = CveDetails(
            cve=cve,
            platform=self.name,
            component=component,
            impact=advisory.impact,
            description=advisory.description,
            fixed_version=advisory.fixed_version,
            pre_version=pre.version,
            pre_build=pre.build,
            post_build=post.build,
            advisory_url=advisory.advisory_url,
            extra={
                "pre_ipsw_url": pre.ipsw_url,
                "post_ipsw_url": post.ipsw_url,
                "device": self.device,
            },
        )
        log.info("ios_enrich_complete", cve=cve, pre=pre.build, post=post.build)
        return {"cve_details": details}

    async def gather_artifacts(self, state: PipelineState, ctx: AppContext) -> GatherResult:
        details = state.cve_details
        if not details:
            raise RuntimeError("Missing CVE details")

        if state.artifacts_mode:
            return self._gather_from_local(state, ctx)

        ipsw_bin = resolve_ipsw_bin(ctx.settings.tools.ipsw)
        work = ctx.temp_dir / details.cve / "ios"
        pre_dir = work / "pre"
        post_dir = work / "post"
        diff_dir = work / "diff"

        ctx.progress.start("Downloading IPSW pair", total=2)
        device = details.extra["device"]
        pre_ipsw = await download_ipsw(
            pre_dir,
            ipsw_bin=ipsw_bin,
            device=device,
            build=details.pre_build,
            url=details.extra.get("pre_ipsw_url"),
            vphone_settings=ctx.settings.vphone,
        )
        ctx.progress.advance("Downloaded pre-patch IPSW")
        post_ipsw = await download_ipsw(
            post_dir,
            ipsw_bin=ipsw_bin,
            device=device,
            build=details.post_build,
            url=details.extra.get("post_ipsw_url"),
            vphone_settings=ctx.settings.vphone,
        )
        ctx.progress.advance("Downloaded post-patch IPSW")
        ctx.progress.stop()

        ctx.progress.info("Running ipsw diff")
        diff_md = await diff_ipsw(pre_ipsw, post_ipsw, diff_dir, ipsw_bin=ipsw_bin)
        changed = parse_diff_markdown(diff_md)

        rules = load_component_map()
        ranked = rank_changed_files(changed, details.component, rules)
        top_files = [f for f, score, auto_re in ranked if score >= 0.2 and auto_re][:10]

        extracted_pre = work / "extracted_pre"
        extracted_post = work / "extracted_post"
        for fpath in top_files[:3]:
            name = Path(fpath).name
            await extract_dylib(pre_ipsw, name, extracted_pre, ipsw_bin=ipsw_bin)
            await extract_dylib(post_ipsw, name, extracted_post, ipsw_bin=ipsw_bin)

        return GatherResult(
            pre_artifacts_dir=str(extracted_pre),
            post_artifacts_dir=str(extracted_post),
            changed_files=changed,
            inventory_path=str(diff_md),
        )

    def _gather_from_local(self, state: PipelineState, ctx: AppContext) -> GatherResult:
        pre = Path(state.pre_artifacts_path)
        post = Path(state.post_artifacts_path)
        if not pre.exists() or not post.exists():
            raise RuntimeError("artifacts mode requires valid --pre and --post directories")

        pre_files = {p.name: p for p in pre.rglob("*") if p.is_file()}
        post_files = {p.name: p for p in post.rglob("*") if p.is_file()}
        changed = sorted(set(pre_files) | set(post_files))

        return GatherResult(
            pre_artifacts_dir=str(pre),
            post_artifacts_dir=str(post),
            changed_files=changed,
        )

    def candidate_metadata(self, cve: CveDetails) -> dict:
        return {
            "component": cve.component,
            "impact": cve.impact,
            "description": cve.description,
            "platform": self.name,
            "device": self.device,
        }

    def classify_candidate(self, name: str) -> RECategory:
        if name.endswith((".c", ".h", ".cpp", ".py")):
            return RECategory.SOURCE
        return RECategory.BINARY
