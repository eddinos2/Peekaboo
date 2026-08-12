"""Integration test with mocked artifacts."""

from pathlib import Path

import pytest

from peekaboo.config.settings import Settings
from peekaboo.core.bootstrap import build_context
from peekaboo.platforms.ios.platform import IOSPlatform
from peekaboo.schemas import PipelineState, CveDetails


@pytest.mark.asyncio
async def test_ios_artifacts_gather(tmp_path: Path):
    pre = tmp_path / "pre"
    post = tmp_path / "post"
    pre.mkdir()
    post.mkdir()
    (pre / "libtest.dylib").write_bytes(b"\x00" * 64)
    (post / "libtest.dylib").write_bytes(b"\x01" * 64)

    platform = IOSPlatform()
    ctx = build_context(Settings(), platform=platform)
    state = PipelineState(
        cve_details=CveDetails(cve="CVE-TEST-0001", platform="ios"),
        artifacts_mode=True,
        pre_artifacts_path=str(pre),
        post_artifacts_path=str(post),
    )
    result = await platform.gather_artifacts(state, ctx)
    assert "libtest.dylib" in result.changed_files
