"""Unit tests for validate node (mocked vphone)."""

from unittest.mock import AsyncMock, patch

import pytest

from peekaboo.config.settings import Settings
from peekaboo.core.bootstrap import build_context
from peekaboo.graphs.pipeline.nodes import validate_node
from peekaboo.platforms.ios.platform import IOSPlatform
from peekaboo.schemas import CveDetails, PipelineState, Stage


@pytest.mark.asyncio
async def test_validate_node_skipped_when_disabled():
    settings = Settings()
    settings = settings.model_copy(update={"vphone": settings.vphone.model_copy(update={"enabled": False})})
    ctx = build_context(settings, platform=IOSPlatform())
    state = PipelineState(
        cve_details=CveDetails(cve="CVE-TEST", platform="ios"),
        skip_vphone=True,
    )
    result = await validate_node(state, ctx)
    assert result["stage"] == Stage.VALIDATE
    assert result["validation"].status == "skipped"


@pytest.mark.asyncio
async def test_validate_node_readiness_ok():
    settings = Settings()
    ctx = build_context(settings, platform=IOSPlatform())
    state = PipelineState(cve_details=CveDetails(cve="CVE-TEST", platform="ios"))

    with patch(
        "peekaboo.graphs.pipeline.nodes.vphone_status",
        AsyncMock(return_value=(True, [], ["binary: /usr/local/bin/vphone-cli"])),
    ):
        result = await validate_node(state, ctx)

    assert result["stage"] == Stage.VALIDATE
    assert "Will attempt crash compare" in " ".join(result["validation"].notes)
