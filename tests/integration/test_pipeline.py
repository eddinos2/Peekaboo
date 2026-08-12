"""Pipeline integration test with mocked RE and LLM."""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from peekaboo.config.settings import Settings
from peekaboo.core.bootstrap import build_context
from peekaboo.core.orchestrator import run_cve
from peekaboo.platforms.ios.platform import IOSPlatform
from peekaboo.re.base import DiffResult
from peekaboo.schemas import CveDetails, PoCBlueprint


@pytest.mark.asyncio
async def test_pipeline_artifacts_mode(tmp_path: Path, monkeypatch):
    pre = tmp_path / "pre"
    post = tmp_path / "post"
    pre.mkdir()
    post.mkdir()
    (pre / "libxpc.dylib").write_bytes(b"\x00" * 128)
    (post / "libxpc.dylib").write_bytes(b"\x01" * 128)

    settings = Settings()
    platform = IOSPlatform(device="iPhone16,1")
    ctx = build_context(settings, platform=platform)

    mock_backend = MagicMock()
    mock_backend.name = "ghidra"
    mock_backend.diff_pair = AsyncMock(
        return_value=DiffResult(changed_functions=[(0x1000, "sub_1000", 0.5)])
    )
    mock_backend.decompile_functions = AsyncMock(
        side_effect=[
            {0x1000: "void pre() { bad(); }"},
            {0x1000: "void pre() { check(); bad(); }"},
        ]
    )
    ctx.re_factory.resolve = MagicMock(return_value=mock_backend)

    mock_llm = MagicMock()
    mock_resp = MagicMock()
    mock_resp.content = (
        "Summary: bounds check added.\n"
        "Root cause: missing validation.\n"
        "Confidence: 0.78"
    )
    mock_llm.ainvoke = AsyncMock(return_value=mock_resp)
    ctx.models.chat_for = MagicMock(return_value=mock_llm)

    async def fake_poc(ctx, details, art, report, fuzz=None):
        return PoCBlueprint(
            title="libxpc validation test",
            hypothesis="Missing bounds check on XPC payload",
            attack_vector="Malformed XPC dictionary",
            trigger_surface="xpc_connection_send_message",
            reproduction_steps=["Attach to service", "Send malformed message"],
            verification_signals=["Crash or errno change"],
            minimal_code="def test_poc():\n    # UNKNOWN: service name\n    pass",
            language="python",
            limitations=["Requires on-device validation"],
            poc_confidence=0.55,
        )

    monkeypatch.setattr(
        "peekaboo.graphs.pipeline.nodes.generate_poc_blueprint",
        fake_poc,
    )

    result = await run_cve(
        ctx,
        "CVE-TEST-0001",
        pre_artifacts=str(pre),
        post_artifacts=str(post),
    )

    assert len(result.reports) == 1
    report = result.reports[0]
    assert report.file_name == "libxpc.dylib"
    assert report.confidence > 0
    assert report.confidence_breakdown.overall == report.confidence
    assert report.poc is not None
    assert report.export_path
    assert Path(report.export_path, "cinema.html").exists()
    assert Path(report.export_path, "poc", "minimal.py").exists()
