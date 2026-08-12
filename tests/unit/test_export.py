"""Unit tests for export pack."""

from pathlib import Path

from peekaboo.export.cinema import render_cinema
from peekaboo.export.pack import export_pack
from peekaboo.schemas import ConfidenceBreakdown, CveDetails, PoCBlueprint, Report


def test_export_pack_creates_files(tmp_path: Path):
    report = Report(
        cve="CVE-TEST-0001",
        platform="ios",
        file_name="libxpc.dylib",
        function_address=0x80,
        confidence=0.72,
        confidence_breakdown=ConfidenceBreakdown(overall=0.72, component_match=0.9),
        summary="Test summary",
        root_cause="Test root cause",
        diff_text="+ patched",
    )
    poc = PoCBlueprint(
        title="XPC validation gap",
        hypothesis="Missing bounds check",
        attack_vector="Malformed XPC message",
        trigger_surface="xpc_connection_send_message",
        reproduction_steps=["Connect to service", "Send malformed dictionary"],
        verification_signals=["Crash in libxpc"],
        minimal_code="# stub\npass",
        language="python",
        limitations=["Requires device"],
        poc_confidence=0.6,
    )
    out = export_pack(tmp_path, report, poc=poc)
    assert (out / "cinema.html").exists()
    assert (out / "report.md").exists()
    assert (out / "report.json").exists()
    assert (out / "poc_blueprint.json").exists()
    assert (out / "poc" / "minimal.py").exists()
    assert (out / "repro.sh").exists()
    html = (out / "cinema.html").read_text()
    assert "CVE-TEST-0001" in html
    assert "PoC Blueprint" in html


def test_cinema_renders_confidence_bars():
    report = Report(
        cve="CVE-TEST",
        platform="ios",
        confidence=0.5,
        confidence_breakdown=ConfidenceBreakdown(
            overall=0.5,
            component_match=0.8,
            human_review_recommended=True,
        ),
    )
    html = render_cinema(CveDetails(cve="CVE-TEST", platform="ios"), report)
    assert "Human review recommended" in html
    assert "Confidence breakdown" in html
