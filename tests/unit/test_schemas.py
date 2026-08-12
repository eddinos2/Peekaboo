"""Unit tests for schemas."""

from peekaboo.schemas import CveDetails, Report


def test_report_markdown():
    report = Report(
        cve="CVE-2024-0001",
        platform="ios",
        file_name="libxpc.dylib",
        function_name="sub_1000",
        function_address=0x1000,
        confidence=0.85,
        summary="Buffer overflow fixed.",
        root_cause="Missing bounds check.",
    )
    md = report.to_markdown()
    assert "CVE-2024-0001" in md
    assert "libxpc.dylib" in md
