"""Unit tests for PoC JSON extraction."""

from peekaboo.analysis.poc_generator import _extract_json, _sanitize_poc
from peekaboo.schemas import PoCBlueprint


def test_extract_json_from_fenced():
    raw = '```json\n{"title": "test", "hypothesis": "h", "poc_confidence": 0.5}\n```'
    data = _extract_json(raw)
    assert data["title"] == "test"


def test_sanitize_poc_flags_unknown():
    poc = PoCBlueprint(
        title="t",
        hypothesis="h",
        attack_vector="a",
        trigger_surface="s",
        minimal_code="void f() { /* UNKNOWN offset */ }",
        poc_confidence=0.9,
    )
    out = _sanitize_poc(poc, known_addr=0x1000)
    assert out.poc_confidence <= 0.75 or out.limitations
