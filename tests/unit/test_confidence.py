"""Unit tests for confidence scoring."""

from peekaboo.analysis.confidence import compute_confidence, parse_llm_confidence


def test_compute_confidence_high():
    cb = compute_confidence(
        component_match=True,
        relevancy_score=0.9,
        function_similarity=0.3,
        re_backend="ghidra",
        llm_score=0.8,
        has_decompile=True,
    )
    assert cb.overall >= 0.7
    assert cb.function_diff == 0.7
    assert isinstance(cb.human_review_recommended, bool)


def test_compute_confidence_simple_backend_flags_review():
    cb = compute_confidence(
        component_match=True,
        relevancy_score=0.9,
        function_similarity=0.5,
        re_backend="simple",
        has_decompile=True,
    )
    assert cb.human_review_recommended is True
    assert any("byte-level" in n for n in cb.notes)


def test_parse_llm_confidence():
    assert parse_llm_confidence("Confidence: 0.82") == 0.82
    assert parse_llm_confidence("no score here") is None
