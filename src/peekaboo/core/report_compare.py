"""Report comparison utility."""

from __future__ import annotations

import difflib

from peekaboo.schemas import Report


def compare_reports(a: Report, b: Report) -> str:
    lines = [
        f"# Report Comparison: {a.cve}",
        "",
        f"## A ({a.model}) — confidence {a.confidence:.2f}",
        a.summary,
        "",
        f"## B ({b.model}) — confidence {b.confidence:.2f}",
        b.summary,
        "",
        "## Summary Diff",
        "```diff",
    ]
    lines.extend(
        difflib.unified_diff(
            a.summary.splitlines(),
            b.summary.splitlines(),
            fromfile="A",
            tofile="B",
            lineterm="",
        )
    )
    lines.append("```")
    return "\n".join(lines)
