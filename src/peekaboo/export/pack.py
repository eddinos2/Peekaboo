"""Export pack — bundle report, cinema, PoC, repro script."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from peekaboo.export.cinema import render_cinema
from peekaboo.schemas import CveDetails, PoCBlueprint, Report, ValidationResult, FuzzCampaignResult


def export_pack(
    dest: Path,
    report: Report,
    details: CveDetails | None = None,
    poc: PoCBlueprint | None = None,
    *,
    repro_command: str | None = None,
    validation: ValidationResult | None = None,
    fuzz: FuzzCampaignResult | None = None,
) -> Path:
    """Write a portfolio-ready export directory. Returns dest path."""
    slug = f"{report.cve}_{report.file_name}_{report.function_address:x}".replace("/", "_")
    out = dest / slug
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    (out / "report.md").write_text(report.to_markdown(), encoding="utf-8")
    (out / "report.json").write_text(report.model_dump_json(indent=2), encoding="utf-8")
    (out / "cinema.html").write_text(render_cinema(details, report, poc), encoding="utf-8")

    if poc:
        (out / "poc_blueprint.json").write_text(poc.model_dump_json(indent=2), encoding="utf-8")
        (out / "poc").mkdir(exist_ok=True)
        ext = {"python": "py", "c": "c", "pseudo": "txt"}.get(poc.language, "txt")
        (out / "poc" / f"minimal.{ext}").write_text(poc.minimal_code, encoding="utf-8")
        (out / "poc" / "README.md").write_text(poc.to_markdown(), encoding="utf-8")

    meta = {
        "cve": report.cve,
        "platform": report.platform,
        "confidence": report.confidence,
        "human_review_recommended": report.confidence_breakdown.human_review_recommended,
        "has_poc": poc is not None,
        "poc_confidence": poc.poc_confidence if poc else None,
        "vphone_validation": validation.status if validation else None,
        "fuzz_interesting": fuzz.interesting_count if fuzz else None,
    }
    (out / "meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    if fuzz and fuzz.findings:
        fuzz_dir = out / "fuzz"
        fuzz_dir.mkdir(exist_ok=True)
        (fuzz_dir / "campaign.json").write_text(fuzz.model_dump_json(indent=2), encoding="utf-8")
        for finding in fuzz.top_findings(10):
            src = Path(finding.sample_path)
            if src.exists():
                shutil.copy2(src, fuzz_dir / src.name)

    if validation:
        val_dir = out / "validation"
        val_dir.mkdir(exist_ok=True)
        (val_dir / "result.json").write_text(validation.model_dump_json(indent=2), encoding="utf-8")
        if validation.log_excerpt:
            (val_dir / "guest_output.txt").write_text(validation.log_excerpt, encoding="utf-8")
        if validation.payload_path and Path(validation.payload_path).exists():
            shutil.copy2(validation.payload_path, val_dir / Path(validation.payload_path).name)

    repro = repro_command or f"peekaboo cached --cve {report.cve}"
    (out / "repro.sh").write_text(
        f"#!/usr/bin/env bash\n# Reproduce or view this analysis\nset -euo pipefail\n{repro}\n",
        encoding="utf-8",
    )
    (out / "repro.sh").chmod(0o755)

    return out
