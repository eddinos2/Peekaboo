"""Generate component-aware test payloads for vphone validation."""

from __future__ import annotations

from pathlib import Path

from peekaboo.schemas import CveDetails, PoCBlueprint


def build_validation_payload(
    work_dir: Path,
    details: CveDetails,
    poc: PoCBlueprint | None,
) -> Path:
    """Write a minimal trigger file for dynamic validation."""
    work_dir.mkdir(parents=True, exist_ok=True)
    component = (details.component or "").lower()

    if "imageio" in component or "image" in (details.description or "").lower():
        path = work_dir / "peekaboo_trigger.heic"
        path.write_bytes(_minimal_heic_stub())
        return path

    if poc and poc.minimal_code.strip():
        ext = {"python": "py", "c": "c"}.get(poc.language, "txt")
        path = work_dir / f"peekaboo_poc.{ext}"
        path.write_text(poc.minimal_code, encoding="utf-8")
        return path

    path = work_dir / "peekaboo_trigger.bin"
    path.write_bytes(b"\x00" * 256 + b"\xff" * 64)
    return path


def guest_trigger_command(payload_name: str, details: CveDetails) -> str:
    """Shell command to exercise the payload inside the guest."""
    component = (details.component or "").lower()
    remote = f"/tmp/{payload_name}"
    if "imageio" in component or payload_name.endswith((".heic", ".jpg", ".png")):
        return (
            f"file {remote} 2>/dev/null; "
            f"(/usr/bin/sips -g all {remote} 2>&1 || true); "
            f"(/usr/bin/mdls {remote} 2>&1 || true)"
        )
    return f"file {remote}; ls -la {remote}"


def _minimal_heic_stub() -> bytes:
    """Tiny malformed HEIC-ish blob to hit ImageIO parser paths (research stub)."""
    # ftyp box + minimal meta — not a valid image; enough to reach parser entry
    ftyp = b"\x00\x00\x00\x18ftypheic\x00\x00\x00\x00heicmif1"
    meta = b"\x00\x00\x00\x20meta\x00\x00\x00\x00" + b"\xff" * 24
    return ftyp + meta + (b"\x00" * 512)
