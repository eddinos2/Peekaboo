"""ipsw CLI wrapper."""

from __future__ import annotations

import asyncio
import shutil
from pathlib import Path

from peekaboo.tools.process import ToolError, run


def resolve_ipsw_bin(configured: str | None) -> str:
    if configured and Path(configured).exists():
        return configured
    found = shutil.which("ipsw")
    if found:
        return found
    raise RuntimeError("ipsw CLI not found — install from https://github.com/blacktop/ipsw")


async def download_ipsw(
    dest_dir: Path,
    *,
    ipsw_bin: str,
    device: str,
    build: str,
    url: str | None = None,
    vphone_settings=None,
) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    if url:
        expected = dest_dir / url.rsplit("/", 1)[-1]
        if expected.exists():
            return expected
    matches = list(dest_dir.glob(f"*{build}*.ipsw"))
    if matches:
        return matches[0]

    if vphone_settings is not None and getattr(vphone_settings, "ipsw_cache_enabled", True):
        from peekaboo.validation.vphone.ipsw_cache import find_cached_ipsw, materialize_ipsw

        cached = find_cached_ipsw(build, device, vphone_settings)
        if cached and cached.stat().st_size > 1_000_000_000:
            return materialize_ipsw(cached, dest_dir, build=build)

    last_err: Exception | None = None
    for attempt in range(1, 11):
        try:
            await run(
                ipsw_bin,
                "download",
                "ipsw",
                "--device",
                device,
                "--build",
                build,
                "-y",
                "--resume-all",
                "-o",
                str(dest_dir),
                timeout=14400,
            )
            break
        except ToolError as exc:
            last_err = exc
            if attempt >= 10:
                raise
            await asyncio.sleep(min(60 * attempt, 300))
    else:
        if last_err:
            raise last_err
    if url:
        expected = dest_dir / url.rsplit("/", 1)[-1]
        if expected.exists():
            return expected
    matches = list(dest_dir.glob(f"*{build}*.ipsw")) or list(dest_dir.glob("*.ipsw"))
    if matches:
        return matches[0]
    raise RuntimeError(f"IPSW download failed for {device} build {build}")


async def diff_ipsw(
    pre_ipsw: Path,
    post_ipsw: Path,
    output_dir: Path,
    *,
    ipsw_bin: str,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    await run(
        ipsw_bin,
        "diff",
        "--output", str(output_dir),
        "--markdown",
        str(pre_ipsw),
        str(post_ipsw),
        timeout=3600,
    )
    md_files = list(output_dir.glob("*.md"))
    if md_files:
        return md_files[0]
    return output_dir / "diff.md"


def parse_diff_markdown(md_path: Path) -> list[str]:
    if not md_path.exists():
        return []
    changed: list[str] = []
    for line in md_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line.startswith("|") and ".dylib" in line.lower():
            parts = [p.strip() for p in line.split("|") if p.strip()]
            if parts:
                changed.append(parts[0])
        elif ".dylib" in line.lower() or ".framework" in line.lower():
            token = line.split()[0].strip("`")
            if token:
                changed.append(token)
    return changed


async def extract_dylib(
    ipsw_path: Path,
    dylib_name: str,
    output_dir: Path,
    *,
    ipsw_bin: str,
) -> Path | None:
    output_dir.mkdir(parents=True, exist_ok=True)
    try:
        await run(
            ipsw_bin,
            "extract",
            "--dyld",
            str(ipsw_path),
            "-o",
            str(output_dir),
            timeout=3600,
        )
    except Exception:
        pass
    matches = list(output_dir.rglob(f"*{dylib_name}*"))
    return matches[0] if matches else None
