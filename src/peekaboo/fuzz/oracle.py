"""Execute inputs against host parsers / tools."""

from __future__ import annotations

import asyncio
import hashlib
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path


@dataclass
class ExecSignal:
    crashed: bool = False
    timed_out: bool = False
    returncode: int = 0
    stderr: str = ""
    stdout: str = ""
    output_hash: str = ""

    @property
    def interesting(self) -> bool:
        return self.crashed or self.timed_out or self.returncode != 0


async def run_sips_probe(path: Path, *, timeout: float = 5.0) -> ExecSignal:
    """Probe ImageIO via macOS sips (uses ImageIO framework)."""
    sips = shutil.which("sips")
    if not sips:
        return ExecSignal(returncode=-1, stderr="sips not found")

    proc = await asyncio.create_subprocess_exec(
        sips,
        "-g",
        "all",
        str(path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return ExecSignal(timed_out=True, stderr="timeout")

    stdout = stdout_b.decode(errors="replace")
    stderr = stderr_b.decode(errors="replace")
    crashed = proc.returncode != 0 and (
        "Abort" in stderr or "Segmentation" in stderr or proc.returncode < 0
    )
    digest = hashlib.sha256(stdout.encode()).hexdigest()[:16]
    return ExecSignal(
        crashed=crashed,
        returncode=proc.returncode or 0,
        stdout=stdout[:500],
        stderr=stderr[:500],
        output_hash=digest,
    )


async def execute_component_input(
    data: bytes,
    component: str,
    *,
    suffix: str = ".heic",
) -> ExecSignal:
    with tempfile.TemporaryDirectory(prefix="peekaboo-fuzz-") as tmp:
        path = Path(tmp) / f"input{suffix}"
        path.write_bytes(data)
        comp = component.lower()
        if "imageio" in comp or "image" in comp or suffix in (".heic", ".jpg", ".png"):
            return await run_sips_probe(path)
        return ExecSignal(returncode=0, stdout="no executor configured")
