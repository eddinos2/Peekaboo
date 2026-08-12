"""Subprocess runner with timeout."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass


class ToolError(RuntimeError):
    pass


class ToolTimeout(ToolError):
    pass


@dataclass
class ProcessResult:
    returncode: int
    stdout: str
    stderr: str


async def run(
    *argv: str,
    timeout: float = 3600.0,
    cwd: str | None = None,
) -> ProcessResult:
    if not argv:
        raise ToolError("empty argv")
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
    )
    try:
        stdout_b, stderr_b = await asyncio.wait_for(proc.communicate(), timeout=timeout)
    except asyncio.TimeoutError as exc:
        proc.kill()
        await proc.wait()
        raise ToolTimeout(f"timeout after {timeout}s: {' '.join(argv)}") from exc

    stdout = stdout_b.decode(errors="replace")
    stderr = stderr_b.decode(errors="replace")
    if proc.returncode != 0:
        raise ToolError(
            f"command failed ({proc.returncode}): {' '.join(argv)}\n{stderr or stdout}"
        )
    return ProcessResult(proc.returncode, stdout, stderr)
