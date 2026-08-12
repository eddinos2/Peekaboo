"""IDA + BinDiff backend stub."""

from __future__ import annotations

import shutil
from pathlib import Path

from peekaboo.config.settings import Settings
from peekaboo.re.base import DiffResult


class IDABackend:
    name = "ida"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _ida_path(self) -> Path | None:
        if self.settings.tools.ida:
            return Path(self.settings.tools.ida)
        for pattern in [
            "/Applications/IDA Professional 9.0/idat64",
            "/Applications/IDA Professional 8.4/idat64",
            "C:/Program Files/IDA Professional 9.3/idat64.exe",
        ]:
            p = Path(pattern)
            if p.exists():
                return p
        return None

    async def export_binary(self, path: Path, work_dir: Path) -> Path:
        raise NotImplementedError(
            "IDA export requires idalib or idat subprocess wiring. "
            "Configure tools.ida and install BinDiff plugins, or use re.backend=ghidra."
        )

    async def diff_pair(self, primary: Path, secondary: Path, work_dir: Path) -> DiffResult:
        bindiff = self.settings.tools.bindiff
        if not bindiff or not Path(bindiff).exists():
            raise NotImplementedError("BinDiff not configured (tools.bindiff)")
        raise NotImplementedError("IDA+BinDiff diff_pair not yet implemented on this host")

    async def decompile_functions(
        self, binary: Path, addresses: list[int], work_dir: Path
    ) -> dict[int, str]:
        raise NotImplementedError("IDA decompile requires idalib — use ghidra backend for now")

    def health_check(self) -> tuple[bool, list[str]]:
        issues: list[str] = []
        if not self._ida_path():
            issues.append("IDA not found: set tools.ida")
        if not self.settings.tools.bindiff:
            issues.append("BinDiff not configured: set tools.bindiff")
        return len(issues) == 0, issues
