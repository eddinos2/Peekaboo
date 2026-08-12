"""Ghidra headless RE backend."""

from __future__ import annotations

import asyncio
import difflib
import json
import re
import shutil
from pathlib import Path

import structlog

from peekaboo.config.settings import Settings
from peekaboo.re.base import DiffResult
from peekaboo.tools.process import run

log = structlog.get_logger(__name__)


class GhidraBackend:
    name = "ghidra"

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def _ghidra_root(self) -> Path | None:
        if self.settings.tools.ghidra:
            return Path(self.settings.tools.ghidra)
        for candidate in [
            Path("/Applications/ghidra_11.3.2_PUBLIC"),
            Path("/Applications/ghidra_11.2.1_PUBLIC"),
            Path("/Applications/ghidra_11.1.2_PUBLIC"),
            Path.home() / "ghidra",
        ]:
            if candidate.exists():
                return candidate
        return None

    def _analyze_headless(self) -> Path | None:
        root = self._ghidra_root()
        if not root:
            return None
        path = root / "support" / "analyzeHeadless"
        return path if path.exists() else None

    async def export_binary(self, path: Path, work_dir: Path) -> Path:
        work_dir.mkdir(parents=True, exist_ok=True)
        out = work_dir / f"{path.stem}.json"
        await self._analyze(path, work_dir, export_json=out)
        return out

    async def _analyze(self, binary: Path, work_dir: Path, export_json: Path) -> None:
        headless = self._analyze_headless()
        if not headless:
            raise RuntimeError("Ghidra analyzeHeadless not found")
        project_dir = work_dir / "ghidra_projects"
        project_dir.mkdir(parents=True, exist_ok=True)
        script_dir = Path(__file__).parent / "scripts"
        await run(
            str(headless),
            str(project_dir),
            "Peekaboo",
            "-import", str(binary),
            "-deleteProject",
            "-postScript", str(script_dir / "ExportFunctions.py"),
            export_json.name,
            cwd=str(work_dir),
            timeout=1800,
        )

    async def diff_pair(self, primary: Path, secondary: Path, work_dir: Path) -> DiffResult:
        work_dir.mkdir(parents=True, exist_ok=True)
        pri_export = await self.export_binary(primary, work_dir / "primary")
        sec_export = await self.export_binary(secondary, work_dir / "secondary")

        pri_funcs = self._load_functions(pri_export)
        sec_funcs = self._load_functions(sec_export)

        changed: list[tuple[int, str, float]] = []
        for addr, pri_body in pri_funcs.items():
            sec_body = sec_funcs.get(addr)
            if sec_body is None:
                changed.append((addr, f"sub_{addr:x}", 0.0))
                continue
            ratio = difflib.SequenceMatcher(None, pri_body, sec_body).ratio()
            if ratio < 0.99:
                changed.append((addr, f"sub_{addr:x}", ratio))

        for addr in sec_funcs:
            if addr not in pri_funcs:
                changed.append((addr, f"sub_{addr:x}", 0.0))

        return DiffResult(changed_functions=changed)

    def _load_functions(self, export_path: Path) -> dict[int, str]:
        if not export_path.exists():
            return {}
        data = json.loads(export_path.read_text(encoding="utf-8"))
        return {int(k, 16): v for k, v in data.get("functions", {}).items()}

    async def decompile_functions(
        self, binary: Path, addresses: list[int], work_dir: Path
    ) -> dict[int, str]:
        work_dir.mkdir(parents=True, exist_ok=True)
        out: dict[int, str] = {}
        export = await self.export_binary(binary, work_dir)
        funcs = self._load_functions(export)
        for addr in addresses:
            body = funcs.get(addr, "")
            out[addr] = f"// pseudo-decompile @ 0x{addr:x}\n{body}"
        return out

    def health_check(self) -> tuple[bool, list[str]]:
        issues: list[str] = []
        if not self._analyze_headless():
            issues.append("Ghidra not found: install Ghidra 11+ or set tools.ghidra")
        return len(issues) == 0, issues
