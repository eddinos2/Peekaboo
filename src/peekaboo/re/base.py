"""RE backend protocol and types."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol


@dataclass
class DiffResult:
    changed_functions: list[tuple[int, str, float]] = field(default_factory=list)
    bindiff_db: Path | None = None
    primary_export: Path | None = None
    secondary_export: Path | None = None


class REBackend(Protocol):
    name: str

    async def export_binary(self, path: Path, work_dir: Path) -> Path: ...

    async def diff_pair(
        self, primary: Path, secondary: Path, work_dir: Path
    ) -> DiffResult: ...

    async def decompile_functions(
        self, binary: Path, addresses: list[int], work_dir: Path
    ) -> dict[int, str]: ...

    def health_check(self) -> tuple[bool, list[str]]: ...
