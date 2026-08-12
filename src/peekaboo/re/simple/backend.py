"""Lightweight RE backend for demo/testing without Ghidra."""

from __future__ import annotations

import hashlib
from pathlib import Path

from peekaboo.re.base import DiffResult


class SimpleBackend:
    """Byte-level diff backend — no Ghidra required."""

    name = "simple"

    async def export_binary(self, path: Path, work_dir: Path) -> Path:
        work_dir.mkdir(parents=True, exist_ok=True)
        out = work_dir / f"{path.stem}.hash"
        out.write_text(hashlib.sha256(path.read_bytes()).hexdigest(), encoding="utf-8")
        return out

    async def diff_pair(self, primary: Path, secondary: Path, work_dir: Path) -> DiffResult:
        pre = primary.read_bytes()
        post = secondary.read_bytes()
        if pre == post:
            return DiffResult()

        chunk = 64
        changed: list[tuple[int, str, float]] = []
        max_len = max(len(pre), len(post))
        for offset in range(0, max_len, chunk):
            pre_chunk = pre[offset : offset + chunk]
            post_chunk = post[offset : offset + chunk]
            if pre_chunk != post_chunk:
                ratio = 0.0 if pre_chunk != post_chunk else 1.0
                changed.append((offset, f"chunk_{offset:x}", ratio))
        return DiffResult(changed_functions=changed[:10])

    async def decompile_functions(
        self, binary: Path, addresses: list[int], work_dir: Path
    ) -> dict[int, str]:
        data = binary.read_bytes()
        out: dict[int, str] = {}
        for addr in addresses:
            snippet = data[addr : addr + 32]
            hex_dump = " ".join(f"{b:02x}" for b in snippet)
            out[addr] = f"// simple backend pseudo-decompile @ 0x{addr:x}\n// bytes: {hex_dump}"
        return out

    def health_check(self) -> tuple[bool, list[str]]:
        return True, []
