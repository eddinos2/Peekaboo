"""ISO-BMFF / HEIC structure-aware mutator for ImageIO targets."""

from __future__ import annotations

import random
import struct
from dataclasses import dataclass


@dataclass
class MutationOp:
    name: str
    description: str


OPS = [
    MutationOp("box_size_overflow", "Declare box size larger than payload"),
    MutationOp("nested_meta", "Deeply nest meta/iloc boxes"),
    MutationOp("zero_extent", "Zero-length extent in iloc"),
    MutationOp("truncated_ftyp", "Truncate ftyp payload"),
    MutationOp("bad_brand", "Invalid ftyp brand fourcc"),
]


def base_heic_seed() -> bytes:
    ftyp = struct.pack(">I4s4s", 24, b"ftyp", b"heic") + b"mif1" + b"\x00" * 8
    meta = struct.pack(">I4s", 32, b"meta") + b"\x00" * 4 + b"\x00" * 20
    mdat = struct.pack(">I4s", 16, b"mdat") + b"\x41" * 8
    return ftyp + meta + mdat


def mutate_heic(data: bytes, rng: random.Random, *, op: str | None = None) -> tuple[bytes, str]:
    """Return (mutated_bytes, operation_name)."""
    chosen = op or rng.choice([o.name for o in OPS])
    buf = bytearray(data)

    if chosen == "box_size_overflow" and len(buf) >= 8:
        buf[0:4] = struct.pack(">I", 0xFFFFFFFF)
    elif chosen == "nested_meta":
        inner = struct.pack(">I4s", 16, b"meta") + b"\x00" * 8
        buf += inner * rng.randint(3, 12)
    elif chosen == "zero_extent":
        buf += struct.pack(">I4s", 12, b"iloc") + b"\x00" * 4
    elif chosen == "truncated_ftyp":
        buf = buf[: max(12, len(buf) // 2)]
    elif chosen == "bad_brand":
        if len(buf) >= 12:
            buf[8:12] = b"XXXX"
    else:
        idx = rng.randint(0, max(0, len(buf) - 1))
        buf[idx] ^= 1 << rng.randint(0, 7)

    return bytes(buf), chosen


def llm_ops_from_hints(hints: list[str]) -> list[str]:
    """Map LLM mutation hints to known ops."""
    mapped: list[str] = []
    text = " ".join(hints).lower()
    if "overflow" in text or "integer" in text or "size" in text:
        mapped.append("box_size_overflow")
    if "nested" in text or "recurs" in text:
        mapped.append("nested_meta")
    if "truncat" in text or "length" in text:
        mapped.append("truncated_ftyp")
    if "extent" in text or "iloc" in text:
        mapped.append("zero_extent")
    return mapped or [o.name for o in OPS]
