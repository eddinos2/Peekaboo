"""Tests for grammar mutator."""

import random

from peekaboo.fuzz.mutators.imageio_heic import base_heic_seed, llm_ops_from_hints, mutate_heic


def test_mutate_heic_produces_variants():
    seed = base_heic_seed()
    rng = random.Random(42)
    out, op = mutate_heic(seed, rng)
    assert op
    assert out != seed or op == "truncated_ftyp"


def test_llm_ops_mapping():
    ops = llm_ops_from_hints(["integer overflow in box size"])
    assert "box_size_overflow" in ops
