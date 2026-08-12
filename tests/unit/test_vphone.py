"""Unit tests for vphone IPSW cache and payloads."""

from pathlib import Path

from peekaboo.config.settings import VPhoneSettings
from peekaboo.schemas import CveDetails, PoCBlueprint
from peekaboo.validation.vphone.ipsw_cache import find_cached_ipsw, materialize_ipsw
from peekaboo.validation.vphone.payloads import build_validation_payload, guest_trigger_command


def test_find_cached_ipsw_by_build(tmp_path: Path):
    cache = tmp_path / "ipsws"
    cache.mkdir()
    ipsw = cache / "iPhone17,3_26.5.2_23F84_Restore.ipsw"
    ipsw.write_bytes(b"x" * 64)

    settings = VPhoneSettings(library_root=tmp_path)
    found = find_cached_ipsw("23F84", "iPhone16,1", settings)
    assert found == ipsw


def test_materialize_ipsw_symlink(tmp_path: Path):
    src = tmp_path / "test.ipsw"
    src.write_bytes(b"data")
    dest_dir = tmp_path / "work"
    out = materialize_ipsw(src, dest_dir, build="23F84")
    assert out.exists()


def test_imageio_payload_and_command(tmp_path: Path):
    details = CveDetails(cve="CVE-TEST", platform="ios", component="ImageIO")
    path = build_validation_payload(tmp_path, details, None)
    assert path.suffix == ".heic"
    cmd = guest_trigger_command(path.name, details)
    assert "sips" in cmd
