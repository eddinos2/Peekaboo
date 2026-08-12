"""vphone-cli integration for iOS dynamic validation."""

from peekaboo.validation.vphone.client import VPhoneClient, resolve_vphone_bin
from peekaboo.validation.vphone.validate import run_vphone_validation

__all__ = ["VPhoneClient", "resolve_vphone_bin", "run_vphone_validation"]
