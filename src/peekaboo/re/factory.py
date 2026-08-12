"""RE backend factory."""

from __future__ import annotations

from peekaboo.config.settings import Settings
from peekaboo.re.base import REBackend
from peekaboo.re.ghidra.backend import GhidraBackend
from peekaboo.re.ida.backend import IDABackend
from peekaboo.re.simple.backend import SimpleBackend


class REBackendFactory:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._ghidra = GhidraBackend(settings)
        self._ida = IDABackend(settings)
        self._simple = SimpleBackend()

    def resolve(self) -> REBackend:
        mode = self.settings.re.backend
        if mode == "simple":
            return self._simple
        if mode == "ghidra":
            return self._ghidra
        if mode == "ida":
            return self._ida
        ida_ok, _ = self._ida.health_check()
        if ida_ok:
            return self._ida
        ghidra_ok, _ = self._ghidra.health_check()
        if ghidra_ok:
            return self._ghidra
        return self._simple

    def health_check(self) -> tuple[bool, list[str]]:
        backend = self.resolve()
        return backend.health_check()
