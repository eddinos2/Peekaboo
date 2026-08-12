"""Platform plugin protocols."""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    import click

    from peekaboo.core.app_context import AppContext
    from peekaboo.schemas import CveDetails, GatherResult, PipelineState


class UnknownPlatform(KeyError):
    pass


class UnsupportedPlatform(LookupError):
    pass


class PlatformNotReady(RuntimeError):
    pass


class RECategory(str, Enum):
    BINARY = "binary"
    SOURCE = "source"


class Platform(Protocol):
    name: str

    async def enrich_cve(self, state: PipelineState, ctx: AppContext) -> dict[str, Any]: ...

    async def gather_artifacts(self, state: PipelineState, ctx: AppContext) -> GatherResult: ...

    def candidate_metadata(self, cve: CveDetails) -> dict[str, Any]: ...

    def classify_candidate(self, name: str) -> RECategory: ...


class PlatformProvider(Protocol):
    name: str

    def cli_group(self) -> click.Group: ...

    def health_check(self, ctx: AppContext) -> tuple[bool, list[str]]: ...

    async def matches_native(self, cve_id: str, ctx: AppContext) -> Platform | None: ...

    def matches_nvd(self, cpes: list[str], ctx: AppContext) -> Platform | None: ...

    def resolve(self, ctx: AppContext, **overrides: Any) -> Platform: ...
