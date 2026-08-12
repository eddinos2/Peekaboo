"""Structlog setup + progress events."""

from __future__ import annotations

import logging
import sys
import uuid
from contextvars import ContextVar
from pathlib import Path

import structlog

_cve_var: ContextVar[str | None] = ContextVar("cve", default=None)
_run_id_var: ContextVar[str | None] = ContextVar("run_id", default=None)


def bind_cve(cve: str, run_id: str | None = None) -> str:
    rid = run_id or uuid.uuid4().hex[:12]
    _cve_var.set(cve)
    _run_id_var.set(rid)
    structlog.contextvars.bind_contextvars(cve=cve, run_id=rid)
    return rid


def clear_cve() -> None:
    _cve_var.set(None)
    _run_id_var.set(None)
    structlog.contextvars.clear_contextvars()


def setup_logging(logs_dir: Path, level: str = "info") -> Path:
    logs_dir.mkdir(parents=True, exist_ok=True)
    log_file = logs_dir / f"{uuid.uuid4().hex}.log"

    lvl = getattr(logging, level.upper(), logging.INFO)

    shared_processors: list[structlog.types.Processor] = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(lvl),
        logger_factory=structlog.PrintLoggerFactory(file=open(log_file, "a", encoding="utf-8")),
        cache_logger_on_first_use=True,
    )

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(lvl)
    structlog.configure(
        processors=[
            *shared_processors,
            structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty()),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(lvl),
        logger_factory=structlog.PrintLoggerFactory(),
        cache_logger_on_first_use=False,
    )

    return log_file


def get_logger(name: str | None = None):
    return structlog.get_logger(name)
