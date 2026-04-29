"""Centralized logging configuration for MCPHunt.

Usage in any module::

    from mcphunt.log import get_logger
    log = get_logger(__name__)
    log.info("message")

The CLI entry point calls ``setup_logging()`` once to configure
console format and optional file output.
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional


_CONFIGURED = False

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_FORMAT_BRIEF = "  [%(name)s] %(message)s"


def get_logger(name: str) -> logging.Logger:
    short = name.replace("mcphunt.", "")
    return logging.getLogger(f"mcphunt.{short}" if not name.startswith("mcphunt.") else name)


def setup_logging(
    level: int = logging.INFO,
    log_file: Optional[Path] = None,
    verbose: bool = False,
) -> None:
    """Configure root mcphunt logger. Call once from CLI entry point."""
    global _CONFIGURED
    if _CONFIGURED:
        return
    _CONFIGURED = True

    root = logging.getLogger("mcphunt")
    root.setLevel(level)

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(level)
    fmt = LOG_FORMAT if verbose else LOG_FORMAT_BRIEF
    console.setFormatter(logging.Formatter(fmt, datefmt="%H:%M:%S"))
    root.addHandler(console)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(str(log_file), encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter(LOG_FORMAT, datefmt="%Y-%m-%d %H:%M:%S"))
        root.addHandler(fh)
