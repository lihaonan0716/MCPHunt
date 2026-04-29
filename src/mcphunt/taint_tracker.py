"""Runtime taint tracking defense for MCP agent orchestration.

Monitors data flow from read operations to write operations.  When write
arguments contain canary values that were previously observed in read
results, the write is blocked and the tainted values are replaced with a
redaction marker.  This proves that orchestration-layer taint tracking
can prevent data leakage without relying on model compliance.

Design:
    - Substring matching against a known canary set (exact + fragment).
    - Only sanitizes the *arguments dict* before it reaches the MCP server;
      never modifies actual workspace files or databases.
    - Fully opt-in: existing experiments without ``--defense`` are unaffected.
"""
from __future__ import annotations

import copy
import json
import time
from typing import Any, Dict, List, Set, Tuple

from .canary_registry import Canary, get_canaries, build_taint_registry
from .taxonomy import WRITE_TOOLS, READ_TOOLS, BROWSER_INPUT_TOOLS
from .text_utils import strip_md_escapes as _strip_md_escapes

EXFIL_TOOLS = frozenset({"fetch", "browser_navigate"})

REDACTED = "<REDACTED:taint_blocked>"


class TaintTracker:
    """Runtime taint tracking: monitors data flow from reads to writes."""

    def __init__(self, canary_values: List[Canary]) -> None:
        """Initialize with known canary values to track.

        Parameters
        ----------
        canary_values:
            ``Canary`` objects for the current environment variant.
        """
        self._canaries = canary_values
        # Full canary values that have been observed in read results
        self._tainted_values: Set[str] = set()
        # Core fragments that have been observed in read results
        self._tainted_cores: Set[str] = set()
        # Reverse map: tainted string -> canary id (for reporting)
        self._value_to_id: Dict[str, str] = {c.value: c.id for c in canary_values}
        self._core_to_id: Dict[str, str] = {c.core: c.id for c in canary_values}

        # Statistics
        self._reads_observed: int = 0
        self._writes_checked: int = 0
        self._writes_blocked: int = 0
        self._values_redacted: int = 0
        self._blocked_details: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Observation (read side)
    # ------------------------------------------------------------------

    def observe_read(self, tool: str, result: str) -> None:
        """Record canary values found in a read result.

        Called after every read tool call so that newly-seen canary values
        are added to the taint set.
        """
        self._reads_observed += 1
        cleaned = _strip_md_escapes(result)
        for c in self._canaries:
            if c.value in cleaned:
                self._tainted_values.add(c.value)
                self._tainted_cores.add(c.core)
            elif c.core in cleaned:
                self._tainted_cores.add(c.core)

    # ------------------------------------------------------------------
    # Enforcement (write side)
    # ------------------------------------------------------------------

    def check_write(self, tool: str, args: dict) -> Tuple[bool, dict, str]:
        """Check if write args contain tainted data.

        Returns
        -------
        is_tainted : bool
            True if any tainted canary value or fragment was found.
        sanitized_args : dict
            A deep copy of *args* with tainted substrings replaced by
            ``<REDACTED:taint_blocked>``.  Identical to *args* when
            ``is_tainted`` is False.
        report : str
            Human-readable summary (empty when not tainted).
        """
        self._writes_checked += 1

        if not self._tainted_values and not self._tainted_cores:
            return False, args, ""

        args_str = _strip_md_escapes(json.dumps(args, ensure_ascii=False))
        found_ids: List[str] = []

        # Check full values first (more specific), then fragments
        for val in self._tainted_values:
            if val in args_str:
                cid = self._value_to_id.get(val, "unknown")
                found_ids.append(f"{cid}(verbatim)")
        for core in self._tainted_cores:
            if core in args_str:
                cid = self._core_to_id.get(core, "unknown")
                tag = f"{cid}(fragment)"
                if tag not in found_ids:
                    found_ids.append(tag)

        if not found_ids:
            return False, args, ""

        # Tainted — produce sanitized args
        sanitized = self._sanitize(args)
        self._writes_blocked += 1
        self._values_redacted += len(found_ids)

        report = (
            f"TAINT BLOCKED: {tool} write contained {len(found_ids)} tainted "
            f"value(s): {', '.join(found_ids)}"
        )
        self._blocked_details.append({
            "tool": tool,
            "tainted_ids": found_ids,
            "timestamp": time.time(),
        })

        return True, sanitized, report

    # ------------------------------------------------------------------
    # Sanitization helpers
    # ------------------------------------------------------------------

    def _sanitize(self, args: dict) -> dict:
        """Return a deep copy of *args* with all tainted substrings replaced."""
        sanitized = copy.deepcopy(args)
        self._sanitize_dict(sanitized)
        return sanitized

    def _sanitize_dict(self, d: dict) -> None:
        for key, value in d.items():
            if isinstance(value, str):
                d[key] = self._sanitize_string(value)
            elif isinstance(value, dict):
                self._sanitize_dict(value)
            elif isinstance(value, list):
                self._sanitize_list(value)

    def _sanitize_list(self, lst: list) -> None:
        for i, item in enumerate(lst):
            if isinstance(item, str):
                lst[i] = self._sanitize_string(item)
            elif isinstance(item, dict):
                self._sanitize_dict(item)
            elif isinstance(item, list):
                self._sanitize_list(item)

    def _sanitize_string(self, s: str) -> str:
        # Replace full values first (longer matches before fragments)
        for val in sorted(self._tainted_values, key=len, reverse=True):
            if val in s:
                s = s.replace(val, REDACTED)
        # Then replace remaining fragment matches
        for core in sorted(self._tainted_cores, key=len, reverse=True):
            if core in s:
                s = s.replace(core, REDACTED)
        return s

    # ------------------------------------------------------------------
    # Reporting
    # ------------------------------------------------------------------

    def get_stats(self) -> dict:
        """Return tracking statistics."""
        return {
            "reads_observed": self._reads_observed,
            "tainted_values_seen": len(self._tainted_values),
            "tainted_cores_seen": len(self._tainted_cores),
            "writes_checked": self._writes_checked,
            "writes_blocked": self._writes_blocked,
            "values_redacted": self._values_redacted,
            "blocked_details": self._blocked_details,
        }
