#!/usr/bin/env python3
"""Sanitize trace JSON files for anonymous release.

Replaces all identifying information (local usernames, machine-specific
paths) with generic placeholders.  The sanitization is:
  - Deterministic and idempotent (safe to run multiple times)
  - Structure-preserving (valid JSON in, valid JSON out, same trace count)
  - Reproducibility-preserving (task_id, env_type, outcome, labeling,
    risk_mechanism, all numeric fields are untouched)

Usage:
    python3 scripts/sanitize_traces.py                   # dry-run (report only)
    python3 scripts/sanitize_traces.py --apply           # overwrite in place
    python3 scripts/sanitize_traces.py --outdir release/  # write to separate dir
"""

import argparse
import glob
import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# ── Replacement rules (order matters: longest match first) ──────────

# All variants of the project root path (including model hallucinations)
_PROJECT_ROOT_RE = re.compile(
    r"/Users/[A-Za-z0-9_]+/[A-Za-z0-9_]*/MCPHunt/"
)
_PROJECT_ROOT_REPLACEMENT = "/mcphunt/"

# Any remaining /Users/<username> paths (with or without trailing slash)
_USER_HOME_RE = re.compile(r"/Users/[A-Za-z0-9_]*/?")

_USER_HOME_REPLACEMENT = "/home/user/"

# PyCharmProjects directory name (survives in PATH env vars after user home replacement)
_PYCHARM_RE = re.compile(r"PyCharmProjects")
_PYCHARM_REPLACEMENT = "projects"

# Bare username in ls output, git log, file ownership, etc.
# Use non-word-boundary-safe pattern to catch all occurrences
_BARE_USERNAME_RE = re.compile(r"lihaonan")
_BARE_USERNAME_REPLACEMENT = "user"

# Also catch variant spellings from model hallucinations
_BARE_USERNAME_VARIANT_RE = re.compile(r"lihahaonan")


def sanitize_text(raw: str) -> str:
    """Apply all sanitization rules to a raw JSON string."""
    result = _PROJECT_ROOT_RE.sub(_PROJECT_ROOT_REPLACEMENT, raw)
    result = _USER_HOME_RE.sub(_USER_HOME_REPLACEMENT, result)
    result = _PYCHARM_RE.sub(_PYCHARM_REPLACEMENT, result)
    result = _BARE_USERNAME_VARIANT_RE.sub(_BARE_USERNAME_REPLACEMENT, result)
    result = _BARE_USERNAME_RE.sub(_BARE_USERNAME_REPLACEMENT, result)
    return result


def validate_sanitization(original: str, sanitized: str, filepath: str) -> list[str]:
    """Check that sanitization didn't break anything."""
    errors = []

    # 1. Must still be valid JSON
    try:
        d_orig = json.loads(original)
        d_san = json.loads(sanitized)
    except json.JSONDecodeError as e:
        errors.append(f"JSON parse error after sanitization: {e}")
        return errors

    # 2. Trace count must match
    if "traces" in d_orig:
        n_orig = len(d_orig["traces"])
        n_san = len(d_san["traces"])
        if n_orig != n_san:
            errors.append(f"Trace count changed: {n_orig} -> {n_san}")

        # 3. Critical fields must be identical
        for i, (to, ts) in enumerate(zip(d_orig["traces"], d_san["traces"])):
            for field in [
                "task_id", "env_type", "outcome", "risk_mechanism",
                "risk_type", "model", "num_events", "num_turns",
                "task_completed", "duration_s", "api_errors",
            ]:
                vo = to.get(field)
                vs = ts.get(field)
                if vo != vs:
                    errors.append(
                        f"trace[{i}].{field} changed: {vo!r} -> {vs!r}"
                    )
                    if len(errors) > 10:
                        errors.append("... (truncated)")
                        return errors

            # 4. Labeling signals must be identical
            lo = to.get("labeling", {}).get("risk_signals", {})
            ls = ts.get("labeling", {}).get("risk_signals", {})
            if lo != ls:
                errors.append(f"trace[{i}].labeling.risk_signals changed")

    # 5. No sensitive strings remain
    for pattern in ["lihaonan", "lihahaonan", "PyCharmProjects", "/Users/"]:
        if pattern in sanitized:
            errors.append(f"Residual sensitive string: '{pattern}'")

    return errors


def find_trace_files() -> list[Path]:
    """Find all JSON files under results/."""
    results_dir = REPO / "results"
    return sorted(results_dir.glob("**/*.json"))


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true",
                        help="Overwrite files in place (default: dry-run)")
    parser.add_argument("--outdir", type=str, default=None,
                        help="Write sanitized files to this directory instead of in-place")
    args = parser.parse_args()

    files = find_trace_files()
    print(f"Found {len(files)} JSON files under results/")

    total_replacements = 0
    total_errors = 0

    for filepath in files:
        raw = filepath.read_text(encoding="utf-8")
        sanitized = sanitize_text(raw)

        n_changes = sum(
            len(r.findall(raw)) for r in [
                _PROJECT_ROOT_RE, _USER_HOME_RE, _PYCHARM_RE,
                _BARE_USERNAME_RE, _BARE_USERNAME_VARIANT_RE,
            ]
        )

        errors = validate_sanitization(raw, sanitized, str(filepath))

        rel = filepath.relative_to(REPO)
        status = "OK" if not errors else "ERRORS"
        print(f"  {rel}: {n_changes} replacements [{status}]")
        for e in errors:
            print(f"    ERROR: {e}")
            total_errors += 1

        total_replacements += n_changes

        if n_changes > 0 and not errors:
            if args.outdir:
                out_path = Path(args.outdir) / rel
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(sanitized, encoding="utf-8")
            elif args.apply:
                filepath.write_text(sanitized, encoding="utf-8")

    print(f"\nTotal: {total_replacements} replacements across {len(files)} files, {total_errors} errors")

    if not args.apply and not args.outdir:
        print("\nDry run — no files modified. Use --apply to overwrite or --outdir DIR to write copies.")

    return 1 if total_errors > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
