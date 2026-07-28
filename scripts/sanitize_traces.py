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
_BARE_USERNAME_RE = re.compile(r"<local-username>")
_BARE_USERNAME_REPLACEMENT = "user"

# Also catch variant spellings from model hallucinations
_BARE_USERNAME_VARIANT_RE = re.compile(r"<local-username-typo>")

# ── Windows / VSCode collection environment rules ────────────────────
# IMPORTANT: only replace "Administrator" when it is ANCHORED to a leak
# context (a path separator, an env-var assignment, or ls ownership).
# A bare "Administrator" also occurs in legitimate trace content
# (e.g. the PyPI classifier "Intended Audience :: System Administrators"),
# so a bare \bAdministrator\b rule would corrupt real data — do NOT add one.
#
# The username token "Administrator" is preceded, across all observed leak
# forms, by one of: "\Users\", "\\Users\\", "/Users/", "USERNAME=".
# We normalise the username to "user" only in those anchored forms.

# Path-anchored username: <sep>Users<sep>Administrator  (all slash flavours,
# incl. JSON double-escaped \\\\, single \\, forward /, and git-bash /c/).
_WIN_USER_IN_PATH_RE = re.compile(
    r"(?P<pre>(?:\\{2,4}|/)Users(?:\\{2,4}|/))Administrator"
)
_WIN_USER_IN_PATH_REPLACEMENT = r"\g<pre>user"

# Collapsed variant from bash error messages where the shell stripped all
# backslashes: "C:UsersAdministratorAppDataLocalTemp...". The whole mangled
# drive-prefix (through the username, whether still "Administrator" or already
# normalised to "user") is rewritten to a clean, separator-bearing home marker
# so no "C:Users<name>" token survives for reviewers to see.
_WIN_COLLAPSED_USER_RE = re.compile(r"C:Users(?:Administrator|user)")
# This token only ever appears inside backslash-stripped bash error strings
# ("ls: cannot access 'C:UsersuserAppData...'"), never as a real reconstructable
# path. Collapse it to a neutral home marker that carries no username, no
# drive-relative "C:Users" token and no "/Users/" segment, so it satisfies both
# the C:Users and /Users/ residual checks and stays JSON-escape-safe.
_WIN_COLLAPSED_USER_REPLACEMENT = r"<HOME>"

# Proper drive prefix "C:\Users" / "C:\\Users" (with separators) left intact
# structurally; only the username after it is normalised above. The machine
# drive letter alone is not PII.

# ls -la ownership from git-bash: "Administrator 197121" → "user user"
# (197121 is a Windows SID group id that leaks the local account).
_WIN_LS_OWNER_RE = re.compile(r"Administrator(\s+)197121")
_WIN_LS_OWNER_REPLACEMENT = r"user\1user"

# stat(1) ownership form: "Uid: (197108/Administrator)  Gid: (197121/ UNKNOWN)".
# The username after a "(<sid>/" prefix is also a leak of the local account,
# and the raw SID numbers themselves identify the machine's local group.
_WIN_STAT_OWNER_RE = re.compile(r"(\((?:19710[0-9]|19711[0-9]|19712[0-9])/)Administrator")
_WIN_STAT_OWNER_REPLACEMENT = r"\1user"
# Bare leaked Windows SID numbers (uid 197108, gid 197121) → neutral 0.
_WIN_SID_RE = re.compile(r"\b(?:197108|197121)\b")
_WIN_SID_REPLACEMENT = "0"

# Env-var assignment: USERNAME=Administrator
_WIN_USERNAME_ENV_RE = re.compile(r"(USERNAME=)Administrator")
_WIN_USERNAME_ENV_REPLACEMENT = r"\1user"

# CLAUDE_CODE_EXECPATH env var value (exposes collection tooling + local path).
# Value runs until whitespace / quote / backslash-n; keep the key, drop value.
_CLAUDE_EXECPATH_RE = re.compile(r"(CLAUDE_CODE_EXECPATH=)[^\s\"]*")
_CLAUDE_EXECPATH_REPLACEMENT = r"\1<redacted>"

# INIT_CWD pointing to local project root: INIT_CWD=C:\\Project\\MCPHunt\\...
_INIT_CWD_RE = re.compile(r"(INIT_CWD=)C:(?:\\{2,4}|/)Project(?:\\{2,4}|/)MCPHunt[^\s\"]*")
_INIT_CWD_REPLACEMENT = r"\1C:\\\\mcphunt"

# Machine hostname: COMPUTERNAME=DESKTOP-XXXX and LOGONSERVER=\\DESKTOP-XXXX
_COMPUTERNAME_RE = re.compile(r"(COMPUTERNAME=)[A-Z0-9_-]+")
_COMPUTERNAME_REPLACEMENT = r"\1MCPHUNT-HOST"
_LOGONSERVER_RE = re.compile(r"(LOGONSERVER=\\{2,4})[A-Z0-9_-]+")
_LOGONSERVER_REPLACEMENT = r"\1MCPHUNT-HOST"
_HOSTNAME_BARE_RE = re.compile(r"DESKTOP-10UVREO")
_HOSTNAME_BARE_REPLACEMENT = "MCPHUNT-HOST"


def sanitize_text(raw: str) -> str:
    """Apply all sanitization rules to a raw JSON string."""
    # macOS / PyCharm rules
    result = _PROJECT_ROOT_RE.sub(_PROJECT_ROOT_REPLACEMENT, raw)
    result = _USER_HOME_RE.sub(_USER_HOME_REPLACEMENT, result)
    result = _PYCHARM_RE.sub(_PYCHARM_REPLACEMENT, result)
    result = _BARE_USERNAME_VARIANT_RE.sub(_BARE_USERNAME_REPLACEMENT, result)
    result = _BARE_USERNAME_RE.sub(_BARE_USERNAME_REPLACEMENT, result)
    # Windows / VSCode rules (anchored — never touch bare "Administrator")
    result = _WIN_USER_IN_PATH_RE.sub(_WIN_USER_IN_PATH_REPLACEMENT, result)
    result = _WIN_COLLAPSED_USER_RE.sub(_WIN_COLLAPSED_USER_REPLACEMENT, result)
    result = _WIN_LS_OWNER_RE.sub(_WIN_LS_OWNER_REPLACEMENT, result)
    # stat owner (keeps SID digits, rewrites the trailing username) must run
    # before the bare-SID zeroing rule below, which consumes those digits.
    result = _WIN_STAT_OWNER_RE.sub(_WIN_STAT_OWNER_REPLACEMENT, result)
    result = _WIN_SID_RE.sub(_WIN_SID_REPLACEMENT, result)
    result = _WIN_USERNAME_ENV_RE.sub(_WIN_USERNAME_ENV_REPLACEMENT, result)
    result = _CLAUDE_EXECPATH_RE.sub(_CLAUDE_EXECPATH_REPLACEMENT, result)
    result = _INIT_CWD_RE.sub(_INIT_CWD_REPLACEMENT, result)
    result = _COMPUTERNAME_RE.sub(_COMPUTERNAME_REPLACEMENT, result)
    result = _LOGONSERVER_RE.sub(_LOGONSERVER_REPLACEMENT, result)
    result = _HOSTNAME_BARE_RE.sub(_HOSTNAME_BARE_REPLACEMENT, result)
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

    # 5. No sensitive strings remain (substring checks)
    for pattern in [
        "<local-username>", "<local-username-typo>", "PyCharmProjects", "/Users/",
        # Windows / VSCode collection environment
        "197121", "DESKTOP-10UVREO", "USERNAME=Administrator",
    ]:
        if pattern in sanitized:
            errors.append(f"Residual sensitive string: '{pattern}'")

    # 5b. Anchored Windows-username leaks (bare 'Administrator' is legitimate
    # trace content — e.g. 'System Administrators' — so only flag the
    # path-/env-anchored forms that actually expose the local account).
    for label, rgx in [
        ("Users\\Administrator (path)",
         re.compile(r"(?:\\{2,4}|/)Users(?:\\{2,4}|/)Administrator")),
        ("C:UsersAdministrator (collapsed)",
         re.compile(r"C:UsersAdministrator")),
        ("Administrator 197121 (ls owner)",
         re.compile(r"Administrator\s+197121")),
        ("CLAUDE_CODE_EXECPATH= value",
         re.compile(r"CLAUDE_CODE_EXECPATH=(?!<redacted>)\S")),
    ]:
        if rgx.search(sanitized):
            errors.append(f"Residual sensitive string: {label}")

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
