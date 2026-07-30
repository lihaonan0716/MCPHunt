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

The private inference-gateway host is never stored in this source. To enable
the host-conditional gateway rules (api_base/base_url value match, bare-host
fallback, residual red line), export the host at runtime:
    MCPHUNT_PRIVATE_GATEWAY_HOST=<host> python3 scripts/sanitize_traces.py ...
Without it, only the always-on keyed rules (ANTHROPIC_BASE_URL, judge_api_base)
run.
"""

import argparse
import glob
import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# -- Replacement rules (order matters: longest match first) ----------

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

# -- Windows / VSCode collection environment rules --------------------
# IMPORTANT: only replace "Administrator" when it is ANCHORED to a leak
# context (a path separator, an env-var assignment, or ls ownership).
# A bare "Administrator" also occurs in legitimate trace content
# (e.g. the PyPI classifier "Intended Audience :: System Administrators"),
# so a bare \bAdministrator\b rule would corrupt real data - do NOT add one.
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

# ls -la ownership from git-bash: "Administrator 197121" -> "user user"
# (197121 is a Windows SID group id that leaks the local account).
_WIN_LS_OWNER_RE = re.compile(r"Administrator(\s+)197121")
_WIN_LS_OWNER_REPLACEMENT = r"user\1user"

# stat(1) ownership form: "Uid: (197108/Administrator)  Gid: (197121/ UNKNOWN)".
# The username after a "(<sid>/" prefix is also a leak of the local account,
# and the raw SID numbers themselves identify the machine's local group.
_WIN_STAT_OWNER_RE = re.compile(r"(\((?:19710[0-9]|19711[0-9]|19712[0-9])/)Administrator")
_WIN_STAT_OWNER_REPLACEMENT = r"\1user"
# Bare leaked Windows SID numbers (uid 197108, gid 197121) -> neutral 0.
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

# -- Private inference-gateway rules ----------------------------------
# The judge / collection calls were routed through a private paid gateway
# whose host must never appear on a public release. The host literal is NOT
# stored in this (public) source: it is injected at runtime from the
# environment variable MCPHUNT_PRIVATE_GATEWAY_HOST. Rules split into two tiers:
#
#   Always-on (generic keyed provenance - value is a gateway URL by the field's
#   definition, so it is always safe to neutralise, no host literal needed):
#     (a) env-dump string:  ANTHROPIC_BASE_URL=<scheme>://<host>/...
#     (b) JSON field:       "judge_api_base": "<scheme>://<host>/..."
#
#   Host-conditional (only when MCPHUNT_PRIVATE_GATEWAY_HOST is configured -
#   these need the literal host to avoid corrupting legitimate metadata):
#     (c) "api_base"/"base_url" JSON field, but ONLY when the value carries the
#         configured private host (a bare api.anthropic.com value is left alone)
#     (d) bare-host fallback: any residual mention of the private host, in any
#         surrounding context, collapses to the neutral marker.
#
# The sanitizer must NOT read configs/api_keys.yaml - it is a release-cleaning
# tool and has no business touching secret config.

_PRIVATE_GATEWAY_HOST_ENV = "MCPHUNT_PRIVATE_GATEWAY_HOST"
_GATEWAY_MARKER = "<internal-gateway>"
_GATEWAY_BARE_MARKER = "internal-gateway"

# (a) env-var assignment form: ANTHROPIC_BASE_URL=<scheme>://<host>...
_GATEWAY_ENV_RE = re.compile(
    r"(ANTHROPIC_BASE_URL=)https?://[^\s\"'`,)]+"
)
_GATEWAY_ENV_REPLACEMENT = r"\1" + _GATEWAY_MARKER

# (b) JSON endpoint field form: "judge_api_base": "https://<host>/v1"
# Scoped to the exact key judge_api_base only - not any field containing
# "judge" - so unrelated provenance fields are never rewritten.
_GATEWAY_JUDGE_FIELD_RE = re.compile(
    r"(\"judge_api_base\"\s*:\s*\")https?://[^\"]+(\")"
)
_GATEWAY_JUDGE_FIELD_REPLACEMENT = r"\1" + _GATEWAY_MARKER + r"\2"


def _resolve_private_host(explicit: str | None = None) -> str | None:
    """Return the private gateway host: explicit arg, else env var, else None."""
    host = explicit if explicit is not None else os.environ.get(_PRIVATE_GATEWAY_HOST_ENV)
    host = (host or "").strip()
    return host or None


# Single ordered source of truth for every host-independent rule. Both
# sanitize_text() and main()'s match counter read this list, so a newly added
# rule cannot apply during sanitization while staying invisible to the counter
# (the drift that previously left the Windows rules uncounted).
#
# Order is load-bearing and matches the original sequence: macOS/PyCharm rules,
# then the anchored Windows/VSCode rules (stat-owner before the bare-SID zeroing
# that would otherwise consume those digits), then the always-on keyed gateway
# rules.
_HOST_INDEPENDENT_RULES = (
    (_PROJECT_ROOT_RE, _PROJECT_ROOT_REPLACEMENT),
    (_USER_HOME_RE, _USER_HOME_REPLACEMENT),
    (_PYCHARM_RE, _PYCHARM_REPLACEMENT),
    (_BARE_USERNAME_VARIANT_RE, _BARE_USERNAME_REPLACEMENT),
    (_BARE_USERNAME_RE, _BARE_USERNAME_REPLACEMENT),
    (_WIN_USER_IN_PATH_RE, _WIN_USER_IN_PATH_REPLACEMENT),
    (_WIN_COLLAPSED_USER_RE, _WIN_COLLAPSED_USER_REPLACEMENT),
    (_WIN_LS_OWNER_RE, _WIN_LS_OWNER_REPLACEMENT),
    (_WIN_STAT_OWNER_RE, _WIN_STAT_OWNER_REPLACEMENT),
    (_WIN_SID_RE, _WIN_SID_REPLACEMENT),
    (_WIN_USERNAME_ENV_RE, _WIN_USERNAME_ENV_REPLACEMENT),
    (_CLAUDE_EXECPATH_RE, _CLAUDE_EXECPATH_REPLACEMENT),
    (_INIT_CWD_RE, _INIT_CWD_REPLACEMENT),
    (_COMPUTERNAME_RE, _COMPUTERNAME_REPLACEMENT),
    (_LOGONSERVER_RE, _LOGONSERVER_REPLACEMENT),
    (_HOSTNAME_BARE_RE, _HOSTNAME_BARE_REPLACEMENT),
    (_GATEWAY_ENV_RE, _GATEWAY_ENV_REPLACEMENT),
    (_GATEWAY_JUDGE_FIELD_RE, _GATEWAY_JUDGE_FIELD_REPLACEMENT),
)

# Derived view for match counting; never maintained separately.
_COUNTED_RULES = tuple(rgx for rgx, _ in _HOST_INDEPENDENT_RULES)


def _host_conditional_rules(host: str):
    """Build host-conditional regex rules from an injected host literal.

    Returned as (compiled_re, replacement) pairs so no host literal ever lives
    in this source file.
    """
    esc = re.escape(host)
    # (c) api_base / base_url JSON field, ONLY when value carries the host.
    api_field_re = re.compile(
        r"(\"(?:api_base|base_url)\"\s*:\s*\")https?://" + esc + r"[^\"]*(\")"
    )
    api_field_repl = r"\1" + _GATEWAY_MARKER + r"\2"
    # (d) scheme-bearing host fallback then bare host.
    host_url_re = re.compile(r"https?://" + esc + r"[^\s\"'`,)]*")
    bare_host_re = re.compile(esc)
    return [
        (api_field_re, api_field_repl),
        (host_url_re, _GATEWAY_MARKER),
        (bare_host_re, _GATEWAY_BARE_MARKER),
    ]


def sanitize_text(raw: str, private_host: str | None = None) -> str:
    """Apply all sanitization rules to a raw JSON string.

    ``private_host`` (or the ``MCPHUNT_PRIVATE_GATEWAY_HOST`` env var when the
    argument is omitted) enables the host-conditional gateway rules. When no
    host is configured, only the always-on keyed rules (ANTHROPIC_BASE_URL,
    judge_api_base) run - generic api_base/base_url values are left untouched.
    """
    host = _resolve_private_host(private_host)
    # Host-independent rules, in the order fixed by _HOST_INDEPENDENT_RULES:
    # macOS/PyCharm, then the anchored Windows/VSCode rules (never touching a
    # bare "Administrator"), then the always-on keyed gateway forms (which
    # preserve the key and need no host literal).
    result = raw
    for rgx, repl in _HOST_INDEPENDENT_RULES:
        result = rgx.sub(repl, result)
    # Then, only when a private host is configured, the host-conditional rules:
    # api_base/base_url value match, scheme-bearing host fallback, bare host.
    # Running them last ensures a bare-host rule never eats a value the keyed
    # rules would neutralise first.
    if host:
        for rgx, repl in _host_conditional_rules(host):
            result = rgx.sub(repl, result)
    return result


def validate_sanitization(original: str, sanitized: str, filepath: str,
                          private_host: str | None = None) -> list[str]:
    """Check that sanitization didn't break anything.

    The private-gateway host red line is only checked when a host is configured
    (via ``private_host`` or ``MCPHUNT_PRIVATE_GATEWAY_HOST``); the host literal
    is never stored in this source.
    """
    errors = []
    host = _resolve_private_host(private_host)

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

    # 5a. Private inference-gateway host red line - only when a host is
    # configured (the literal is injected, never stored in this source).
    if host and host in sanitized:
        errors.append("Residual sensitive string: private gateway host")

    # 5b. Anchored Windows-username leaks (bare 'Administrator' is legitimate
    # trace content - e.g. 'System Administrators' - so only flag the
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

    host = _resolve_private_host()
    if host:
        print(f"Private gateway host configured via {_PRIVATE_GATEWAY_HOST_ENV} "
              f"- host-conditional rules ENABLED.")
    else:
        print(f"No {_PRIVATE_GATEWAY_HOST_ENV} set - only generic keyed gateway "
              f"rules active (ANTHROPIC_BASE_URL, judge_api_base).")

    total_replacements = 0
    total_errors = 0

    # Reporting-only match counts. NOTE: the write decision below is gated on
    # `sanitized != raw`, never on this number -- a hand-maintained regex list
    # silently under-counts the moment a rule is added to sanitize_text() but
    # not here, and a file whose only leak came from an uncounted rule would
    # then be reported as clean and never written out.
    count_res = list(_COUNTED_RULES)
    if host:
        # re.escape'd bare-host regex catches the recall/live_guard leaks.
        count_res.append(re.compile(re.escape(host)))

    for filepath in files:
        raw = filepath.read_text(encoding="utf-8")
        sanitized = sanitize_text(raw, private_host=host)

        n_changes = sum(len(r.findall(raw)) for r in count_res)
        # Authoritative signal: did any rule actually rewrite this file?
        changed = sanitized != raw

        errors = validate_sanitization(raw, sanitized, str(filepath),
                                       private_host=host)

        rel = filepath.relative_to(REPO)
        status = "OK" if not errors else "ERRORS"
        print(f"  {rel}: {n_changes} replacements [{status}]")
        for e in errors:
            print(f"    ERROR: {e}")
            total_errors += 1

        total_replacements += n_changes

        if changed and not errors:
            if args.outdir:
                out_path = Path(args.outdir) / rel
                out_path.parent.mkdir(parents=True, exist_ok=True)
                out_path.write_text(sanitized, encoding="utf-8")
            elif args.apply:
                filepath.write_text(sanitized, encoding="utf-8")

    print(f"\nTotal: {total_replacements} replacements across {len(files)} files, {total_errors} errors")

    if not args.apply and not args.outdir:
        print("\nDry run - no files modified. Use --apply to overwrite or --outdir DIR to write copies.")

    return 1 if total_errors > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
