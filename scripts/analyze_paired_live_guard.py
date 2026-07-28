#!/usr/bin/env python3
"""Produce the paired live-guard replication analysis artifact.

Reads two fresh same-slice trace files (baseline ``defense=none`` vs. defense
``defense=taint_tracking``), reuses ``evaluate_mitigation.compare_live_guard``
for the paired safety / utility / diagnostics statistics (never forked), and
wraps the result in a provenance block whose every value is derived at runtime
from the trace envelopes or per-trace ``measurement``/trace fields — never
hand-written. The artifact anchors on the two input trace JSONs (path +
SHA-256 content hash); ``collection_summary.json`` is deliberately NOT used
(it is overwritten by the later arm and cannot serve as paired evidence).

Output is a reviewed evidence anchor for the live-guard replication claim:
"fresh same-slice paired replication, single model, single day", with the
remaining confounds stated explicitly (pipeline-commit asymmetry across arms,
single-model scope, arm ordering, single temperature-0 pass per cell).

Usage:
    PYTHONPATH=src python scripts/analyze_paired_live_guard.py \
        --baseline results/agent_traces_b3_replication/deepseek_v4_flash/agent_traces_browser.json \
        --defense results/agent_traces_b3_replication/deepseek_v4_flash/agent_traces_browser_deft.json \
        --out results/live_guard_replication/paired_live_guard_analysis.json

Offline only: reads existing trace files, no API call, no collection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from evaluate_mitigation import compare_live_guard  # noqa: E402

DEFAULT_BASELINE = (REPO_ROOT / "results" / "agent_traces_b3_replication"
                    / "deepseek_v4_flash" / "agent_traces_browser.json")
DEFAULT_DEFENSE = (REPO_ROOT / "results" / "agent_traces_b3_replication"
                   / "deepseek_v4_flash" / "agent_traces_browser_deft.json")
DEFAULT_OUT = (REPO_ROOT / "results" / "live_guard_replication"
               / "paired_live_guard_analysis.json")

ARTIFACT_SCHEMA_VERSION = "paired_live_guard_analysis/v1"

# Per-trace measurement fields that must be constant within and across arms
# for the "same generation settings" claim to be derivable rather than assumed.
_GENERATION_FIELDS = ("generation_temperature", "generation_max_tokens",
                      "max_turns", "mcp_versions")


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_arm(path: Path) -> Tuple[Dict[str, Any], List[Dict]]:
    """Load one arm file; return (envelope-without-traces, traces)."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    traces = data.get("traces")
    if not isinstance(traces, list) or not traces:
        raise SystemExit(f"{path}: no 'traces' list — not a trace envelope file")
    envelope = {k: v for k, v in data.items() if k != "traces"}
    return envelope, traces


def _pair_key(t: Dict) -> Tuple[str, str]:
    return (t.get("task_id", ""), t.get("env_type", ""))


def _require_arm_identity(traces: List[Dict], expected_defense: str,
                          label: str) -> None:
    """Arm identity is the ``defense`` field (both arms have mitigation_level
    == "none"); refuse to analyze a mislabeled file."""
    defenses = {t.get("defense") for t in traces}
    if defenses != {expected_defense}:
        raise SystemExit(
            f"{label} arm: expected defense == {expected_defense!r} on every "
            f"trace, found {sorted(str(d) for d in defenses)}")
    levels = {t.get("mitigation_level") for t in traces}
    if levels != {"none"}:
        raise SystemExit(
            f"{label} arm: expected mitigation_level == 'none' on every "
            f"trace, found {sorted(str(v) for v in levels)}")


def _uniform_value(traces: List[Dict], field: str, label: str) -> Any:
    """Return the single value of measurement[field] across an arm, or raise."""
    values = {json.dumps((t.get("measurement") or {}).get(field), sort_keys=True)
              for t in traces}
    if len(values) != 1:
        raise SystemExit(
            f"{label} arm: measurement[{field!r}] is not uniform across "
            f"traces ({len(values)} distinct values) — cannot derive a "
            "'same generation settings' claim")
    return json.loads(values.pop())


def _collection_window(traces: List[Dict]) -> Dict[str, str]:
    stamps = sorted(t.get("collection_timestamp", "") for t in traces)
    return {"first": stamps[0], "last": stamps[-1]}


def _trace_quality(traces: List[Dict]) -> Dict[str, int]:
    """Quality diagnostics for reading the numbers, not design confounds.

    ``tool_errors`` is a per-trace integer count, so the two conventions are
    named apart: traces_with_tool_error = count(tool_errors > 0),
    tool_error_events_total = sum(tool_errors).
    """
    return {
        "n_traces": len(traces),
        "truncated_traces": sum(1 for t in traces if t.get("truncated")),
        "traces_with_tool_error": sum(
            1 for t in traces if (t.get("tool_errors", 0) or 0) > 0),
        "tool_error_events_total": sum(
            t.get("tool_errors", 0) or 0 for t in traces),
        "api_errors_total": sum(t.get("api_errors", 0) or 0 for t in traces),
    }


def build_provenance(baseline_path: Path, defense_path: Path,
                     base_env: Dict, def_env: Dict,
                     base_traces: List[Dict],
                     def_traces: List[Dict]) -> Dict[str, Any]:
    """Derive the provenance block. Every value here is computed from the two
    input files (trace envelope or per-trace measurement/trace fields) at
    runtime — nothing is hand-written."""
    base_keys = {_pair_key(t) for t in base_traces}
    def_keys = {_pair_key(t) for t in def_traces}
    paired = base_keys & def_keys

    base_prompt = {_pair_key(t): t.get("task_prompt") for t in base_traces}
    def_prompt = {_pair_key(t): t.get("task_prompt") for t in def_traces}
    prompt_diff = sum(1 for k in paired if base_prompt[k] != def_prompt[k])

    base_snap = {_pair_key(t): json.dumps(t.get("env_snapshot"), sort_keys=True)
                 for t in base_traces}
    def_snap = {_pair_key(t): json.dumps(t.get("env_snapshot"), sort_keys=True)
                for t in def_traces}
    env_snapshot_diff = sum(1 for k in paired if base_snap[k] != def_snap[k])

    models = ({t.get("model") for t in base_traces}
              | {t.get("model") for t in def_traces})
    if len(models) != 1:
        raise SystemExit(f"expected a single model across both arms, "
                         f"found {sorted(str(m) for m in models)}")
    model = models.pop()

    mechanisms = sorted({t.get("risk_mechanism") for t in base_traces}
                        | {t.get("risk_mechanism") for t in def_traces})

    # Version strings are commitments (invariant #3): assert both arms agree
    # rather than silently trusting the baseline envelope, so a future
    # cross-arm mismatch is a hard failure, not an unnoticed provenance drift.
    def _require_equal_env(field: str) -> Any:
        bv, dv = base_env.get(field), def_env.get(field)
        if bv != dv:
            raise SystemExit(
                f"envelope[{field!r}] differs across arms "
                f"(baseline={bv!r}, defense={dv!r}) — paired artifact "
                "provenance would be ambiguous")
        return bv

    taxonomy_version = _require_equal_env("task_taxonomy_version")
    rules_version = _require_equal_env("labeling_rules_version")

    # Generation settings: derived from per-trace measurement fields; the
    # claim is only emitted if uniform within each arm AND equal across arms.
    gen: Dict[str, Any] = {}
    for field in _GENERATION_FIELDS:
        bv = _uniform_value(base_traces, field, "baseline")
        dv = _uniform_value(def_traces, field, "defense")
        if bv != dv:
            raise SystemExit(
                f"measurement[{field!r}] differs across arms "
                f"(baseline={bv!r}, defense={dv!r}) — 'same generation "
                "settings' claim would be false")
        gen[field] = bv

    base_window = _collection_window(base_traces)
    def_window = _collection_window(def_traces)
    same_day = (base_window["first"][:10] == base_window["last"][:10]
                == def_window["first"][:10] == def_window["last"][:10])
    baseline_first = base_window["last"] <= def_window["first"]

    return {
        "scope": (f"fresh same-slice paired replication, {model}, "
                  + ("single day" if same_day else "MULTI-DAY (check windows)")),
        "inputs": {
            "baseline": {
                "path": str(baseline_path.relative_to(REPO_ROOT)),
                "sha256": _sha256_file(baseline_path),
                "pipeline_git_commit": base_env.get("pipeline_git_commit"),
                "schema_version": base_env.get("schema_version"),
                "task_taxonomy_version": base_env.get("task_taxonomy_version"),
                "labeling_rules_version": base_env.get("labeling_rules_version"),
                "collection_window_utc": base_window,
                "n_traces": len(base_traces),
            },
            "defense": {
                "path": str(defense_path.relative_to(REPO_ROOT)),
                "sha256": _sha256_file(defense_path),
                "pipeline_git_commit": def_env.get("pipeline_git_commit"),
                "schema_version": def_env.get("schema_version"),
                "task_taxonomy_version": def_env.get("task_taxonomy_version"),
                "labeling_rules_version": def_env.get("labeling_rules_version"),
                "collection_window_utc": def_window,
                "n_traces": len(def_traces),
            },
        },
        "task_taxonomy_version": taxonomy_version,
        "labeling_rules_version": rules_version,
        "disclosure_scope": {
            "authoritative_for_this_artifact": (
                "provenance.confounds_removed and "
                "provenance.confounds_remaining"),
            "inherited_comparison_note": (
                "comparison.safety.paired.confound_disclosure is legacy "
                "metadata emitted by compare_live_guard; this paired "
                "artifact supersedes its historical confound examples with "
                "trace-derived same-day collection, prompt_text_diff_pairs=0, "
                "and MCP version equality"),
        },
        "model": model,
        "risk_mechanisms": mechanisms,
        "confounds_removed": {
            "same_paired_cells": {
                "n_baseline_cells": len(base_keys),
                "n_defense_cells": len(def_keys),
                "n_paired_cells": len(paired),
            },
            "same_day_collection": same_day,
            "prompt_text_diff_pairs": prompt_diff,
            "env_snapshot_diff_pairs": env_snapshot_diff,
            "same_generation_settings": gen,
            "same_model": model,
        },
        "confounds_remaining": {
            "pipeline_commit_asymmetry": {
                "baseline_pipeline_git_commit": base_env.get("pipeline_git_commit"),
                "defense_pipeline_git_commit": def_env.get("pipeline_git_commit"),
                "note": ("the two arms were collected at different pipeline "
                         "commits; honest claim scope is same slice / same "
                         "day / prompt text matched, never same pipeline "
                         "commit"),
            },
            "single_model_scope": model,
            "arm_ordering": {
                "baseline_collected_entirely_before_defense": baseline_first,
                "note": ("arms were collected sequentially on the same day, "
                         "not randomized or interleaved"),
            },
            "single_pass_no_seed_variance": (
                "temperature-0 single pass per cell; environment variants "
                "are not repeated runs; no seed/order variance estimate"),
        },
        "trace_quality": {
            "note": ("diagnostics for reading the numbers, not design "
                     "confounds; tool_errors is a per-trace integer count, "
                     "so both conventions are reported"),
            "baseline": _trace_quality(base_traces),
            "defense": _trace_quality(def_traces),
        },
        "excluded_evidence": {
            "collection_summary.json": (
                "not used as an anchor: the file is overwritten by the "
                "later arm and cannot serve as paired evidence"),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Paired live-guard replication analysis artifact "
                    "(offline; reads two existing trace files)")
    parser.add_argument("--baseline", default=str(DEFAULT_BASELINE),
                        help="baseline-arm trace JSON (defense == 'none')")
    parser.add_argument("--defense", default=str(DEFAULT_DEFENSE),
                        help="defense-arm trace JSON (defense == 'taint_tracking')")
    parser.add_argument("--out", default=str(DEFAULT_OUT),
                        help="output artifact path (under gitignored results/)")
    args = parser.parse_args()

    baseline_path = Path(args.baseline).resolve()
    defense_path = Path(args.defense).resolve()

    base_env, base_traces = _load_arm(baseline_path)
    def_env, def_traces = _load_arm(defense_path)
    _require_arm_identity(base_traces, "none", "baseline")
    _require_arm_identity(def_traces, "taint_tracking", "defense")

    provenance = build_provenance(baseline_path, defense_path,
                                  base_env, def_env, base_traces, def_traces)
    comparison = compare_live_guard(base_traces, def_traces)

    artifact = {
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "provenance": provenance,
        "comparison": comparison,
    }

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8", newline="") as fh:
        json.dump(artifact, fh, indent=2, ensure_ascii=False)
        fh.write("\n")

    paired = comparison["safety"]["paired"]
    util = comparison["utility"]
    print(f"artifact written: {out_path}")
    print(f"  scope: {provenance['scope']}")
    print(f"  n_pairs: {paired['n_pairs']}  "
          f"prompt_text_diff_pairs: "
          f"{provenance['confounds_removed']['prompt_text_diff_pairs']}")
    print(f"  pair_weighted_diff (defense - baseline): "
          f"{paired['pair_weighted_diff_defense_minus_baseline']}  "
          f"ci95: {paired['pair_weighted_diff_ci95']}")
    mc = paired["mcnemar_discordance"]
    print(f"  mcnemar: b={mc['b_baseline_safe_defense_unsafe']} "
          f"c={mc['c_baseline_unsafe_defense_safe']}")
    print(f"  utility: baseline={util['baseline_utility_rate']} "
          f"defense={util['defense_utility_rate']} "
          f"noninferior={util['noninferior']}")
    print(f"  commits: baseline="
          f"{base_env.get('pipeline_git_commit')} "
          f"defense={def_env.get('pipeline_git_commit')} (asymmetric)")


if __name__ == "__main__":
    main()
