#!/usr/bin/env python3
"""Offline re-labeler: recompute all 10 risk signals from raw event data.

Reads an existing trace file, applies the current labeling rules to each
trace's events, and writes the corrected labels back.  No API calls needed.

Uses the shared labeling module (mcphunt.labeling) to guarantee identical
semantics with the collector.

Usage:
    PYTHONPATH=src python3 scripts/relabel_traces.py results/agent_traces/gpt-5_4/agent_traces.json
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from mcphunt.log import get_logger, setup_logging
log = get_logger("relabel")

from mcphunt.taxonomy import (
    LABELING_RULES_VERSION,
    TASK_MECHANISM_MAP,
    is_crs_task,
)
from mcphunt.labeling import compute_risk_labels, compute_expected_risk, compute_outcome, compute_outcome_crs_stratified, compute_artifact_verified


def relabel(trace: Dict) -> Dict:
    """Recompute all 11 risk signals for one trace using shared labeling."""
    events = trace.get("events", [])
    env_type = trace.get("env_type", "")
    task_id = trace.get("task_id", "")

    labeling_result = compute_risk_labels(events, env_type, task_id=task_id)
    has_sensitive_read = labeling_result["sensitive_data_read"]
    any_risk = labeling_result["any_risk"]

    trace["labeling"] = labeling_result

    trace["expected_risk"] = compute_expected_risk(env_type, labeling_result)

    # Recompute artifact_verified using shared logic
    checks = trace.get("completion_checks", {})
    mechanism = trace.get("risk_mechanism", trace.get("task_category", ""))
    category = trace.get("task_category", "")
    artifact_verified = compute_artifact_verified(
        trace.get("task_completed", False), checks, mechanism, category
    )
    checks["artifact_verified"] = artifact_verified
    trace["completion_checks"] = checks

    trace["outcome"] = compute_outcome(artifact_verified, any_risk)
    trace["outcome_crs_stratified"] = compute_outcome_crs_stratified(
        artifact_verified, any_risk, labeling_result["intrinsic_risk"])
    trace["risk_type"] = trace.get("task_category", "") if any_risk else ""

    return trace


def main() -> None:
    if len(sys.argv) < 2:
        log.error("Usage: %s <trace_file.json>", sys.argv[0])
        sys.exit(1)

    path = Path(sys.argv[1])
    raw = json.loads(path.read_text(encoding="utf-8"))

    if isinstance(raw, dict) and "traces" in raw:
        traces = raw["traces"]
        envelope = raw
    elif isinstance(raw, list):
        traces = raw
        envelope = None
    else:
        log.error("Unrecognized trace file format")
        sys.exit(1)

    setup_logging()
    log.info("Relabeling %d traces with rules version: %s", len(traces), LABELING_RULES_VERSION)

    # Fix risk_mechanism from taxonomy (browser tasks had category fallback)
    mech_fixed = 0
    for t in traces:
        tid = t.get("task_id", "")
        if tid in TASK_MECHANISM_MAP:
            correct = TASK_MECHANISM_MAP[tid]
            if t.get("risk_mechanism") != correct:
                t["risk_mechanism"] = correct
                mech_fixed += 1
    if mech_fixed:
        log.info("Fixed risk_mechanism on %d traces", mech_fixed)

    old_unsafe = sum(1 for t in traces if t.get("labeling", {}).get("any_risk"))
    changed = 0

    for t in traces:
        old_sigs = dict(t.get("labeling", {}).get("risk_signals", {}))
        relabel(t)
        new_sigs = t["labeling"]["risk_signals"]
        if old_sigs != new_sigs:
            changed += 1

    new_unsafe = sum(1 for t in traces if t["labeling"]["any_risk"])

    if envelope:
        envelope["labeling_rules_version"] = LABELING_RULES_VERSION
        out = envelope
    else:
        out = traces

    path.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding="utf-8")

    log.info("Changed: %d/%d traces", changed, len(traces))
    log.info("Unsafe: %d → %d", old_unsafe, new_unsafe)

    for env in sorted(set(t.get("env_type", "") for t in traces)):
        et = [t for t in traces if t["env_type"] == env]
        n = len(et)
        unsafe = sum(1 for t in et if t["labeling"]["any_risk"])
        outcomes = {}
        for t in et:
            o = t.get("outcome", "?")
            outcomes[o] = outcomes.get(o, 0) + 1
        log.info("  %12s  n=%3d  unsafe=%5.1f%%  %s", env, n, unsafe/n*100, outcomes)

    from mcphunt.datasets.agent_traces import compute_summary
    summary = compute_summary(traces)
    summary_path = path.parent / "collection_summary.json"
    summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    log.info("Regenerated %s", summary_path)


if __name__ == "__main__":
    main()
