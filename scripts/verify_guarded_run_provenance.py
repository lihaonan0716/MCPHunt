#!/usr/bin/env python
"""Verify the provenance of the historical single-model guarded collection run.

The manuscript describes this evidence as a *post-hoc simulation replayed over
the main benchmark*. It is not: it is a real collection run with the taint guard
active at tool dispatch, on one model, against a baseline arm collected months
earlier under a different pipeline commit. This script establishes that identity
from the traces themselves and records the confounds that bound how the
comparison may be described.

Reads trace files; writes one artifact. It computes no statistic of its own --
the paired figures come from ``paired_actual_sink_analysis``, the same function
that produced the released paired artifact, because a second implementation of
the statistics would fork them away from the released record.

Every check below is a hard failure, not a warning. A guarded run whose
provenance cannot be established is not evidence we can cite.

Usage::

    PYTHONPATH=src python scripts/verify_guarded_run_provenance.py
    PYTHONPATH=src python scripts/verify_guarded_run_provenance.py --check
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcphunt.taxonomy import TASK_REGISTRY  # noqa: E402
from evaluate_mitigation import (  # noqa: E402
    PairingIntegrityError,
    paired_actual_sink_analysis,
)

REPO = Path(__file__).resolve().parent.parent
BASELINE_PATH = REPO / "results/agent_traces/deepseek_v4_flash/agent_traces.json"
DEFENSE_PATH = REPO / "results/agent_traces/deepseek_v4_flash/agent_traces_deft.json"
RELEASED_PAIRED = (REPO / "results/mitigation_analysis"
                   / "live_guard_deepseek_v4_flash_paired.json")
OUT_PATH = (REPO / "results/live_guard_replication"
            / "guarded_run_provenance.json")

ARTIFACT_SCHEMA = "guarded_run_provenance/v1"

# The arm identity we are establishing. A trace outside these values means the
# file is not what this script was written to verify.
EXPECTED_DEFENSE_FIELD = "taint_tracking"
EXPECTED_BASELINE_FIELD = "none"

# Denominator decomposition asserted by the rebuttal: 351 risk + 36 benign.
EXPECTED_RISK_PAIRS = 351
EXPECTED_BENIGN_PAIRS = 36
BENIGN_MECHANISM = "benign_control"


class ProvenanceError(RuntimeError):
    """A provenance claim could not be established from the traces."""


def _fail(msg: str) -> None:
    raise ProvenanceError(msg)


def _rel(path: Path) -> str:
    """Repo-relative POSIX path, falling back to the absolute path.

    ``Path.relative_to`` raises for anything outside the repo, which would
    replace a clear provenance failure with a confusing ValueError.
    """
    try:
        return str(path.relative_to(REPO)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load(path: Path) -> Dict[str, Any]:
    if not path.exists():
        _fail(f"required input missing: {_rel(path)}")
    return json.loads(path.read_text(encoding="utf-8"))


def _pair_key(trace: Dict[str, Any]) -> tuple:
    return (trace["task_id"], trace["env_type"])


def _mechanism(trace: Dict[str, Any]) -> str:
    """Mechanism for a trace, taken from the REGISTRY, not the trace.

    The registry is the frozen source of truth (invariant: CRS/task metadata is
    assigned before experiments). Reading ``risk_mechanism`` off the trace first
    would let a mislabeled trace define its own denominator. The trace's own
    value is cross-checked by :func:`check_denominator` and a disagreement fails
    the run.
    """
    task_id = trace.get("task_id", "")
    task = TASK_REGISTRY.get(task_id)
    if task is None:
        _fail(f"task_id {task_id!r} is not in TASK_REGISTRY; the denominator "
              f"cannot be reproduced from the registry")
    return task.mechanism


def _dates(traces: List[Dict[str, Any]]) -> List[str]:
    """UTC collection dates for an arm.

    ``collection_timestamp`` is an ISO-8601 string (``2026-04-26T16:01:47Z``).
    An unparseable or absent stamp fails the run: the non-contemporaneous-arms
    confound is recorded from these values, so silently dropping them would let
    the artifact assert a date range it could not support.

    A timestamp without an explicit UTC offset is REJECTED. ``astimezone()``
    would interpret a naive stamp in the *running machine's* local zone, so the
    recorded date would depend on who ran the script -- e.g. naive
    ``2026-07-25T01:00:00`` resolves to 2026-07-24 UTC in a positive-offset
    zone, silently shifting the arm's collection date by a day.
    """
    out = set()
    for t in traces:
        ts = t.get("collection_timestamp")
        if not ts or not isinstance(ts, str):
            _fail(f"trace {t.get('trace_id', '?')} has no usable "
                  f"collection_timestamp ({ts!r}); arm collection dates cannot "
                  f"be established")
        try:
            parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            _fail(f"trace {t.get('trace_id', '?')} has unparseable "
                  f"collection_timestamp {ts!r}")
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            _fail(f"trace {t.get('trace_id', '?')} has a timezone-naive "
                  f"collection_timestamp {ts!r}; the UTC date would depend on "
                  f"the machine running this script")
        out.add(parsed.astimezone(timezone.utc).strftime("%Y-%m-%d"))
    return sorted(out)


_VERSION_FIELDS = ("schema_version", "pipeline_git_commit",
                   "task_taxonomy_version", "labeling_rules_version")


def _versions(bundle: Dict[str, Any]) -> Dict[str, Any]:
    """Schema/rules versions for an arm, from the bundle header.

    These live on the bundle, not on individual traces. Every field is
    required: the cross-commit confound is read off ``pipeline_git_commit``, so
    a bundle that omits it cannot support the confound record.
    """
    missing = [k for k in _VERSION_FIELDS if not bundle.get(k)]
    if missing:
        _fail(f"trace bundle is missing version field(s) {missing}; the "
              f"pipeline-commit confound cannot be established")
    return {k: bundle[k] for k in _VERSION_FIELDS}


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------

def check_arm_identity(baseline: List[Dict], defense: List[Dict]) -> Dict[str, Any]:
    """The defense arm ran the guard live; the baseline arm did not."""
    d_fields = sorted({t.get("defense") for t in defense})
    b_fields = sorted({t.get("defense") for t in baseline})
    if d_fields != [EXPECTED_DEFENSE_FIELD]:
        _fail(f"defense arm carries defense={d_fields}, "
              f"expected ['{EXPECTED_DEFENSE_FIELD}'] -- this file is not a "
              f"guarded run")
    if b_fields != [EXPECTED_BASELINE_FIELD]:
        _fail(f"baseline arm carries defense={b_fields}, "
              f"expected ['{EXPECTED_BASELINE_FIELD}'] -- the baseline is "
              f"contaminated with guarded traces")

    d_models = sorted({t.get("model") for t in defense})
    b_models = sorted({t.get("model") for t in baseline})
    if len(d_models) != 1 or d_models != b_models:
        _fail(f"arms span models {b_models} vs {d_models}; the comparison is "
              f"defined only within a single model")
    return {"defense_field": d_fields[0], "baseline_field": b_fields[0],
            "model": d_models[0]}


def check_pairing(baseline: List[Dict], defense: List[Dict]) -> Dict[str, Any]:
    """Pairing keys unique within each arm; missing/extra pairs enumerated."""
    for arm, traces in (("baseline", baseline), ("defense", defense)):
        dupes = [k for k, n in Counter(_pair_key(t) for t in traces).items() if n > 1]
        if dupes:
            _fail(f"{arm} arm has {len(dupes)} duplicate pairing key(s), e.g. "
                  f"{dupes[:5]}; the pairing is ambiguous")

    bkeys = {_pair_key(t) for t in baseline}
    dkeys = {_pair_key(t) for t in defense}
    defense_only = sorted(dkeys - bkeys)
    matched = sorted(dkeys & bkeys)

    if defense_only:
        _fail(f"{len(defense_only)} defense-only cell(s) with no baseline "
              f"counterpart, e.g. {defense_only[:5]}")

    # Baseline-only cells are expected: the baseline arm is the full 723-trace
    # main collection, of which the guarded run covers a 387-cell subset. They
    # are enumerated rather than counted so a reader can see exactly which cells
    # the guarded run does not cover.
    baseline_only = sorted(bkeys - dkeys)
    return {
        "n_baseline_traces": len(baseline),
        "n_defense_traces": len(defense),
        "n_matched_pairs": len(matched),
        "n_defense_only": len(defense_only),
        "defense_only_keys": [list(k) for k in defense_only],
        "n_baseline_only": len(baseline_only),
        "baseline_only_keys": [list(k) for k in baseline_only],
        "baseline_is_superset": True,
    }


def check_denominator(defense: List[Dict]) -> Dict[str, Any]:
    """351 risk + 36 benign-control = 387, reproduced from the task registry.

    Mechanisms come from ``TASK_REGISTRY`` (frozen metadata). Each trace's own
    ``risk_mechanism`` is then compared against it: a disagreement means the
    trace file and the registry describe different experiments, and the
    denominator would be whichever one we happened to read.
    """
    disagreements = []
    for t in defense:
        registry_mech = _mechanism(t)
        trace_mech = t.get("risk_mechanism")
        if trace_mech and trace_mech != registry_mech:
            disagreements.append(
                f"{t.get('task_id', '?')}: trace={trace_mech!r} "
                f"registry={registry_mech!r}")
    if disagreements:
        _fail(f"{len(disagreements)} trace(s) disagree with TASK_REGISTRY on "
              f"risk_mechanism, e.g. {disagreements[:3]}")

    per_mech = Counter(_mechanism(t) for t in defense)
    benign = per_mech.get(BENIGN_MECHANISM, 0)
    risk = sum(n for m, n in per_mech.items() if m != BENIGN_MECHANISM)
    if risk != EXPECTED_RISK_PAIRS or benign != EXPECTED_BENIGN_PAIRS:
        _fail(f"denominator decomposition is {risk} risk + {benign} benign = "
              f"{risk + benign}, expected {EXPECTED_RISK_PAIRS} + "
              f"{EXPECTED_BENIGN_PAIRS} = "
              f"{EXPECTED_RISK_PAIRS + EXPECTED_BENIGN_PAIRS}")
    return {"risk_pairs": risk, "benign_control_pairs": benign,
            "total": risk + benign,
            "mechanism_source": "TASK_REGISTRY (cross-checked against traces)",
            "per_mechanism": dict(sorted(per_mech.items()))}


def check_blocked_events(defense: List[Dict]) -> Dict[str, Any]:
    """Every taint_blocked event must preserve what was actually delivered.

    Without sanitized_args the residual classification cannot be verified -- we
    could not tell a fully-cleared write from one that still leaked. An event
    missing it fails the run rather than being skipped.

    Presence of the KEY is not enough. A ``sanitized_args`` of ``null`` -- or of
    any non-mapping type -- reads downstream as empty arguments, which
    ``actual_sink`` would score as "nothing was delivered", turning an unknown
    residual into a clean block. The value must be an actual argument mapping.
    """
    total = 0
    traces_with_block = 0
    bad: List[str] = []
    for t in defense:
        hit = False
        for ev in t.get("events", []):
            if not ev.get("taint_blocked"):
                continue
            hit = True
            total += 1
            if "sanitized_args" not in ev:
                bad.append(f"{t.get('trace_id', '?')}:turn{ev.get('turn', '?')}"
                           f" missing")
            elif not isinstance(ev["sanitized_args"], dict):
                bad.append(f"{t.get('trace_id', '?')}:turn{ev.get('turn', '?')}"
                           f" is {type(ev['sanitized_args']).__name__}, not a "
                           f"mapping")
        if hit:
            traces_with_block += 1
    if bad:
        _fail(f"{len(bad)}/{total} taint_blocked event(s) have no usable "
              f"sanitized_args, e.g. {bad[:3]}; residual classification is "
              f"unverifiable for those events")
    if total == 0:
        _fail("no taint_blocked events found -- the guard never fired, so this "
              "is not a guarded run")
    return {"taint_blocked_events": total,
            "traces_with_blocked_event": traces_with_block,
            "events_with_unusable_sanitized_args": 0}


#: Exact location of the mismatch count in the released paired artifact. A
#: fixed path, not a recursive name search: a search would silently bind to any
#: same-named field elsewhere in the document, so a schema change would read as
#: agreement instead of as drift.
RELEASED_PROMPT_DIFF_PATH = ("live_guard", "safety", "paired",
                             "prompt_text_diff_pairs")


def check_prompt_mismatch(baseline: List[Dict], defense: List[Dict]) -> Dict[str, Any]:
    """Recompute the prompt-text mismatch and compare to the released artifact.

    The released artifact is a REQUIRED input. If it is absent, unreadable, or
    no longer carries the field at its documented path, the run fails: skipping
    the comparison would mean reporting a mismatch count that was never checked
    against the analysis the rebuttal cited.
    """
    bmap = {_pair_key(t): t for t in baseline}
    diff = sum(1 for t in defense
               if _pair_key(t) in bmap
               and t.get("task_prompt") != bmap[_pair_key(t)].get("task_prompt"))

    if not RELEASED_PAIRED.exists():
        _fail(f"required input missing: "
              f"{_rel(RELEASED_PAIRED)} -- the recomputed "
              f"prompt-text mismatch cannot be cross-checked")
    try:
        blob = json.loads(RELEASED_PAIRED.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        _fail(f"{_rel(RELEASED_PAIRED)} is not valid JSON: {exc}")

    node: Any = blob
    for part in RELEASED_PROMPT_DIFF_PATH:
        if not isinstance(node, dict) or part not in node:
            _fail(f"{_rel(RELEASED_PAIRED)} has no field at "
                  f"{'.'.join(RELEASED_PROMPT_DIFF_PATH)}; the released "
                  f"artifact's schema has changed and the cross-check is no "
                  f"longer meaningful")
        node = node[part]
    released = node

    if released != diff:
        _fail(f"prompt-text mismatch recomputed as {diff} but the released "
              f"paired artifact records {released}; the arms on disk are not "
              f"the arms that analysis described")

    return {"prompt_text_diff_pairs": diff,
            "n_pairs": len(defense),
            "cross_checked_against": {
                "path": _rel(RELEASED_PAIRED),
                "sha256": _sha256(RELEASED_PAIRED),
                "field": ".".join(RELEASED_PROMPT_DIFF_PATH),
                "value": released,
            },
            "note": ("Task prompts differ for most pairs. The arms are NOT "
                     "prompt-controlled; any difference between them is an "
                     "observed difference in a matched-coverage comparison, "
                     "not a guard-caused effect.")}


# ---------------------------------------------------------------------------

def build(baseline_bundle: Dict, defense_bundle: Dict) -> Dict[str, Any]:
    baseline = baseline_bundle["traces"]
    defense = defense_bundle["traces"]

    identity = check_arm_identity(baseline, defense)
    pairing = check_pairing(baseline, defense)
    denominator = check_denominator(defense)
    blocked = check_blocked_events(defense)
    prompts = check_prompt_mismatch(baseline, defense)

    dkeys = {_pair_key(t) for t in defense}
    baseline_matched = [t for t in baseline if _pair_key(t) in dkeys]
    try:
        paired = paired_actual_sink_analysis(baseline_matched, defense)
    except PairingIntegrityError as exc:
        _fail(f"paired analysis rejected the arms: {exc}")

    b_versions = _versions(baseline_bundle)
    d_versions = _versions(defense_bundle)
    cross_commit = (b_versions["pipeline_git_commit"]
                    != d_versions["pipeline_git_commit"])

    return {
        "artifact_schema_version": ARTIFACT_SCHEMA,
        "what_this_is": (
            "Provenance record for the historical single-model guarded "
            "collection run. The guard was ACTIVE AT TOOL DISPATCH during "
            "collection; this is not a replay or simulation over the main "
            "benchmark."
        ),
        "inputs": {
            "baseline": {
                "path": _rel(BASELINE_PATH),
                "sha256": _sha256(BASELINE_PATH),
                "collection_dates_utc": _dates(baseline),
                "versions": b_versions,
            },
            "defense": {
                "path": _rel(DEFENSE_PATH),
                "sha256": _sha256(DEFENSE_PATH),
                "collection_dates_utc": _dates(defense),
                "versions": d_versions,
            },
        },
        "arm_identity": identity,
        "pairing": pairing,
        "denominator": denominator,
        "guard_activity": blocked,
        "paired_actual_sink": paired,
        "metric_scope": (
            "actual_sink measures canary values present in the arguments a sink "
            "tool RECEIVES. It does not inspect final persisted file or "
            "database content."
        ),
        # Machine-checkable claim boundary. generate_results_macros.py asserts
        # these flags before emitting a single macro, so the manuscript cannot
        # quietly reacquire a conclusion this evidence does not support.
        "evidence_scope": {
            "causal": False,
            "cross_model": False,
            "supports_utility_claim": False,
            "comparison_type": "historical_matched_coverage_observed_difference",
            "statement": (
                "A single-model guarded collection run co-occurred with lower "
                "delivered-argument propagation than a baseline arm collected "
                "months earlier under a different pipeline commit and largely "
                "different task prompts. This is an OBSERVED DIFFERENCE under "
                "confounds, not a guard effect estimate, not evidence about "
                "other models, and not evidence about task utility."
            ),
        },
        "confounds": {
            "non_contemporaneous_arms": {
                "baseline": _dates(baseline),
                "defense": _dates(defense),
            },
            "differing_pipeline_commit": {
                "differs": cross_commit,
                "baseline": b_versions["pipeline_git_commit"],
                "defense": d_versions["pipeline_git_commit"],
            },
            "prompt_text_not_controlled": prompts,
            "single_model": identity["model"],
            "arm_ordering_not_randomized": True,
            "interpretation": (
                "These confounds are not removed by the task-clustered "
                "bootstrap. The paired difference is an OBSERVED DIFFERENCE in "
                "a historical matched-coverage comparison, not an estimate of "
                "the guard's causal effect. Do not describe the 387 cells in "
                "terms that imply prompts, dates, or code were controlled."
            ),
        },
        "confound_list_completeness": (
            "Enumerates the confounds recorded in the released paired artifact "
            "and recomputable from the traces. Not independently audited for "
            "exhaustiveness; a suspected memory-server version difference "
            "between arms remains unverified."
        ),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="verify without writing; exit 1 if the artifact on "
                         "disk differs from what would be generated")
    args = ap.parse_args()

    try:
        artifact = build(_load(BASELINE_PATH), _load(DEFENSE_PATH))
    except ProvenanceError as exc:
        print(f"PROVENANCE FAILURE: {exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(artifact, indent=2, ensure_ascii=False) + "\n"

    if args.check:
        if not OUT_PATH.exists():
            print(f"--check: {_rel(OUT_PATH)} does not exist",
                  file=sys.stderr)
            return 1
        if OUT_PATH.read_text(encoding="utf-8") != rendered:
            print(f"--check: {_rel(OUT_PATH)} is stale",
                  file=sys.stderr)
            return 1
        print(f"--check: {_rel(OUT_PATH)} is current")
        return 0

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(rendered, encoding="utf-8")

    pa = artifact["paired_actual_sink"]
    print(f"wrote {_rel(OUT_PATH)}")
    print(f"  arm identity     : defense={artifact['arm_identity']['defense_field']} "
          f"baseline={artifact['arm_identity']['baseline_field']} "
          f"model={artifact['arm_identity']['model']}")
    print(f"  matched pairs    : {artifact['pairing']['n_matched_pairs']} "
          f"({artifact['denominator']['risk_pairs']} risk + "
          f"{artifact['denominator']['benign_control_pairs']} benign)")
    print(f"  guard fired      : {artifact['guard_activity']['taint_blocked_events']} "
          f"events, all with sanitized_args")
    print(f"  prompt mismatch  : "
          f"{artifact['confounds']['prompt_text_not_controlled']['prompt_text_diff_pairs']}"
          f"/{artifact['pairing']['n_matched_pairs']} pairs")
    print(f"  baseline dates   : {artifact['inputs']['baseline']['collection_dates_utc']}")
    print(f"  defense dates    : {artifact['inputs']['defense']['collection_dates_utc']}")
    if isinstance(pa, dict):
        print(f"  paired estimand  : "
              f"{pa.get('pair_weighted_diff_defense_minus_baseline')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
