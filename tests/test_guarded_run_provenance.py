"""Regression tests for the guarded-run provenance verifier.

The verifier's job is to REFUSE evidence it cannot establish. A check that
cannot fail proves nothing, so every acceptance condition gets a negative
control that corrupts one property and asserts the run aborts.

All mutations are applied to in-memory deep copies. No test writes a trace file
or an artifact.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from verify_guarded_run_provenance import (  # noqa: E402
    BASELINE_PATH,
    DEFENSE_PATH,
    RELEASED_PAIRED,
    ProvenanceError,
    build,
)

pytestmark = pytest.mark.skipif(
    not (BASELINE_PATH.exists() and DEFENSE_PATH.exists()
         and RELEASED_PAIRED.exists()),
    reason="guarded-run traces not present (run `make download`)",
)


@pytest.fixture(scope="module")
def arms():
    baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
    defense = json.loads(DEFENSE_PATH.read_text(encoding="utf-8"))
    return baseline, defense


@pytest.fixture
def fresh(arms):
    """A mutable deep copy of both arms."""
    return copy.deepcopy(arms[0]), copy.deepcopy(arms[1])


def _first_blocked_event(defense):
    for t in defense["traces"]:
        for ev in t.get("events", []):
            if ev.get("taint_blocked"):
                return ev
    raise AssertionError("fixture has no taint_blocked event")


# ---------------------------------------------------------------------------
# Positive control
# ---------------------------------------------------------------------------

def test_unmodified_arms_verify(fresh):
    """The real traces must establish the guarded-run identity."""
    art = build(*fresh)
    assert art["arm_identity"]["defense_field"] == "taint_tracking"
    assert art["arm_identity"]["baseline_field"] == "none"
    assert art["pairing"]["n_matched_pairs"] == 387
    assert art["denominator"]["risk_pairs"] == 351
    assert art["denominator"]["benign_control_pairs"] == 36
    assert art["guard_activity"]["taint_blocked_events"] > 0
    assert art["guard_activity"]["events_with_unusable_sanitized_args"] == 0


def test_confounds_are_recorded_not_elided(fresh):
    """The artifact must carry the facts that bound how this may be described."""
    art = build(*fresh)
    conf = art["confounds"]
    assert conf["differing_pipeline_commit"]["differs"] is True
    assert conf["prompt_text_not_controlled"]["prompt_text_diff_pairs"] == 345
    assert conf["non_contemporaneous_arms"]["baseline"] != \
        conf["non_contemporaneous_arms"]["defense"]
    assert conf["single_model"] == "deepseek-v4-flash"


def test_mechanisms_come_from_the_registry(fresh):
    art = build(*fresh)
    assert "TASK_REGISTRY" in art["denominator"]["mechanism_source"]


# ---------------------------------------------------------------------------
# Negative controls — arm identity
# ---------------------------------------------------------------------------

def test_rejects_guarded_trace_in_baseline(fresh):
    baseline, defense = fresh
    baseline["traces"][0]["defense"] = "taint_tracking"
    with pytest.raises(ProvenanceError, match="baseline arm carries"):
        build(baseline, defense)


def test_rejects_unguarded_defense_arm(fresh):
    baseline, defense = fresh
    for t in defense["traces"]:
        t["defense"] = "none"
    with pytest.raises(ProvenanceError, match="not a guarded run"):
        build(baseline, defense)


def test_rejects_multi_model_arm(fresh):
    baseline, defense = fresh
    defense["traces"][0]["model"] = "some-other-model"
    with pytest.raises(ProvenanceError, match="span models"):
        build(baseline, defense)


# ---------------------------------------------------------------------------
# Negative controls — guard activity
#
# The "guard never fired" branch must be reachable INDEPENDENTLY of arm
# identity: keep defense="taint_tracking" and remove only the event flags, or
# the arm-identity check short-circuits and this branch is never exercised.
# ---------------------------------------------------------------------------

def test_rejects_arm_with_no_blocked_events_despite_correct_identity(fresh):
    baseline, defense = fresh
    for t in defense["traces"]:
        assert t["defense"] == "taint_tracking"
        for ev in t.get("events", []):
            ev.pop("taint_blocked", None)
    with pytest.raises(ProvenanceError, match="guard never fired"):
        build(baseline, defense)


def test_rejects_blocked_event_missing_sanitized_args(fresh):
    baseline, defense = fresh
    _first_blocked_event(defense).pop("sanitized_args", None)
    with pytest.raises(ProvenanceError, match="no usable sanitized_args"):
        build(baseline, defense)


@pytest.mark.parametrize("bad_value", [None, "redacted", 42, []])
def test_rejects_non_mapping_sanitized_args(fresh, bad_value):
    """A null or wrong-typed value reads downstream as 'nothing delivered'.

    That would score an unknown residual as a clean block, which is the exact
    direction of error this verifier exists to prevent.
    """
    baseline, defense = fresh
    _first_blocked_event(defense)["sanitized_args"] = bad_value
    with pytest.raises(ProvenanceError, match="no usable sanitized_args"):
        build(baseline, defense)


# ---------------------------------------------------------------------------
# Negative controls — pairing and denominator
# ---------------------------------------------------------------------------

def test_rejects_duplicate_pairing_key(fresh):
    baseline, defense = fresh
    defense["traces"].append(copy.deepcopy(defense["traces"][0]))
    with pytest.raises(ProvenanceError, match="duplicate pairing key"):
        build(baseline, defense)


def test_rejects_broken_denominator(fresh):
    baseline, defense = fresh
    defense["traces"] = defense["traces"][:-1]
    with pytest.raises(ProvenanceError, match="denominator decomposition"):
        build(baseline, defense)


def test_rejects_defense_only_cell(fresh):
    baseline, defense = fresh
    orphan = copy.deepcopy(defense["traces"][0])
    orphan["task_id"] = "no_such_baseline_counterpart"
    defense["traces"].append(orphan)
    with pytest.raises(ProvenanceError):
        build(baseline, defense)


def test_rejects_trace_disagreeing_with_registry_mechanism(fresh):
    baseline, defense = fresh
    for t in defense["traces"]:
        if t.get("risk_mechanism") == "browser_to_local":
            t["risk_mechanism"] = "file_to_file"
            break
    with pytest.raises(ProvenanceError, match="disagree with TASK_REGISTRY"):
        build(baseline, defense)


def test_enumerates_uncovered_baseline_cells(fresh):
    """Counts alone hide WHICH cells the guarded run does not cover."""
    art = build(*fresh)
    keys = art["pairing"]["baseline_only_keys"]
    assert len(keys) == art["pairing"]["n_baseline_only"]
    assert all(len(k) == 2 for k in keys)


# ---------------------------------------------------------------------------
# Negative controls — timestamps
# ---------------------------------------------------------------------------

def test_rejects_missing_timestamp(fresh):
    baseline, defense = fresh
    defense["traces"][0]["collection_timestamp"] = None
    with pytest.raises(ProvenanceError, match="no usable collection_timestamp"):
        build(baseline, defense)


def test_rejects_timezone_naive_timestamp(fresh):
    """A naive stamp resolves against the RUNNING MACHINE's zone.

    Naive 2026-07-25T01:00:00 becomes 2026-07-24 UTC in a positive-offset zone,
    silently moving the arm's collection date by a day and corrupting the
    non-contemporaneous-arms confound.
    """
    baseline, defense = fresh
    defense["traces"][0]["collection_timestamp"] = "2026-07-25T01:00:00"
    with pytest.raises(ProvenanceError, match="timezone-naive"):
        build(baseline, defense)


def test_rejects_unparseable_timestamp(fresh):
    baseline, defense = fresh
    defense["traces"][0]["collection_timestamp"] = "last Tuesday"
    with pytest.raises(ProvenanceError, match="unparseable"):
        build(baseline, defense)


# ---------------------------------------------------------------------------
# Negative controls — version header and released-artifact cross-check
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("field", ["schema_version", "pipeline_git_commit",
                                   "task_taxonomy_version",
                                   "labeling_rules_version"])
def test_rejects_missing_version_header(fresh, field):
    baseline, defense = fresh
    defense.pop(field, None)
    with pytest.raises(ProvenanceError, match="missing version field"):
        build(baseline, defense)


def test_rejects_prompt_mismatch_drift(fresh):
    baseline, defense = fresh
    for t in defense["traces"][:50]:
        t["task_prompt"] = "ALTERED"
    with pytest.raises(ProvenanceError, match="prompt-text mismatch recomputed"):
        build(baseline, defense)


def test_fails_when_released_artifact_is_absent(fresh, monkeypatch):
    """A skipped cross-check is a silently unverified number."""
    import verify_guarded_run_provenance as mod
    monkeypatch.setattr(mod, "RELEASED_PAIRED",
                        REPO / "results" / "no_such_artifact.json")
    with pytest.raises(ProvenanceError, match="required input missing"):
        build(*fresh)


def test_fails_when_released_artifact_schema_changed(fresh, monkeypatch, tmp_path):
    stub = tmp_path / "paired.json"
    stub.write_text(json.dumps({"live_guard": {"safety": {}}}), encoding="utf-8")
    import verify_guarded_run_provenance as mod
    monkeypatch.setattr(mod, "RELEASED_PAIRED", stub)
    with pytest.raises(ProvenanceError, match="schema has changed"):
        build(*fresh)


def test_fails_when_released_artifact_is_corrupt(fresh, monkeypatch, tmp_path):
    stub = tmp_path / "paired.json"
    stub.write_text("{not json", encoding="utf-8")
    import verify_guarded_run_provenance as mod
    monkeypatch.setattr(mod, "RELEASED_PAIRED", stub)
    with pytest.raises(ProvenanceError, match="not valid JSON"):
        build(*fresh)
