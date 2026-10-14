"""Tests for the guarded-run macro block in generate_results_macros.py.

Two properties, both load-bearing:

1. **Input-hash drift is caught.** The artifact records the SHA-256 of the
   traces it was computed from. If a relabel changes those bytes, macro
   generation must stop rather than emitting statistics derived from the old
   ones.
2. **The claim boundary is machine-checked.** The historical guarded run cannot
   support a causal, cross-model, or utility conclusion. An artifact that
   asserts one must abort macro generation, not quietly widen what the
   manuscript may say.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

from generate_results_macros import (  # noqa: E402
    GUARDED_RUN_ARTIFACT,
    require_artifact,
    require_recorded_inputs,
)

pytestmark = pytest.mark.skipif(
    not GUARDED_RUN_ARTIFACT.exists(),
    reason="guarded-run provenance artifact not generated",
)

MACROS = REPO / "paper" / "results_macros.tex"


@pytest.fixture
def artifact():
    return json.loads(GUARDED_RUN_ARTIFACT.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# Input-hash re-verification
# ---------------------------------------------------------------------------

def test_recorded_inputs_match_disk(artifact):
    """Positive control: the artifact is current with respect to its traces."""
    require_recorded_inputs(artifact, GUARDED_RUN_ARTIFACT)


def test_rejects_input_hash_drift(artifact):
    bad = copy.deepcopy(artifact)
    arm = next(iter(bad["inputs"]))
    bad["inputs"][arm]["sha256"] = "0" * 64
    with pytest.raises(SystemExit, match="input drift"):
        require_recorded_inputs(bad, GUARDED_RUN_ARTIFACT)


def test_rejects_vanished_input(artifact):
    bad = copy.deepcopy(artifact)
    arm = next(iter(bad["inputs"]))
    bad["inputs"][arm]["path"] = "results/no_such_trace_file.json"
    with pytest.raises(SystemExit, match="no longer exists"):
        require_recorded_inputs(bad, GUARDED_RUN_ARTIFACT)


def test_rejects_schema_drift(tmp_path):
    stub = tmp_path / "artifact.json"
    stub.write_text(json.dumps({"artifact_schema_version": "something_else"}),
                    encoding="utf-8")
    with pytest.raises(SystemExit, match="schema drift"):
        require_artifact(stub, "artifact_schema_version",
                         "guarded_run_provenance/v1")


def test_rejects_missing_artifact(tmp_path):
    with pytest.raises(SystemExit, match="required artifact missing"):
        require_artifact(tmp_path / "absent.json", "artifact_schema_version",
                         "guarded_run_provenance/v1")


# ---------------------------------------------------------------------------
# Claim boundary
# ---------------------------------------------------------------------------

def test_evidence_scope_disclaims_the_retracted_conclusions(artifact):
    """The three conclusions withdrawn from the manuscript stay disclaimed."""
    scope = artifact["evidence_scope"]
    assert scope["causal"] is False
    assert scope["cross_model"] is False
    assert scope["supports_utility_claim"] is False
    assert scope["comparison_type"] == \
        "historical_matched_coverage_observed_difference"


def test_confounds_are_present_and_nonempty(artifact):
    conf = artifact["confounds"]
    assert conf["differing_pipeline_commit"]["differs"] is True
    assert conf["prompt_text_not_controlled"]["prompt_text_diff_pairs"] > 0
    assert conf["single_model"]
    assert conf["arm_ordering_not_randomized"] is True


def test_arm_is_single_model(artifact):
    """The cross-model claim this corrects is impossible from one arm."""
    assert artifact["arm_identity"]["model"] == "deepseek-v4-flash"
    assert artifact["arm_identity"]["defense_field"] == "taint_tracking"


# ---------------------------------------------------------------------------
# Macro surface
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not MACROS.exists(), reason="macros not generated")
def test_guarded_run_macros_are_emitted():
    text = MACROS.read_text(encoding="utf-8")
    for name in ("guardedRunPairs", "guardedRunDiff", "guardedRunPromptDiffPairs",
                 "guardedRunBaselineCommit", "guardedRunBrowserResidual",
                 "guardedRunOtherMechResidual"):
        assert f"\\newcommand{{\\{name}}}" in text, f"missing macro {name}"


@pytest.mark.skipif(not MACROS.exists(), reason="macros not generated")
def test_guarded_run_and_live_pilot_macros_stay_distinct():
    """Distinct prefixes keep the two bodies of evidence un-conflatable.

    The historical run (387 cells, one model, confounded) and the same-day
    pilot (39 pairs, prompt-matched) answer different questions. Sharing a
    prefix would make a `\\liveGuard...` in the .tex ambiguous about which
    evidence it cites.
    """
    text = MACROS.read_text(encoding="utf-8")
    guarded = {ln.split("}")[0].split("{\\")[1] for ln in text.splitlines()
               if ln.startswith("\\newcommand{\\guardedRun")}
    live = {ln.split("}")[0].split("{\\")[1] for ln in text.splitlines()
            if ln.startswith("\\newcommand{\\liveGuard")}
    assert guarded and live
    assert not (guarded & live)


@pytest.mark.skipif(not MACROS.exists(), reason="macros not generated")
def test_guarded_run_macros_match_the_artifact(artifact):
    """Every emitted value must trace back to the artifact, not to prose."""
    text = MACROS.read_text(encoding="utf-8")
    paired = artifact["paired_actual_sink"]
    expected = {
        "guardedRunPairs": str(paired["n_pairs"]),
        "guardedRunRiskPairs": str(artifact["denominator"]["risk_pairs"]),
        "guardedRunBenignPairs":
            str(artifact["denominator"]["benign_control_pairs"]),
        "guardedRunDiscordantC":
            str(paired["mcnemar_discordance"]["c_baseline_unsafe_defense_safe"]),
        "guardedRunPromptDiffPairs": str(
            artifact["confounds"]["prompt_text_not_controlled"]
            ["prompt_text_diff_pairs"]),
        "guardedRunBlockedEvents":
            str(artifact["guard_activity"]["taint_blocked_events"]),
    }
    for name, value in expected.items():
        assert f"\\newcommand{{\\{name}}}{{{value}}}" in text, \
            f"{name} does not match the artifact value {value}"
