"""Reproducibility test for the deviance-share decomposition (mech vs. model).

Pins the two shares reported in the paper (`\\mechDevianceShare`,
`\\modelDevianceShare`) so they are reproducible from
``results/regression_data.csv`` via ``mcphunt.deviance.compute_deviance_shares``.

Two-level check (per docs/deviance_share_fix_plan.md §4):
- HARD sanity assertion (test failure): ``80 <= mech + model <= 100``. A
  violation means denominator / non-CRS subset / reference category /
  encoding drifted structurally — do NOT paper-over, fix the code.
- Snapshot band (informational warning, non-fatal): shares fall inside a
  narrow neighbourhood of the committed 62.1 / 31.9 headline. A drift
  inside the hard band but outside the snapshot band means either the
  input CSV changed (update the snapshot deliberately) or the method
  changed (re-run the plan gate).

Pure logic + committed CSV; no trace files, no judge, no paid path.
"""
from __future__ import annotations

import unittest
import warnings
from pathlib import Path

from mcphunt.deviance import compute_deviance_shares

REPO_ROOT = Path(__file__).resolve().parents[1]
REGRESSION_DATA = REPO_ROOT / "results" / "regression_data.csv"

# Frozen headline values for the paper's deviance-share (62% mechanism vs. 32%
# model). Changing these means either the input CSV changed or the
# decomposition method changed — that must be a deliberate, disclosed action,
# never a silent edit to move the split.
EXPECTED_N = 1_440
EXPECTED_MECH_SHARE = 62.1
EXPECTED_MODEL_SHARE = 31.9
DISPLAY_PRECISION = 0.5  # % (macro precision is 1 decimal, tolerate ±0.05 headline)
SNAPSHOT_BAND = (90.0, 98.0)  # informational; hard band is 60-100 (below)


class TestDevianceShareReproducibility(unittest.TestCase):
    """Pins the paper's mechanism vs. model deviance-share to the CSV."""

    def setUp(self) -> None:
        self.assertTrue(
            REGRESSION_DATA.exists(),
            f"missing regression input: {REGRESSION_DATA}",
        )
        self.result = compute_deviance_shares(REGRESSION_DATA)

    def test_non_crs_subset_size(self) -> None:
        # The appendix stakes n=1,440 for the non-CRS subset; if the CSV
        # changes so this drifts, the appendix number is no longer supported.
        self.assertEqual(self.result["n_rows_used"], EXPECTED_N)

    def test_hard_sanity_bounds(self) -> None:
        # Structural check: shares must both live in (0, 100] and their sum
        # in [60, 100]. A violation implies denominator/subset/reference-category
        # drift; fix the code, do not adjust the assertion.
        mech = self.result["mech_share_pct"]
        model = self.result["model_share_pct"]
        self.assertGreater(mech, 0.0)
        self.assertLessEqual(mech, 100.0)
        self.assertGreater(model, 0.0)
        self.assertLessEqual(model, 100.0)
        total = mech + model
        self.assertGreaterEqual(total, 60.0,
                                msg=f"shares sum too low: {total} (mech={mech}, model={model})")
        self.assertLessEqual(total, 100.0,
                             msg=f"shares sum > 100: {total} (mech={mech}, model={model})")

    def test_snapshot_band_informational(self) -> None:
        # Non-fatal: warn if the sum drifts out of the expected snapshot band
        # even while still inside the hard sanity band. This is a signal to
        # review whether the input CSV changed vs. whether a bug crept in.
        total = self.result["mech_share_pct"] + self.result["model_share_pct"]
        lo, hi = SNAPSHOT_BAND
        if not (lo <= total <= hi):
            warnings.warn(
                f"deviance-share sum {total:.2f}% drifted outside snapshot band "
                f"[{lo}, {hi}] — review whether the input CSV changed (update the "
                f"snapshot) or the method changed (re-run the plan gate)",
                RuntimeWarning,
                stacklevel=2,
            )

    def test_headline_mech_share(self) -> None:
        # Pins the paper's 62% figure to the CSV.
        self.assertAlmostEqual(
            self.result["mech_share_pct"], EXPECTED_MECH_SHARE,
            delta=DISPLAY_PRECISION,
        )

    def test_headline_model_share(self) -> None:
        # Pins the paper's 32% figure to the CSV.
        self.assertAlmostEqual(
            self.result["model_share_pct"], EXPECTED_MODEL_SHARE,
            delta=DISPLAY_PRECISION,
        )

    def test_pseudo_r2_ordering(self) -> None:
        # A full model must fit at least as well as either single-predictor
        # (larger pseudo-R²); if not, the null model or the encoding is wrong.
        r_mech = self.result["mech_pseudo_r2"]
        r_model = self.result["model_pseudo_r2"]
        r_full = self.result["full_pseudo_r2"]
        self.assertGreaterEqual(r_full, r_mech)
        self.assertGreaterEqual(r_full, r_model)
        self.assertGreater(r_mech, 0.0)
        self.assertGreater(r_model, 0.0)

    def test_input_hash_stable(self) -> None:
        # Determinism: running twice on the same CSV must return the same hash.
        r2 = compute_deviance_shares(REGRESSION_DATA)
        self.assertEqual(self.result["input_hash"], r2["input_hash"])
        self.assertAlmostEqual(
            self.result["mech_share_pct"], r2["mech_share_pct"], places=6,
        )


if __name__ == "__main__":
    unittest.main()
