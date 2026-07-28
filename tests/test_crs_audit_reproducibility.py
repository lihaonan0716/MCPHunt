"""Reproducibility test for the CRS independent-audit reliability statistic.

This pins the headline inter-annotator numbers reported for the post-submission
CRS blind audit so they are reproducible from the committed raw labels
(``artifacts/release/crs_audit/annotation_{1,2}.csv``) via
``scripts/score_annotation.py``. It is the machine-checkable half of the
project's provenance-before-value invariant (#7): the restored kappa is only
legitimate if a real annotation event backs it AND the number is reproducible
from the committed labels — this test locks the second half.

Pure logic + committed CSVs; no trace files, no judge, no paid path.
"""
from __future__ import annotations

import csv
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

import score_annotation as sa  # noqa: E402

AUDIT_DIR = REPO_ROOT / "artifacts" / "release" / "crs_audit"
SHEET_A = AUDIT_DIR / "annotation_1.csv"
SHEET_B = AUDIT_DIR / "annotation_2.csv"

# Frozen headline values for the post-submission CRS audit. Changing these means
# the raw labels changed — that must be a deliberate, disclosed relabel, never a
# silent edit to move the statistic.
EXPECTED_N = 147
EXPECTED_AGREE = 138
EXPECTED_KAPPA = 0.7097
EXPECTED_CI = (0.5039, 0.8672)


class TestCrsAuditReproducibility(unittest.TestCase):
    def setUp(self) -> None:
        self.assertTrue(SHEET_A.exists(), f"missing committed raw labels: {SHEET_A}")
        self.assertTrue(SHEET_B.exists(), f"missing committed raw labels: {SHEET_B}")
        self.a = sa._load_sheet(SHEET_A)
        self.b = sa._load_sheet(SHEET_B)
        # Canonical item order = annotator-1 row order (see score_annotation.py).
        self.ids = list(self.a)
        self.va = [self.a[t] for t in self.ids]
        self.vb = [self.b[t] for t in self.ids]

    def test_same_task_set(self) -> None:
        self.assertEqual(set(self.a), set(self.b))
        self.assertEqual(len(self.ids), EXPECTED_N)

    def test_raw_agreement(self) -> None:
        agree = sum(1 for x, y in zip(self.va, self.vb) if x == y)
        self.assertEqual(agree, EXPECTED_AGREE)

    def test_headline_kappa(self) -> None:
        kappa = sa._cohen_kappa(self.va, self.vb)
        self.assertAlmostEqual(kappa, EXPECTED_KAPPA, places=4)

    def test_kappa_symmetric(self) -> None:
        # Cohen's kappa must not depend on which annotator is "a".
        self.assertAlmostEqual(
            sa._cohen_kappa(self.va, self.vb),
            sa._cohen_kappa(self.vb, self.va),
            places=12,
        )

    def test_bootstrap_ci(self) -> None:
        lo, hi = sa._bootstrap_kappa_ci(
            self.va, self.vb, sa.BOOTSTRAP_RESAMPLES, sa.BOOTSTRAP_SEED
        )
        self.assertAlmostEqual(lo, EXPECTED_CI[0], places=4)
        self.assertAlmostEqual(hi, EXPECTED_CI[1], places=4)

    def test_ci_order_invariant_under_fixed_seed(self) -> None:
        # Same canonical item order + fixed seed => same CI regardless of which
        # sheet is passed first (guards against the ordering fork that would
        # otherwise silently shift the committed interval).
        self.assertEqual(
            sa._bootstrap_kappa_ci(
                self.va, self.vb, sa.BOOTSTRAP_RESAMPLES, sa.BOOTSTRAP_SEED
            ),
            sa._bootstrap_kappa_ci(
                self.vb, self.va, sa.BOOTSTRAP_RESAMPLES, sa.BOOTSTRAP_SEED
            ),
        )

    def test_labels_are_binary_and_complete(self) -> None:
        # Every task labeled, values strictly boolean (no blanks slipped through).
        self.assertTrue(all(isinstance(v, bool) for v in self.a.values()))
        self.assertTrue(all(isinstance(v, bool) for v in self.b.values()))

    def test_raw_csv_columns(self) -> None:
        with SHEET_A.open(encoding="utf-8") as f:
            cols = next(csv.reader(f))
        self.assertIn("task_id", cols)
        self.assertIn("your_crs_label", cols)


if __name__ == "__main__":
    unittest.main()
