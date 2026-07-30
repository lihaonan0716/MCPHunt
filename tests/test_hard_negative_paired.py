"""Contract tests for the hard-negative matched-pair analysis.

Pins the AC-4 paired surface produced by scripts/compute_hard_negative_ci.py:
pairing integrity (one trace per task per arm, complete in both directions,
single model), the matched 2x2 construction, the Tango score interval for the
paired difference, and the exact McNemar p-value.

Pure-logic tests over synthetic traces; they never read a released trace file.
"""
from __future__ import annotations

import math
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
for p in (REPO_ROOT / "src", REPO_ROOT / "scripts"):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from mcphunt.taxonomy import TASK_REGISTRY  # noqa: E402

import compute_hard_negative_ci as HN  # noqa: E402


ALL_RISK_IDS = sorted(tid for tid, t in TASK_REGISTRY.items()
                      if t.task_type == "risk")


def _risk_task_ids(n: int) -> list:
    if len(ALL_RISK_IDS) < n:
        raise AssertionError(f"registry has only {len(ALL_RISK_IDS)} risk tasks")
    return ALL_RISK_IDS[:n]


def _trace(task_id: str, env_type: str, unsafe: bool,
           model: str = "test-model", prompt: str = "p") -> dict:
    return {
        "task_id": task_id,
        "env_type": env_type,
        "model": model,
        "task_prompt": prompt,
        "outcome": "unsafe_success" if unsafe else "safe_success",
    }


def _grid(risky_flags: list, hn_flags: list, **kw) -> list:
    """Build a COMPLETE paired trace grid over every registry risk task.

    The leading tasks take the supplied unsafe flags; the remainder are padded
    safe/safe. Padding to the full registry is deliberate: the pairing contract
    requires one cell per frozen risk task, so a grid that covered only a handful
    of tasks would be rejected as incomplete rather than testing the 2x2 logic.
    """
    if len(risky_flags) != len(hn_flags):
        raise AssertionError("both arms need one flag per specified task")
    pad = len(ALL_RISK_IDS) - len(risky_flags)
    risky_flags = list(risky_flags) + [False] * pad
    hn_flags = list(hn_flags) + [False] * pad
    traces = []
    for tid, ru in zip(ALL_RISK_IDS, risky_flags):
        traces.append(_trace(tid, HN.RISKY_ENV, ru, **kw))
    for tid, hu in zip(ALL_RISK_IDS, hn_flags):
        traces.append(_trace(tid, HN.HARDNEG_ENV, hu, **kw))
    return traces


class PairingIntegrityTest(unittest.TestCase):
    def test_builds_matched_2x2_from_task_pairing(self):
        # both / risky-only / hn-only = 1 / 2 / 1; the rest pad to neither.
        traces = _grid([True, True, True, False, False],
                       [True, False, False, True, False])
        paired = HN.build_paired_table(traces)
        self.assertEqual(paired["n_pairs"], len(ALL_RISK_IDS))
        self.assertEqual(paired["table"], {
            "both_unsafe": 1,
            "risky_only_unsafe": 2,
            "hard_negative_only_unsafe": 1,
            "neither_unsafe": len(ALL_RISK_IDS) - 4,
        })
        self.assertTrue(paired["pairing_complete"])
        self.assertEqual(paired["registry_risk_tasks"], len(ALL_RISK_IDS))

    def test_duplicate_task_cell_is_refused(self):
        traces = _grid([True, False], [False, False])
        traces.append(_trace(traces[0]["task_id"], HN.RISKY_ENV, False))
        with self.assertRaises(HN.PairingIntegrityError) as ctx:
            HN.build_paired_table(traces)
        self.assertIn("duplicate", str(ctx.exception))

    def test_incomplete_pairing_is_refused_not_intersected(self):
        # Dropping one hard-negative trace must abort, never silently pair the
        # remaining intersection -- that would change the denominator.
        dropped = ALL_RISK_IDS[2]
        traces = [t for t in _grid([True, False, True], [False, False, True])
                  if not (t["env_type"] == HN.HARDNEG_ENV
                          and t["task_id"] == dropped)]
        with self.assertRaises(HN.PairingIntegrityError) as ctx:
            HN.build_paired_table(traces)
        self.assertIn("incomplete pairing", str(ctx.exception))

    def test_task_missing_from_BOTH_arms_is_refused(self):
        # Regression guard: a symmetric hole leaves the arm-vs-arm set
        # difference empty, so the pairing looks complete while n silently
        # drops. The macros regenerate from the same trace file and shrink in
        # step, so only the registry-anchored denominator catches this.
        dropped = ALL_RISK_IDS[1]
        traces = [t for t in _grid([True, True, False], [False, True, False])
                  if t["task_id"] != dropped]
        with self.assertRaises(HN.PairingIntegrityError) as ctx:
            HN.build_paired_table(traces)
        msg = str(ctx.exception)
        self.assertIn("missing", msg)
        self.assertNotIn("incomplete pairing", msg)  # not the one-sided path

    def test_registry_shortfall_names_the_absolute_denominator(self):
        traces = _grid([True, False], [False, False])
        keep = set(ALL_RISK_IDS[:10])
        traces = [t for t in traces if t["task_id"] in keep]
        with self.assertRaises(HN.PairingIntegrityError) as ctx:
            HN.build_paired_table(traces)
        self.assertIn(f"of {len(ALL_RISK_IDS)}", str(ctx.exception))

    def test_multi_model_arms_are_refused(self):
        traces = _grid([True, False], [False, False])
        traces[0]["model"] = "other-model"
        with self.assertRaises(HN.PairingIntegrityError) as ctx:
            HN.build_paired_table(traces)
        self.assertIn("within-model", str(ctx.exception))

    def test_non_risk_and_other_env_traces_are_ignored(self):
        traces = _grid([True, False], [False, False])
        benign = sorted(tid for tid, t in TASK_REGISTRY.items()
                        if t.task_type == "benign")
        traces.append(_trace(benign[0], HN.RISKY_ENV, True))
        traces.append(_trace(traces[0]["task_id"], "risky_v2", True))
        paired = HN.build_paired_table(traces)
        self.assertEqual(paired["n_pairs"], len(ALL_RISK_IDS))
        self.assertEqual(paired["table"]["risky_only_unsafe"], 1)

    def test_prompt_text_difference_is_counted(self):
        traces = _grid([True], [True])
        traces[1]["task_prompt"] = "different"
        paired = HN.build_paired_table(traces)
        self.assertEqual(paired["prompt_text_diff_pairs"], 1)


class ProvenanceDigestTest(unittest.TestCase):
    """The row digest must see permutations the 2x2 totals cannot."""

    def test_row_digest_changes_when_outcomes_move_between_tasks(self):
        # Same 2x2 (one risky-only, one hn-only), different tasks carrying them.
        a = HN.build_paired_table(_grid([True, False], [False, True]))
        b = HN.build_paired_table(_grid([False, True], [True, False]))
        self.assertEqual(a["table"], b["table"])
        self.assertEqual(a["task_ids_sha256"], b["task_ids_sha256"])
        self.assertNotEqual(a["paired_rows_sha256"], b["paired_rows_sha256"])

    def test_row_digest_changes_when_prompt_match_changes(self):
        base = _grid([True], [True])
        a = HN.build_paired_table(base)
        moved = _grid([True], [True])
        moved[1]["task_prompt"] = "different"
        b = HN.build_paired_table(moved)
        self.assertEqual(a["table"], b["table"])
        self.assertNotEqual(a["paired_rows_sha256"], b["paired_rows_sha256"])

    def test_row_digest_is_deterministic_across_trace_order(self):
        traces = _grid([True, False, True], [False, True, True])
        a = HN.build_paired_table(traces)
        b = HN.build_paired_table(list(reversed(traces)))
        self.assertEqual(a["paired_rows_sha256"], b["paired_rows_sha256"])


class PairedIntervalTest(unittest.TestCase):
    def test_tango_interval_brackets_point_and_covers_zero_when_ns(self):
        n, b, c = 108, 9, 3
        point = (b - c) / n
        lo, hi = HN.tango_score_interval(n, b, c)
        self.assertLess(lo, point)
        self.assertGreater(hi, point)
        self.assertLess(lo, 0.0)  # not distinguishable from zero
        self.assertGreater(hi, 0.0)

    def test_tango_endpoints_solve_the_score_equation(self):
        # The defining property: |score(endpoint)| == z. This pins the method,
        # not a remembered pair of numbers.
        n, b, c = 108, 9, 3
        lo, hi = HN.tango_score_interval(n, b, c)
        self.assertAlmostEqual(HN._tango_score(lo, n, b, c), HN._Z95, places=6)
        self.assertAlmostEqual(HN._tango_score(hi, n, b, c), -HN._Z95, places=6)

    def test_tango_p21_closed_form_matches_numeric_profile_mle(self):
        # Cross-check the closed-form constrained MLE against a direct grid
        # search of the profile log-likelihood, so an algebra slip is caught.
        n, a, b, c, d = 108, 19, 9, 3, 77
        for delta in (-0.02, 0.0, 0.05, 0.10):
            closed = HN._tango_p21(delta, n, b, c)

            def negll(p21: float) -> float:
                p12 = p21 + delta
                p11 = None  # profiled out below
                # Under the constraint, p11 is free; the profile over p11 with
                # p12/p21 fixed is maximised at p11 = a/n * (1 - p12 - p21) /
                # (1 - p12 - p21) i.e. the multinomial MLE a/(a+d) share of the
                # concordant mass. Use the concordant split directly.
                conc = 1.0 - p12 - p21
                if min(p12, p21, conc) <= 1e-12:
                    return math.inf
                p11 = conc * a / (a + d)
                p22 = conc - p11
                if min(p11, p22) <= 1e-12:
                    return math.inf
                return -(a * math.log(p11) + b * math.log(p12)
                         + c * math.log(p21) + d * math.log(p22))

            lo_bound = max(1e-9, -delta + 1e-9)
            grid = [lo_bound + i * (0.4 - lo_bound) / 40000
                    for i in range(40001)]
            best = min(grid, key=negll)
            self.assertAlmostEqual(closed, best, places=4,
                                   msg=f"delta={delta}")

    def test_wald_is_narrower_here_and_kept_as_sensitivity_only(self):
        n, b, c = 108, 9, 3
        t_lo, t_hi = HN.tango_score_interval(n, b, c)
        w_lo, w_hi = HN.wald_paired_interval(n, b, c)
        self.assertLess(t_hi - t_lo, 1.0)
        self.assertLess(w_hi - w_lo, t_hi - t_lo)

    def test_no_discordance_gives_zero_point(self):
        lo, hi = HN.tango_score_interval(50, 0, 0)
        self.assertLessEqual(lo, 0.0)
        self.assertGreaterEqual(hi, 0.0)

    def test_zero_pairs_is_degenerate_not_a_crash(self):
        self.assertEqual(HN.tango_score_interval(0, 0, 0), (0.0, 0.0))
        self.assertEqual(HN.wald_paired_interval(0, 0, 0), (0.0, 0.0))

    def test_all_discordant_one_way_hits_the_admissible_boundary(self):
        # b == n means every pair favours the risky arm, so the point estimate
        # IS +1 and the upper endpoint is the boundary itself. Tango's method is
        # specifically valid with an empty off-diagonal cell, so these inputs
        # must return an interval rather than raise.
        for n in (1, 2, 10, 108):
            lo, hi = HN.tango_score_interval(n, n, 0)
            self.assertEqual(hi, 1.0, msg=f"n={n}")
            self.assertLess(lo, 1.0, msg=f"n={n}")
            self.assertGreater(lo, -1.0, msg=f"n={n}")

            lo, hi = HN.tango_score_interval(n, 0, n)
            self.assertEqual(lo, -1.0, msg=f"n={n}")
            self.assertGreater(hi, -1.0, msg=f"n={n}")
            self.assertLess(hi, 1.0, msg=f"n={n}")

    def test_boundary_cases_are_symmetric_under_swapping_b_and_c(self):
        for n, b, c in ((1, 1, 0), (2, 2, 0), (10, 10, 0), (10, 9, 0),
                        (10, 9, 1), (108, 9, 3)):
            lo, hi = HN.tango_score_interval(n, b, c)
            slo, shi = HN.tango_score_interval(n, c, b)
            self.assertAlmostEqual(lo, -shi, places=12, msg=f"{n},{b},{c}")
            self.assertAlmostEqual(hi, -slo, places=12, msg=f"{n},{b},{c}")

    def test_interior_endpoints_still_solve_the_score_equation(self):
        # Boundary handling must not perturb cases whose endpoints are interior.
        for n, b, c in ((10, 9, 0), (108, 9, 3), (50, 25, 5)):
            lo, hi = HN.tango_score_interval(n, b, c)
            if -1.0 < lo:
                self.assertAlmostEqual(HN._tango_score(lo, n, b, c), HN._Z95,
                                       places=6, msg=f"{n},{b},{c}")
            if hi < 1.0:
                self.assertAlmostEqual(HN._tango_score(hi, n, b, c), -HN._Z95,
                                       places=6, msg=f"{n},{b},{c}")

    def test_every_small_table_is_computable(self):
        # Exhaustive sweep over admissible (n, b, c): no input in the domain may
        # raise, and every interval must contain the point estimate.
        for n in range(1, 13):
            for b in range(0, n + 1):
                for c in range(0, n - b + 1):
                    lo, hi = HN.tango_score_interval(n, b, c)
                    point = (b - c) / n
                    self.assertLessEqual(lo, point + 1e-12,
                                         msg=f"n={n} b={b} c={c}")
                    self.assertGreaterEqual(hi, point - 1e-12,
                                            msg=f"n={n} b={b} c={c}")
                    self.assertGreaterEqual(lo, -1.0, msg=f"n={n} b={b} c={c}")
                    self.assertLessEqual(hi, 1.0, msg=f"n={n} b={b} c={c}")


class McNemarExactTest(unittest.TestCase):
    def test_exact_p_matches_scipy_binomtest(self):
        try:
            from scipy.stats import binomtest
        except ImportError:  # pragma: no cover - scipy is a declared dep
            self.skipTest("scipy unavailable")
        for b, c in ((9, 3), (12, 1), (0, 0), (5, 5), (20, 4), (1, 7)):
            expected = binomtest(b, b + c, 0.5,
                                 alternative="two-sided").pvalue if b + c else 1.0
            self.assertAlmostEqual(HN.mcnemar_exact_p(b, c), expected,
                                   places=12, msg=f"b={b} c={c}")

    def test_symmetric_in_b_and_c(self):
        self.assertEqual(HN.mcnemar_exact_p(9, 3), HN.mcnemar_exact_p(3, 9))

    def test_no_discordant_pairs_gives_p_one(self):
        self.assertEqual(HN.mcnemar_exact_p(0, 0), 1.0)


class MarginalWilsonTest(unittest.TestCase):
    def test_wilson_matches_generator_convention_shape(self):
        lo, hi = HN.wilson_interval(28, 108)
        self.assertLess(lo, 28 / 108)
        self.assertGreater(hi, 28 / 108)
        self.assertGreaterEqual(lo, 0.0)
        self.assertLessEqual(hi, 1.0)

    def test_wilson_zero_denominator(self):
        self.assertEqual(HN.wilson_interval(0, 0), (0.0, 0.0))


if __name__ == "__main__":
    unittest.main()
