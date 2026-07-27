"""Unit tests for the P2 recall-estimation Stage-2 plumbing.

These are pure-logic tests over synthetic traces and small integer fixtures --
they never read a trace file, never call a judge, and incur no cost. They pin
the frozen rules documented in ``docs/p2_recall_plan.md`` (rev 2):

* the no-defense arm filter (``is_no_defense``) that keeps live-guard defense
  traces out of the main-benchmark recall pool,
* the judge evidence window == the labeler's full outbound channel union
  (so the two never silently drift apart),
* proportional ``model x risk_mechanism`` allocation: largest-remainder
  rounding, thin-cell census, deterministic tie-break, uncovered-cell reporting,
* the pooled Wilson 95% score interval (frozen primary interval).
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
SCRIPTS_ROOT = REPO_ROOT / "scripts"
for _p in (SRC_ROOT, SCRIPTS_ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import estimate_recall as ER  # noqa: E402
from mcphunt.taxonomy import (  # noqa: E402
    WRITE_TOOLS,
    BROWSER_INPUT_TOOLS,
    RISK_MECHANISMS,
    TASK_MECHANISM_MAP,
)


def _trace(model="m", mech="file_to_file", tid="t", tool_events=None):
    return {
        "model": model,
        "risk_mechanism": mech,
        "trace_id": tid,
        "events": tool_events or [],
    }


def _candidate(model="m", mech="file_to_file", tid="t"):
    """A trace that satisfies the base eligibility predicate."""
    return {
        "model": model,
        "risk_mechanism": mech,
        "trace_id": tid,
        "env_type": "risky_v1",
        "labeling": {"any_risk": False, "sensitive_data_read": True},
        "events": [],
    }


class TestNoDefenseFilter(unittest.TestCase):
    def test_none_string_is_no_defense(self):
        self.assertTrue(ER.is_no_defense({"defense": "none"}))

    def test_missing_and_empty_are_no_defense(self):
        self.assertTrue(ER.is_no_defense({}))
        self.assertTrue(ER.is_no_defense({"defense": ""}))
        self.assertTrue(ER.is_no_defense({"defense": None}))

    def test_case_and_whitespace_insensitive(self):
        self.assertTrue(ER.is_no_defense({"defense": "  NONE "}))

    def test_active_defense_is_not_no_defense(self):
        self.assertFalse(ER.is_no_defense({"defense": "taint_tracking"}))


class TestJudgeEvidenceWindow(unittest.TestCase):
    def test_equals_labeler_channel_union(self):
        # The judge must see exactly the channels the labeler scores:
        # writes + browser input + the two outbound exfil tools.
        expected = set(WRITE_TOOLS) | set(BROWSER_INPUT_TOOLS) | {"fetch", "browser_navigate"}
        self.assertEqual(set(ER.JUDGE_EVIDENCE_TOOLS), expected)

    def test_write_tools_are_covered(self):
        self.assertTrue(set(WRITE_TOOLS).issubset(ER.JUDGE_EVIDENCE_TOOLS))

    def test_outbound_exfil_channels_present(self):
        # Regression guard against the rev1 write-only blind spot.
        for tool in ("fetch", "browser_navigate", "browser_type", "browser_fill_form"):
            self.assertIn(tool, ER.JUDGE_EVIDENCE_TOOLS)

    def test_read_only_tool_excluded(self):
        self.assertNotIn("read_file", ER.JUDGE_EVIDENCE_TOOLS)

    def test_extract_evidence_selects_only_window(self):
        events = [
            {"turn": 1, "server": "fs", "tool": "read_file", "args": {"path": "x"}},
            {"turn": 2, "server": "fs", "tool": "write_file", "args": {"content": "secret"}},
            {"turn": 3, "server": "fetch", "tool": "fetch", "args": {"url": "http://x"}},
        ]
        text, n_trunc = ER.extract_evidence_events(_trace(tool_events=events))
        self.assertIn("write_file", text)
        self.assertIn("fetch", text)
        self.assertNotIn("read_file", text)
        self.assertEqual(n_trunc, 0)

    def test_extract_evidence_counts_truncation(self):
        big = {"turn": 1, "server": "fs", "tool": "write_file",
               "args": {"content": "x" * (ER.EVENT_ARG_TRUNCATION_CHARS + 100)}}
        text, n_trunc = ER.extract_evidence_events(_trace(tool_events=[big]))
        self.assertEqual(n_trunc, 1)
        self.assertIn("(truncated)", text)

    def test_extract_evidence_empty(self):
        text, n_trunc = ER.extract_evidence_events(_trace(tool_events=[]))
        self.assertEqual(n_trunc, 0)
        self.assertIn("no outbound-channel", text)


class TestWilsonInterval(unittest.TestCase):
    def test_known_value_50_of_100(self):
        # Wilson 95% for 50/100 is approximately [0.404, 0.596].
        lo, hi = ER.wilson_interval(50, 100)
        self.assertAlmostEqual(lo, 0.4038, places=3)
        self.assertAlmostEqual(hi, 0.5962, places=3)

    def test_zero_events(self):
        lo, hi = ER.wilson_interval(0, 100)
        # lo is 0 up to floating-point residue (Wilson center - half at k=0).
        self.assertAlmostEqual(lo, 0.0, places=9)
        self.assertGreater(hi, 0.0)
        self.assertLess(hi, 0.05)

    def test_all_events(self):
        lo, hi = ER.wilson_interval(100, 100)
        self.assertGreater(lo, 0.95)
        self.assertEqual(hi, 1.0)

    def test_empty_n_returns_uninformative(self):
        self.assertEqual(ER.wilson_interval(0, 0), (0.0, 1.0))

    def test_interval_brackets_point_estimate(self):
        lo, hi = ER.wilson_interval(7, 40)
        self.assertLessEqual(lo, 7 / 40)
        self.assertGreaterEqual(hi, 7 / 40)


class TestProportionalAllocation(unittest.TestCase):
    def test_sum_equals_sample_size_when_below_pool(self):
        pool = {("a", "x"): 100, ("a", "y"): 100, ("b", "x"): 100}
        alloc = ER.allocate_proportional(pool, 60)
        self.assertEqual(sum(alloc.values()), 60)

    def test_proportional_split_even(self):
        pool = {("a", "x"): 100, ("a", "y"): 100, ("b", "x"): 100}
        alloc = ER.allocate_proportional(pool, 60)
        self.assertEqual(alloc[("a", "x")], 20)
        self.assertEqual(alloc[("a", "y")], 20)
        self.assertEqual(alloc[("b", "x")], 20)

    def test_largest_remainder_deterministic(self):
        # Three equal cells, N=10 -> ideal 3.33 each; largest remainder gives
        # the extra draw to the lexicographically first cell (tie-break).
        pool = {("a", "x"): 10, ("a", "y"): 10, ("a", "z"): 10}
        alloc = ER.allocate_proportional(pool, 10)
        self.assertEqual(sum(alloc.values()), 10)
        self.assertEqual(alloc[("a", "x")], 4)
        self.assertEqual(alloc[("a", "y")], 3)
        self.assertEqual(alloc[("a", "z")], 3)

    def test_thin_cell_census_caps_at_pool(self):
        # A tiny cell cannot receive more than its pool; freed draws go to the
        # rest. N=50, tiny cell has only 2 traces.
        pool = {("a", "x"): 2, ("a", "y"): 500}
        alloc = ER.allocate_proportional(pool, 50)
        self.assertLessEqual(alloc[("a", "x")], 2)
        self.assertEqual(sum(alloc.values()), 50)

    def test_census_when_sample_exceeds_pool(self):
        pool = {("a", "x"): 10, ("a", "y"): 20}
        alloc = ER.allocate_proportional(pool, 1000)
        self.assertEqual(alloc[("a", "x")], 10)
        self.assertEqual(alloc[("a", "y")], 20)

    def test_empty_pool_returns_zeros(self):
        alloc = ER.allocate_proportional({}, 50)
        self.assertEqual(alloc, {})

    def test_zero_sample_size(self):
        pool = {("a", "x"): 10}
        alloc = ER.allocate_proportional(pool, 0)
        self.assertEqual(alloc[("a", "x")], 0)


class TestAllocationReport(unittest.TestCase):
    def _pool(self):
        traces = []
        for i in range(3):
            traces.append(_trace(model="a", mech="x", tid=f"ax{i}"))
        for i in range(30):
            traces.append(_trace(model="a", mech="y", tid=f"ay{i}"))
        return traces

    def test_uncovered_cells_reported_not_dropped(self):
        report = ER.build_allocation_report(self._pool(), 5)
        cells = {(c["model"], c["risk_mechanism"]): c for c in report["cells"]}
        # Both cells appear in the table even if one gets 0 draws.
        self.assertIn(("a", "x"), cells)
        self.assertIn(("a", "y"), cells)
        uncovered = {(u["model"], u["risk_mechanism"]) for u in report["uncovered_cells"]}
        for cell in cells.values():
            if cell["allocated"] == 0:
                self.assertIn((cell["model"], cell["risk_mechanism"]), uncovered)

    def test_totals(self):
        report = ER.build_allocation_report(self._pool(), 5)
        self.assertEqual(report["total_pool"], 33)
        self.assertEqual(report["total_allocated"], 5)


class TestStratifiedSampling(unittest.TestCase):
    def _pool(self):
        traces = []
        for i in range(40):
            traces.append(_trace(model="a", mech="x", tid=f"ax{i}"))
        for i in range(60):
            traces.append(_trace(model="a", mech="y", tid=f"ay{i}"))
        return traces

    def test_deterministic_given_seed(self):
        pool = self._pool()
        s1 = ER.sample_stratified(pool, 20, seed=42)
        s2 = ER.sample_stratified(pool, 20, seed=42)
        self.assertEqual([t["trace_id"] for t in s1], [t["trace_id"] for t in s2])

    def test_sample_size_respected(self):
        pool = self._pool()
        s = ER.sample_stratified(pool, 20, seed=42)
        self.assertEqual(len(s), 20)

    def test_draws_from_declared_cells(self):
        pool = self._pool()
        alloc = ER.allocate_proportional(
            {("a", "x"): 40, ("a", "y"): 60}, 20)
        s = ER.sample_stratified(pool, 20, seed=42)
        got = {}
        for t in s:
            k = (t["model"], t["risk_mechanism"])
            got[k] = got.get(k, 0) + 1
        self.assertEqual(got.get(("a", "x"), 0), alloc[("a", "x")])
        self.assertEqual(got.get(("a", "y"), 0), alloc[("a", "y")])


class _FakeMessage:
    def __init__(self, content):
        self.content = content


class _FakeChoice:
    def __init__(self, content):
        self.message = _FakeMessage(content)


class _FakeResponse:
    def __init__(self, content):
        self.choices = [_FakeChoice(content)]


class _FakeCompletions:
    def __init__(self, content):
        self._content = content

    def create(self, **kwargs):
        return _FakeResponse(self._content)


class _FakeChat:
    def __init__(self, content):
        self.completions = _FakeCompletions(content)


class _FakeClient:
    """Minimal OpenAI-shaped client returning a fixed judge string."""
    def __init__(self, content):
        self.chat = _FakeChat(content)


class TestValidateJudgment(unittest.TestCase):
    def test_valid_response(self):
        r = ER.validate_judgment(
            {"leaked": True, "confidence": "high", "leak_type": "semantic"})
        self.assertTrue(r["valid"])

    def test_leaked_string_false_is_invalid(self):
        # "false" is a truthy string -- the exact bug this guard prevents.
        r = ER.validate_judgment(
            {"leaked": "false", "confidence": "high", "leak_type": "none"})
        self.assertFalse(r["valid"])
        self.assertFalse(r["leaked"])

    def test_missing_leaked_is_invalid(self):
        r = ER.validate_judgment({"confidence": "high", "leak_type": "none"})
        self.assertFalse(r["valid"])

    def test_bad_confidence_is_invalid(self):
        r = ER.validate_judgment(
            {"leaked": False, "confidence": "certain", "leak_type": "none"})
        self.assertFalse(r["valid"])

    def test_bad_leak_type_is_invalid(self):
        r = ER.validate_judgment(
            {"leaked": True, "confidence": "low", "leak_type": "paraphrase"})
        self.assertFalse(r["valid"])

    def test_non_object_is_invalid(self):
        self.assertFalse(ER.validate_judgment(["not", "an", "object"])["valid"])


class TestJudgeTraceSchema(unittest.TestCase):
    def _judge(self, content):
        return ER.judge_trace(_trace(), _FakeClient(content), "fake-model")

    def test_well_formed_is_valid(self):
        r = self._judge('{"leaked": false, "confidence": "high", '
                        '"evidence": "clean", "leak_type": "none"}')
        self.assertTrue(r["valid"])
        self.assertFalse(r["leaked"])

    def test_schema_violation_marked_invalid(self):
        r = self._judge('{"leaked": "false", "confidence": "high", '
                        '"leak_type": "none"}')
        self.assertFalse(r["valid"])
        self.assertIn("schema_error", r["evidence"])

    def test_non_json_marked_invalid(self):
        r = self._judge("the model refused to answer")
        self.assertFalse(r["valid"])
        self.assertIn("parse_error", r["evidence"])

    def test_broken_json_marked_invalid(self):
        r = self._judge('{"leaked": true, "confidence":')
        self.assertFalse(r["valid"])
        self.assertIn("parse_error", r["evidence"])


class TestTraceMechanism(unittest.TestCase):
    def test_risk_mechanism_field_preferred(self):
        self.assertEqual(
            ER.trace_mechanism({"risk_mechanism": "file_to_file"}), "file_to_file")

    def test_fallback_uses_task_id_not_category(self):
        # TASK_MECHANISM_MAP is keyed by task_id (tid), not task_category.
        tid, mech = next(iter(TASK_MECHANISM_MAP.items()))
        self.assertEqual(ER.trace_mechanism({"task_id": tid}), mech)

    def test_category_as_mechanism_name_accepted(self):
        self.assertEqual(
            ER.trace_mechanism({"task_category": "db_to_artifact"}), "db_to_artifact")

    def test_unknown_when_nothing_resolves(self):
        self.assertEqual(
            ER.trace_mechanism({"task_id": "no_such_task"}), "unknown")


class TestPoolRestriction(unittest.TestCase):
    def test_control_candidates_excluded_from_pool(self):
        traces = [
            _candidate(mech="file_to_file", tid="r1"),
            _candidate(mech="benign_control", tid="c1"),
        ]
        eligible = ER.select_eligible(traces)
        excluded = ER.excluded_control_candidates(traces)
        self.assertEqual([t["trace_id"] for t in eligible], ["r1"])
        self.assertEqual([t["trace_id"] for t in excluded], ["c1"])

    def test_eligible_are_all_risk_mechanisms(self):
        traces = [_candidate(mech=m, tid=f"t{i}")
                  for i, m in enumerate(sorted(RISK_MECHANISMS))]
        traces.append(_candidate(mech="benign_control", tid="ctrl"))
        eligible = ER.select_eligible(traces)
        self.assertEqual(len(eligible), len(RISK_MECHANISMS))
        for t in eligible:
            self.assertIn(ER.trace_mechanism(t), RISK_MECHANISMS)

    def test_non_candidate_excluded_from_both(self):
        # any_risk True -> not a false-negative candidate at all.
        t = _candidate(mech="file_to_file", tid="x")
        t["labeling"]["any_risk"] = True
        self.assertEqual(ER.select_eligible([t]), [])
        self.assertEqual(ER.excluded_control_candidates([t]), [])


class TestEmptyPoolCells(unittest.TestCase):
    def test_empty_cells_reported(self):
        # One model, one mechanism present -> the other 8 risk mechanisms for
        # that model are structurally empty.
        traces = [_candidate(model="a", mech="file_to_file", tid=f"t{i}")
                  for i in range(3)]
        report = ER.build_allocation_report(traces, 2)
        empty = {(c["model"], c["risk_mechanism"]) for c in report["empty_pool_cells"]}
        self.assertEqual(len(empty), len(RISK_MECHANISMS) - 1)
        self.assertNotIn(("a", "file_to_file"), empty)

    def test_all_control_model_still_gridded(self):
        # Model "b" has no eligible risk trace (only control). With observed_models
        # carrying "b", all 9 of b's risk cells must appear as structural gaps
        # rather than b vanishing from the grid entirely (finding: rev2 §3.5).
        traces = [_candidate(model="a", mech="file_to_file", tid="a1")]
        report = ER.build_allocation_report(
            traces, 1, observed_models=["a", "b"])
        empty = {(c["model"], c["risk_mechanism"]) for c in report["empty_pool_cells"]}
        b_cells = {(m, mech) for (m, mech) in empty if m == "b"}
        self.assertEqual(len(b_cells), len(RISK_MECHANISMS))

    def test_observed_models_absent_falls_back(self):
        traces = [_candidate(model="a", mech="file_to_file", tid="a1")]
        report = ER.build_allocation_report(traces, 1)
        models = {c["model"] for c in report["empty_pool_cells"]}
        self.assertEqual(models, {"a"})


if __name__ == "__main__":
    unittest.main()
