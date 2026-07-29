"""Unit tests for the P2 detector-clean miss-prevalence Stage-2 plumbing.

These are pure-logic tests over synthetic traces and small integer fixtures --
they never read a trace file, never call a judge, and incur no cost. They pin
the frozen rules documented in ``docs/p2_recall_plan.md`` (rev 2):

* the no-defense arm filter (``is_no_defense``) that keeps live-guard defense
  traces out of the main-benchmark detector-clean pool,
* the judge evidence window == the labeler's full outbound channel union
  (so the two never silently drift apart),
* seeded pooled SRS over the stable detector-clean frame, plus diagnostic-only
  realized ``model x risk_mechanism`` coverage reporting,
* the pooled Wilson 95% score interval (frozen conservative primary interval)
  over the behavioral ``detector_clean_miss_prevalence`` estimand -- NOT a
  recall / false-negative-rate framing, and the missingness band + per-run
  output contract from decision 3.
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

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
        # Truncation is off by default (EVENT_ARG_TRUNCATION_CHARS == 0); the
        # capping behavior is still available when a positive limit is passed.
        cap = 2000
        big = {"turn": 1, "server": "fs", "tool": "write_file",
               "args": {"content": "x" * (cap + 100)}}
        text, n_trunc = ER.extract_evidence_events(
            _trace(tool_events=[big]), truncation_chars=cap)
        self.assertEqual(n_trunc, 1)
        self.assertIn("(truncated)", text)

    def test_extract_evidence_no_truncation_by_default(self):
        # With the default (0), even very large args pass through untruncated.
        self.assertEqual(ER.EVENT_ARG_TRUNCATION_CHARS, 0)
        big = {"turn": 1, "server": "fs", "tool": "write_file",
               "args": {"content": "x" * 10000}}
        text, n_trunc = ER.extract_evidence_events(_trace(tool_events=[big]))
        self.assertEqual(n_trunc, 0)
        self.assertNotIn("(truncated)", text)

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


class TestSRSSampler(unittest.TestCase):
    """Frozen estimand (decision 3, E-B): seeded without-replacement pooled SRS.

    NOT a proportional stratified allocation. Per-cell coverage is an outcome,
    never balanced, gated, or re-drawn.
    """

    def _pool(self):
        traces = []
        for i in range(40):
            traces.append(_trace(model="a", mech="x", tid=f"ax{i:03d}"))
        for i in range(60):
            traces.append(_trace(model="a", mech="y", tid=f"ay{i:03d}"))
        return traces

    def test_deterministic_given_seed(self):
        pool = self._pool()
        s1 = ER.sample_srs(pool, 20, seed=42)
        s2 = ER.sample_srs(pool, 20, seed=42)
        self.assertEqual([t["trace_id"] for t in s1], [t["trace_id"] for t in s2])

    def test_sample_size_respected(self):
        s = ER.sample_srs(self._pool(), 20, seed=42)
        self.assertEqual(len(s), 20)

    def test_without_replacement_no_duplicates(self):
        s = ER.sample_srs(self._pool(), 50, seed=42)
        ids = [t["trace_id"] for t in s]
        self.assertEqual(len(ids), len(set(ids)))

    def test_census_when_sample_meets_or_exceeds_pool(self):
        pool = self._pool()
        s = ER.sample_srs(pool, 1000, seed=42)
        self.assertEqual(len(s), len(pool))
        self.assertEqual({t["trace_id"] for t in s},
                         {t["trace_id"] for t in pool})

    def test_frame_is_stable_sorted_independent_of_input_order(self):
        pool = self._pool()
        import random as _r
        shuffled = list(pool)
        _r.Random(7).shuffle(shuffled)
        f1 = ER.sampling_frame(pool)
        f2 = ER.sampling_frame(shuffled)
        self.assertEqual([t["trace_id"] for t in f1],
                         [t["trace_id"] for t in f2])

    def test_frame_hash_stable_and_order_independent(self):
        pool = self._pool()
        import random as _r
        shuffled = list(pool)
        _r.Random(9).shuffle(shuffled)
        self.assertEqual(ER.sampling_frame_hash(ER.sampling_frame(pool)),
                         ER.sampling_frame_hash(ER.sampling_frame(shuffled)))

    def test_frame_hash_changes_when_pool_changes(self):
        pool = self._pool()
        h1 = ER.sampling_frame_hash(ER.sampling_frame(pool))
        pool2 = pool + [_trace(model="a", mech="x", tid="ax999")]
        h2 = ER.sampling_frame_hash(ER.sampling_frame(pool2))
        self.assertNotEqual(h1, h2)

    def test_same_trace_id_across_models_does_not_collide(self):
        """trace_id repeats across models (e.g. backup_all_risky_v1); the
        composite key must keep the two traces distinct everywhere so the SRS
        frame is well defined and a paid run provably hits the dry-run sample."""
        a = _trace(model="deepseek", mech="x", tid="shared_v1")
        b = _trace(model="opus", mech="x", tid="shared_v1")
        # Distinct composite keys despite identical trace_id.
        self.assertNotEqual(ER._stable_pool_key(a), ER._stable_pool_key(b))
        # Frame keeps both -- no silent dedup -- and the hash reflects both.
        frame = ER.sampling_frame([a, b])
        self.assertEqual(len(frame), 2)
        self.assertNotEqual(
            ER.sampling_frame_hash(ER.sampling_frame([a])),
            ER.sampling_frame_hash(frame),
        )
        # A census draw returns both, keyed by the collision-free composite.
        drawn = ER.sample_srs([a, b], 1000, seed=20260729)
        keys = [ER._stable_pool_key(t) for t in drawn]
        self.assertEqual(len(keys), 2)
        self.assertEqual(len(set(keys)), 2)


class TestRealizedCoverage(unittest.TestCase):
    def _pool(self):
        traces = []
        for i in range(3):
            traces.append(_trace(model="a", mech="x", tid=f"ax{i}"))
        for i in range(30):
            traces.append(_trace(model="a", mech="y", tid=f"ay{i}"))
        return traces

    def test_coverage_is_diagnostic_only_flag(self):
        pool = self._pool()
        sample = ER.sample_srs(pool, 5, seed=42)
        report = ER.realized_coverage(pool, sample)
        self.assertTrue(report["coverage_is_diagnostic_only"])
        self.assertEqual(report["design"], "pooled_srs_without_replacement")

    def test_totals_and_uncovered_reported(self):
        pool = self._pool()
        sample = ER.sample_srs(pool, 5, seed=42)
        report = ER.realized_coverage(pool, sample)
        self.assertEqual(report["total_pool"], 33)
        self.assertEqual(report["total_drawn"], 5)
        cells = {(c["model"], c["risk_mechanism"]): c for c in report["cells"]}
        self.assertIn(("a", "x"), cells)
        self.assertIn(("a", "y"), cells)
        uncovered = {(u["model"], u["risk_mechanism"])
                     for u in report["uncovered_cells"]}
        for cell in cells.values():
            if cell["drawn"] == 0:
                self.assertIn((cell["model"], cell["risk_mechanism"]), uncovered)


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


VALID_JSON = ('{"leaked": false, "confidence": "high", '
              '"evidence": "clean", "leak_type": "none"}')
INVALID_JSON = "the model refused to answer"  # -> parse_error -> valid=False


class _SeqCompletions:
    """Return scripted contents in call order; repeats the last once drained."""

    def __init__(self, contents):
        assert contents, "need at least one scripted content"
        self._q = list(contents)
        self.n_calls = 0

    def create(self, **kwargs):
        self.n_calls += 1
        content = self._q.pop(0) if len(self._q) > 1 else self._q[0]
        return _FakeResponse(content)


class _SeqChat:
    def __init__(self, contents):
        self.completions = _SeqCompletions(contents)


class _SeqClient:
    """OpenAI-shaped client scripted with a sequence of response bodies."""

    def __init__(self, contents):
        self.chat = _SeqChat(contents)


class TestTruncationStrata(unittest.TestCase):
    def _valid(self):
        return [
            {"evidence_truncated": True, "leaked": True},
            {"evidence_truncated": True, "leaked": False},
            {"evidence_truncated": False, "leaked": False},
            {"evidence_truncated": False, "leaked": False},
        ]

    def test_partition_sums_to_denominator(self):
        s = ER.compute_truncation_strata(self._valid())
        self.assertEqual(s["truncated"]["n"] + s["non_truncated"]["n"], 4)

    def test_misses_and_prevalence_per_stratum(self):
        s = ER.compute_truncation_strata(self._valid())
        self.assertEqual(s["truncated"]["n"], 2)
        self.assertEqual(s["truncated"]["misses"], 1)
        self.assertEqual(s["truncated"]["detector_clean_miss_prevalence"], 0.5)
        self.assertEqual(s["non_truncated"]["n"], 2)
        self.assertEqual(s["non_truncated"]["misses"], 0)
        self.assertEqual(s["non_truncated"]["detector_clean_miss_prevalence"], 0.0)

    def test_ci_fields_are_pairs(self):
        s = ER.compute_truncation_strata(self._valid())
        for name in ("truncated", "non_truncated"):
            self.assertEqual(
                len(s[name]["detector_clean_miss_prevalence_ci95"]), 2)

    def test_empty_stratum_is_unavailable_not_spurious_zero(self):
        # An empty stratum must NOT report prevalence=0.0 -- that would assert a
        # perfectly clean detector from zero observations.
        s = ER.compute_truncation_strata(
            [{"evidence_truncated": False, "leaked": False}])
        self.assertEqual(s["truncated"]["n"], 0)
        self.assertIsNone(s["truncated"]["detector_clean_miss_prevalence"])


class TestCensusStatus(unittest.TestCase):
    def test_complete_only_when_pool_drawn_and_all_valid(self):
        complete, status, _ = ER.compute_census_status(698, 698, 698)
        self.assertTrue(complete)
        self.assertEqual(status, "complete")

    def test_sub_sample_is_not_a_census(self):
        complete, status, _ = ER.compute_census_status(50, 50, 698)
        self.assertFalse(complete)
        self.assertEqual(status, "not_a_census")

    def test_full_pool_with_invalid_is_incomplete(self):
        # Full pool drawn but one judgment invalid -> denominator short.
        complete, status, _ = ER.compute_census_status(698, 697, 698)
        self.assertFalse(complete)
        self.assertEqual(status, "incomplete_invalid")

    def test_clean_full_pool_is_complete_at_any_pool_size(self):
        complete, status, _ = ER.compute_census_status(10, 10, 10)
        self.assertTrue(complete)
        self.assertEqual(status, "complete")


class TestJudgeSampleWithRetry(unittest.TestCase):
    def test_report_mode_single_call_per_trace(self):
        samples = [_trace(tid="a"), _trace(tid="b")]
        client = _SeqClient([INVALID_JSON, VALID_JSON])
        results, audit = ER.judge_sample_with_retry(
            samples, client, "m", on_invalid="report", max_retries=2)
        self.assertEqual(client.chat.completions.n_calls, 2)
        self.assertEqual([r["judge_attempts"] for r in results], [1, 1])
        self.assertTrue(all(r["finalized_after_retry"] is False for r in results))

    def test_report_mode_fixed_audit_values(self):
        samples = [_trace(tid="a")]  # invalid -> stays invalid under report
        client = _SeqClient([INVALID_JSON])
        results, audit = ER.judge_sample_with_retry(
            samples, client, "m", on_invalid="report", max_retries=2)
        self.assertEqual(audit["retry_policy"], "report")
        self.assertEqual(audit["max_retries"], 0)
        self.assertEqual(audit["retry_attempts_total"], 0)
        self.assertEqual(audit["retried_sample_keys"], [])
        self.assertEqual(audit["remaining_invalid_after_retry"], 1)
        self.assertEqual(results[0]["judge_attempts"], 1)
        self.assertFalse(results[0]["finalized_after_retry"])

    def test_per_result_audit_fields_present_in_report_mode(self):
        samples = [_trace(tid="a")]
        client = _SeqClient([VALID_JSON])
        results, _ = ER.judge_sample_with_retry(samples, client, "m")
        r = results[0]
        for key in ("evidence_truncated", "n_truncated_events",
                    "judge_attempts", "finalized_after_retry"):
            self.assertIn(key, r)

    def test_truncation_flag_propagates_to_result(self):
        cap = 2000
        big = {"turn": 1, "server": "fs", "tool": "write_file",
               "args": {"content": "x" * (cap + 50)}}
        samples = [_trace(tid="a", tool_events=[big])]
        client = _SeqClient([VALID_JSON])
        results, _ = ER.judge_sample_with_retry(
            samples, client, "m", truncation_chars=cap)
        self.assertTrue(results[0]["evidence_truncated"])
        self.assertEqual(results[0]["n_truncated_events"], 1)

    def test_no_truncation_flag_by_default(self):
        # Default run (truncation off) must not flag even huge evidence.
        big = {"turn": 1, "server": "fs", "tool": "write_file",
               "args": {"content": "x" * 10000}}
        samples = [_trace(tid="a", tool_events=[big])]
        client = _SeqClient([VALID_JSON])
        results, _ = ER.judge_sample_with_retry(samples, client, "m")
        self.assertFalse(results[0]["evidence_truncated"])
        self.assertEqual(results[0]["n_truncated_events"], 0)

    def test_retry_recovers_invalid_then_valid(self):
        samples = [_trace(tid="a")]
        client = _SeqClient([INVALID_JSON, VALID_JSON])
        results, audit = ER.judge_sample_with_retry(
            samples, client, "m", on_invalid="retry", max_retries=2)
        self.assertEqual(client.chat.completions.n_calls, 2)  # 1 initial + 1 retry
        r = results[0]
        self.assertEqual(r["judge_attempts"], 2)
        self.assertTrue(r["finalized_after_retry"])
        self.assertTrue(r["valid"])
        self.assertEqual(audit["retry_attempts_total"], 1)
        # Composite, collision-free identity (not the bare trace_id).
        self.assertEqual(audit["retried_sample_keys"],
                         [ER._stable_pool_key(samples[0])])
        self.assertEqual(audit["remaining_invalid_after_retry"], 0)

    def test_retry_stops_at_max_retries(self):
        samples = [_trace(tid="a")]
        client = _SeqClient([INVALID_JSON])  # never becomes valid
        results, audit = ER.judge_sample_with_retry(
            samples, client, "m", on_invalid="retry", max_retries=2)
        self.assertEqual(client.chat.completions.n_calls, 3)  # 1 + 2 retries
        r = results[0]
        self.assertEqual(r["judge_attempts"], 3)
        self.assertFalse(r["finalized_after_retry"])
        self.assertFalse(r["valid"])
        self.assertEqual(audit["retry_attempts_total"], 2)
        self.assertEqual(audit["remaining_invalid_after_retry"], 1)

    def test_retry_only_touches_invalid_traces(self):
        # a valid (1 call), b invalid then valid (2 calls) -> 3 total.
        samples = [_trace(tid="a"), _trace(tid="b")]
        client = _SeqClient([VALID_JSON, INVALID_JSON, VALID_JSON])
        results, audit = ER.judge_sample_with_retry(
            samples, client, "m", on_invalid="retry", max_retries=2)
        self.assertEqual(client.chat.completions.n_calls, 3)
        self.assertEqual(results[0]["judge_attempts"], 1)
        self.assertEqual(results[1]["judge_attempts"], 2)
        # Only the invalid trace ("b") is retried, keyed by composite identity.
        self.assertEqual(audit["retried_sample_keys"],
                         [ER._stable_pool_key(samples[1])])


class TestPooledMissPrevalence(unittest.TestCase):
    def test_zero_valid_gives_none_not_spurious_clean(self):
        # HIGH: n == 0 (all invalid) must not report prevalence=0 (a spuriously
        # clean detector from zero observations).
        m = ER.compute_pooled_miss_prevalence(0, 0)
        self.assertIsNone(m["detector_clean_miss_prevalence"])
        # No-information Wilson interval is still reported honestly.
        self.assertEqual(m["detector_clean_miss_prevalence_ci95"], [0.0, 1.0])

    def test_normal_point_estimate(self):
        m = ER.compute_pooled_miss_prevalence(2, 8)
        self.assertEqual(m["detector_clean_miss_prevalence"], 0.25)

    def test_zero_misses_nonzero_n_is_a_real_zero(self):
        # n > 0 with 0 misses IS a legitimate 0.0 prevalence estimate (not None).
        m = ER.compute_pooled_miss_prevalence(0, 10)
        self.assertEqual(m["detector_clean_miss_prevalence"], 0.0)

    def test_hypergeometric_sensitivity_field_when_pool_given(self):
        # A finite-population pool adds the exact hypergeometric sensitivity band.
        m = ER.compute_pooled_miss_prevalence(2, 8, pool_size=100)
        self.assertIn("detector_clean_miss_prevalence_hypergeom95", m)
        self.assertEqual(len(m["detector_clean_miss_prevalence_hypergeom95"]), 2)

    def test_renamed_symbol_fails_loudly(self):
        # The old FNR/recall entry point must not silently return numbers.
        with self.assertRaises(NotImplementedError):
            ER.compute_pooled_fnr_recall(2, 8)


class TestMissingnessBounds(unittest.TestCase):
    """Invalid-judgment contract (decision 3): band over the full n."""

    def test_m_zero_band_is_degenerate(self):
        # No permanent invalids -> optimistic == pessimistic, single interval.
        b = ER.compute_missingness_bounds(k=3, m=0, n=150, pool_size=698)
        self.assertTrue(b["bounds_are_degenerate"])
        self.assertTrue(b["estimable"])
        self.assertEqual(
            b["optimistic"]["detector_clean_miss_prevalence"],
            b["pessimistic"]["detector_clean_miss_prevalence"],
        )
        self.assertEqual(b["complete_case_n"], 150)

    def test_m_positive_band_separates(self):
        # m > 0 -> optimistic (misses=k) below pessimistic (misses=k+m); the
        # complete-case point k/(n-m) is reported for description only.
        b = ER.compute_missingness_bounds(k=3, m=5, n=150, pool_size=698)
        self.assertFalse(b["bounds_are_degenerate"])
        self.assertTrue(b["estimable"])
        self.assertEqual(b["observed_misses_k"], 3)
        self.assertEqual(b["permanent_invalid_m"], 5)
        self.assertEqual(b["complete_case_n"], 145)
        opt = b["optimistic"]["detector_clean_miss_prevalence"]
        pess = b["pessimistic"]["detector_clean_miss_prevalence"]
        self.assertLess(opt, pess)
        self.assertEqual(b["optimistic"]["misses"], 3)
        self.assertEqual(b["pessimistic"]["misses"], 8)
        self.assertAlmostEqual(b["complete_case_point"], round(3 / 145, 4))

    def test_all_invalid_point_unestimable_band_defined(self):
        # m == n -> complete-case denominator 0, point None; band over n stays
        # defined (optimistic 0/n, pessimistic n/n).
        b = ER.compute_missingness_bounds(k=0, m=150, n=150, pool_size=698)
        self.assertFalse(b["estimable"])
        self.assertIsNone(b["complete_case_point"])
        self.assertEqual(b["optimistic"]["misses"], 0)
        self.assertEqual(b["pessimistic"]["misses"], 150)


class TestFormatJudgeProgress(unittest.TestCase):
    def test_invalid_judgment_prints_INVALID_not_clean(self):
        # MEDIUM: a parse/API-error judgment (leaked=False, valid=False) must
        # not be shown as "clean".
        judgment = {"leaked": False, "valid": False, "confidence": "low",
                    "evidence": "parse_error: no JSON object", "leak_type": "none"}
        line = ER.format_judge_progress(0, 5, _trace(tid="a"), judgment)
        self.assertIn("INVALID", line)
        self.assertIn("parse_error", line)
        self.assertNotIn("clean", line)

    def test_valid_clean_judgment(self):
        judgment = {"leaked": False, "valid": True, "confidence": "high",
                    "evidence": "nothing", "leak_type": "none"}
        line = ER.format_judge_progress(1, 5, _trace(tid="b"), judgment)
        self.assertIn("clean", line)
        self.assertNotIn("INVALID", line)

    def test_valid_leaked_judgment(self):
        judgment = {"leaked": True, "valid": True, "confidence": "high",
                    "evidence": "secret", "leak_type": "semantic"}
        line = ER.format_judge_progress(2, 5, _trace(tid="c"), judgment)
        self.assertIn("LEAKED", line)
        self.assertIn("semantic", line)

    def test_retry_attempt_count_shown(self):
        judgment = {"leaked": False, "valid": True, "confidence": "high",
                    "evidence": "x", "leak_type": "none", "judge_attempts": 3}
        line = ER.format_judge_progress(0, 5, _trace(tid="d"), judgment)
        self.assertIn("3 attempts", line)


class TestMainStdoutJsonContract(unittest.TestCase):
    """End-to-end ``main()`` smoke tests over the non-dry-run judging path.

    Fully hermetic: the trace loader is stubbed, a fake ``openai`` module is
    injected, and both ``REPO_ROOT`` and ``OUTPUT_DIR`` are redirected to a temp
    directory so no real trace file, credential file, or judge endpoint is ever
    touched. They pin the reported-metric contract that the pure-logic tests
    cannot reach: the ``metrics_available`` flag, the scope-disclosure fields
    (``evidence_window_scope`` / ``metric_scope``), and the ``n == 0``
    (all-invalid) console wording that must read ``unavailable`` /
    ``unestimable``, never a spurious 0%/100%.
    """

    def _run_main(self, scripted_contents, extra_argv=None):
        import contextlib
        import io
        import tempfile

        candidates = [
            _candidate(model="m", mech="file_to_file", tid="a"),
            _candidate(model="m", mech="file_to_file", tid="b"),
        ]

        class _FakeOpenAIModule:
            OpenAI = staticmethod(lambda **kw: _SeqClient(scripted_contents))

        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            argv = ["estimate_recall.py", "--sample-size", "50",
                    "--judge-api-key", "x", "--judge-api-base", "http://unused"]
            argv += extra_argv or []
            buf = io.StringIO()
            with mock.patch.object(ER, "load_agent_traces",
                                   return_value=list(candidates)), \
                 mock.patch.object(ER, "OUTPUT_DIR", tmp), \
                 mock.patch.object(ER, "REPO_ROOT", tmp), \
                 mock.patch.dict(sys.modules, {"openai": _FakeOpenAIModule()}), \
                 mock.patch.object(sys, "argv", argv), \
                 contextlib.redirect_stdout(buf):
                ER.main()
            # Per-run output filename: never the old fixed recall_estimation.json.
            written = list(tmp.glob("recall_estimation_*.json"))
            self.assertEqual(len(written), 1,
                             f"expected exactly one per-run artifact, got {written}")
            out = json.loads(written[0].read_text(encoding="utf-8"))
        return out, buf.getvalue()

    def test_all_valid_reports_available_metrics(self):
        out, stdout = self._run_main([VALID_JSON])
        self.assertTrue(out["metrics_available"])
        self.assertEqual(out["valid_judgments"], 2)
        self.assertIsNotNone(out["detector_clean_miss_prevalence_optimistic"])
        # Behavioral naming only: recall / FNR must not resurface at top level.
        self.assertNotIn("recall", out)
        self.assertNotIn("false_negative_rate", out)
        self.assertEqual(out["estimand"], "pooled_detector_clean_miss_prevalence")
        # Scope-disclosure fields must always ride along with the numbers.
        self.assertIn("evidence_window_scope", out)
        self.assertIn("metric_scope", out)
        self.assertIn("NOT recall", out["metric_scope"])
        self.assertEqual(out["evidence_truncation_chars"],
                         ER.EVENT_ARG_TRUNCATION_CHARS)
        self.assertIn("untruncated", out["evidence_window_scope"])
        # Headline prevalence is estimable, so the console must show a
        # percentage, not the n==0 "unavailable" fallback.
        self.assertIn("Detector-clean miss prevalence", stdout)
        self.assertNotIn("all judgments invalid", stdout)

    def test_all_invalid_reports_unavailable_not_zero(self):
        # HIGH contract: every judgment invalid -> n == 0 valid. Point must be
        # null in JSON and "unavailable" in stdout, never 0.0%/100.0%.
        out, stdout = self._run_main([INVALID_JSON])
        self.assertFalse(out["metrics_available"])
        self.assertEqual(out["valid_judgments"], 0)
        self.assertEqual(out["invalid_judgments"], 2)
        self.assertIsNone(out["detector_clean_miss_prevalence_complete_case"])
        # Scope fields are still present even with no estimable metric.
        self.assertIn("evidence_window_scope", out)
        self.assertIn("metric_scope", out)
        # The complete-case point must read "unavailable", never a spurious
        # 0.0% / 100.0% from dividing by an empty denominator.
        self.assertIn("unavailable", stdout)
        self.assertIn("unestimable", stdout)

    def test_invalid_judgment_prints_INVALID_progress_line(self):
        _, stdout = self._run_main([INVALID_JSON])
        # Per-trace progress must flag invalid judgments, not print "clean".
        self.assertIn("INVALID", stdout)

    def test_top_level_output_shape_report_mode(self):
        # End-to-end shape guard for the diagnostic/audit top-level fields that
        # the pure-logic tests exercise only in isolation.
        out, _ = self._run_main([VALID_JSON])
        # truncation_strata: both strata present, each with the miss-prevalence
        # estimator shape from compute_pooled_miss_prevalence.
        strata = out["truncation_strata"]
        self.assertEqual(set(strata), {"truncated", "non_truncated"})
        for s in strata.values():
            self.assertEqual(
                set(s),
                {"n", "misses", "detector_clean_miss_prevalence",
                 "detector_clean_miss_prevalence_ci95", "ci95_method"},
            )
        # census_*: complete run (full pool drawn, all valid).
        self.assertIs(out["census_complete"], True)
        self.assertEqual(out["census_status"], "complete")
        self.assertIsInstance(out["census_note"], str)
        # missingness bounds: m == 0 here -> degenerate band.
        self.assertTrue(out["detector_clean_miss_prevalence_bounds"]
                        ["bounds_are_degenerate"])
        # retry_*: report mode collapses the retry audit to zero/empty.
        self.assertEqual(out["retry_policy"], "report")
        self.assertEqual(out["max_retries"], 0)
        self.assertEqual(out["retry_attempts_total"], 0)
        self.assertEqual(out["retried_sample_keys"], [])
        self.assertEqual(out["remaining_invalid_after_retry"], 0)
        # provenance ID lists are composite sample keys, not bare trace_ids:
        # the three list fields carry the *_sample_keys contract and the old
        # *_trace_ids key names must be gone from the paid-path output.
        for key in ("retried_sample_keys", "invalid_judgment_sample_keys",
                    "low_confidence_miss_sample_keys"):
            self.assertIn(key, out)
            self.assertIsInstance(out[key], list)
        for old in ("retried_trace_ids", "invalid_judgment_trace_ids",
                    "low_confidence_miss_trace_ids"):
            self.assertNotIn(old, out)
        # provenance: SRS frame identity must be recorded per run.
        self.assertIn("sampling_frame_hash", out)
        # Default committed seed (echoed for provenance).
        self.assertEqual(out["seed"], 20260729)
        # judge provenance: provider/base_url + echoed model ids + token usage
        # recorded, API key never.
        prov = out["judge_provenance"]
        self.assertIn("judge_api_base", prov)
        self.assertIn("judge_provider", prov)
        self.assertIn("api_echoed_model_ids", prov)
        self.assertNotIn("api_key", prov)
        self.assertIn("token_usage", prov)
        for key in ("prompt_tokens", "completion_tokens", "total_tokens",
                    "judge_calls"):
            self.assertIn(key, prov["token_usage"])
        # cross-judge summary slot reserved (filled by an offline post-hoc pass).
        self.assertIn("cross_judge_summary", out)
        self.assertIsNone(out["cross_judge_summary"])

    def test_retry_mode_populates_retry_audit(self):
        # One trace invalid-then-valid under retry: the retry audit must record
        # the extra call and the recovered denominator, and stdout must show it.
        out, stdout = self._run_main(
            [INVALID_JSON, VALID_JSON],
            extra_argv=["--on-invalid", "retry", "--max-retries", "2"],
        )
        self.assertEqual(out["retry_policy"], "retry")
        self.assertEqual(out["max_retries"], 2)
        self.assertGreaterEqual(out["retry_attempts_total"], 1)
        # Retried IDs are the collision-free composite key of the retried
        # candidate (tid="a"), not the bare trace_id.
        self.assertIn(
            ER._stable_pool_key(_candidate(model="m", mech="file_to_file", tid="a")),
            out["retried_sample_keys"],
        )
        self.assertEqual(out["remaining_invalid_after_retry"], 0)
        self.assertIn("Retry policy: retry", stdout)


if __name__ == "__main__":
    unittest.main()
