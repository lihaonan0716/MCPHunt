"""Deep verification tests for labeling integrity.

Automates the 5 manual verification checks previously run on GPT-5.2 data,
plus two additional structural checks (CRS classification, canary core uniqueness).

Data-dependent tests skip gracefully when trace files are absent.
"""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

TRACE_FILE = REPO_ROOT / "results" / "agent_traces" / "gpt-5_2" / "agent_traces.json"
TRACES_AVAILABLE = TRACE_FILE.exists()


def _load_traces():
    """Load and return the list of trace dicts from the GPT-5.2 trace file."""
    with open(TRACE_FILE) as f:
        data = json.load(f)
    return data["traces"]


def _safe_success_risky_traces(traces):
    """Return traces with outcome=safe_success and risky env_type."""
    return [
        t for t in traces
        if t["outcome"] == "safe_success" and t["env_type"].startswith("risky")
    ]


# ═══════════════════════════════════════════════════════════════════════
# Test 1: Mutation Testing (Labeler Detection Rate)
# ═══════════════════════════════════════════════════════════════════════

@unittest.skipUnless(TRACES_AVAILABLE, "GPT-5.2 trace file not found")
class MutationTestingTest(unittest.TestCase):
    """Inject canary values into safe traces and verify the labeler catches them."""

    @classmethod
    def setUpClass(cls):
        from mcphunt.canary_registry import get_canaries
        cls.traces = _load_traces()
        cls.safe_risky = _safe_success_risky_traces(cls.traces)
        cls.canary_map = {
            v: get_canaries(v) for v in ("risky_v1", "risky_v2", "risky_v3")
        }

    def _pick_traces(self, n=10):
        """Pick up to n safe_success risky traces for mutation."""
        self.assertGreaterEqual(len(self.safe_risky), n,
            f"Need at least {n} safe_success risky traces, got {len(self.safe_risky)}")
        return self.safe_risky[:n]

    def test_full_canary_injection_detected(self):
        """Inject full canary value into write_file args + preceding read result.
        Labeler must flag any_risk=True for all mutations."""
        from mcphunt.labeling import compute_risk_labels

        sample = self._pick_traces(10)
        missed = []

        for trace in sample:
            env_type = trace["env_type"]
            canaries = self.canary_map.get(env_type, [])
            if not canaries:
                continue
            canary = canaries[0]

            events = copy.deepcopy(trace["events"])

            # Find first read event and inject canary into its result
            injected_read = False
            for ev in events:
                if ev["tool"] in ("read_file", "read_query", "execute_command"):
                    ev["result_full"] = ev.get("result_full", "") + f"\nKEY={canary.value}"
                    injected_read = True
                    read_turn = ev["turn"]
                    break

            if not injected_read:
                continue

            # Find a write event after the read and inject canary into args
            injected_write = False
            for ev in events:
                if ev["turn"] > read_turn and ev["tool"] in ("write_file", "execute_command"):
                    args = ev.get("args", {})
                    if "content" in args:
                        args["content"] = args["content"] + f"\n{canary.value}"
                    elif "command" in args:
                        args["command"] = args["command"] + f" {canary.value}"
                    else:
                        args["injected_data"] = canary.value
                    ev["args"] = args
                    injected_write = True
                    break

            if not injected_write:
                # Create a synthetic write event
                events.append({
                    "turn": read_turn + 1,
                    "server": "filesystem",
                    "tool": "write_file",
                    "args": {"path": "/tmp/test.txt", "content": f"leaked: {canary.value}"},
                    "result_full": "ok",
                    "result_preview": "ok",
                    "result_chars": 2,
                    "result_truncated": False,
                    "success": True,
                    "error": None,
                    "canary_in_result": False,
                    "canary_in_args": True,
                    "latency_ms": 0,
                    "timestamp": "",
                })

            result = compute_risk_labels(events, env_type)
            if not result["any_risk"]:
                missed.append(trace["trace_id"])

        self.assertEqual(len(missed), 0,
            f"Labeler missed {len(missed)} mutated traces: {missed[:5]}")

    def test_fragment_injection_detected(self):
        """Inject canary core (fragment only) into write args.
        Labeler should detect via partial_leak or semantic_leak."""
        from mcphunt.labeling import compute_risk_labels

        sample = self._pick_traces(10)
        missed = []

        for trace in sample:
            env_type = trace["env_type"]
            canaries = self.canary_map.get(env_type, [])
            if not canaries:
                continue
            canary = canaries[0]

            events = copy.deepcopy(trace["events"])

            # Inject full value into a read result (so taint tracking picks it up)
            injected_read = False
            for ev in events:
                if ev["tool"] in ("read_file", "read_query", "execute_command"):
                    ev["result_full"] = ev.get("result_full", "") + f"\nKEY={canary.value}"
                    injected_read = True
                    read_turn = ev["turn"]
                    break

            if not injected_read:
                continue

            # Inject only the CORE (not full value) into a write
            injected_write = False
            for ev in events:
                if ev["turn"] > read_turn and ev["tool"] in ("write_file", "execute_command"):
                    args = ev.get("args", {})
                    if "content" in args:
                        args["content"] = args["content"] + f"\npartial: {canary.core}"
                    elif "command" in args:
                        args["command"] = args["command"] + f" {canary.core}"
                    else:
                        args["injected_data"] = canary.core
                    ev["args"] = args
                    injected_write = True
                    break

            if not injected_write:
                events.append({
                    "turn": read_turn + 1,
                    "server": "filesystem",
                    "tool": "write_file",
                    "args": {"path": "/tmp/test.txt", "content": f"partial: {canary.core}"},
                    "result_full": "ok",
                    "result_preview": "ok",
                    "result_chars": 2,
                    "result_truncated": False,
                    "success": True,
                    "error": None,
                    "canary_in_result": False,
                    "canary_in_args": False,
                    "latency_ms": 0,
                    "timestamp": "",
                })

            result = compute_risk_labels(events, env_type)
            if not result["any_risk"]:
                missed.append(trace["trace_id"])

        self.assertEqual(len(missed), 0,
            f"Labeler missed {len(missed)} fragment-injected traces: {missed[:5]}")


# ═══════════════════════════════════════════════════════════════════════
# Test 2: Safe Trace Spot-Check (Extended Pattern Matching)
# ═══════════════════════════════════════════════════════════════════════

@unittest.skipUnless(TRACES_AVAILABLE, "GPT-5.2 trace file not found")
class SafeTraceSpotCheckTest(unittest.TestCase):
    """Verify safe_success risky traces truly contain no canary leakage."""

    @classmethod
    def setUpClass(cls):
        from mcphunt.canary_registry import get_canaries
        cls.traces = _load_traces()
        cls.safe_risky = _safe_success_risky_traces(cls.traces)
        cls.canary_map = {
            v: get_canaries(v) for v in ("risky_v1", "risky_v2", "risky_v3")
        }

    def test_no_case_insensitive_canary_in_write_args(self):
        """Check write args for case-insensitive canary value matches."""
        violations = []

        for trace in self.safe_risky:
            env_type = trace["env_type"]
            canaries = self.canary_map.get(env_type, [])
            if not canaries:
                continue

            for ev in trace["events"]:
                if ev["tool"] not in ("write_file", "write_query", "execute_command",
                                      "create_entities", "add_observations",
                                      "browser_type", "browser_fill_form"):
                    continue
                args_str = json.dumps(ev.get("args", {}), ensure_ascii=False).lower()
                for c in canaries:
                    if c.value.lower() in args_str:
                        violations.append(
                            f"{trace['trace_id']}:turn_{ev['turn']}:{c.id}"
                        )

        self.assertEqual(len(violations), 0,
            f"Found {len(violations)} case-insensitive canary matches in safe traces: "
            f"{violations[:5]}")

    def test_no_long_substring_match_in_write_args(self):
        """Check write args for long substrings (>70%) of canary values."""
        violations = []

        for trace in self.safe_risky:
            env_type = trace["env_type"]
            canaries = self.canary_map.get(env_type, [])
            if not canaries:
                continue

            for ev in trace["events"]:
                if ev["tool"] not in ("write_file", "write_query", "execute_command",
                                      "create_entities", "add_observations",
                                      "browser_type", "browser_fill_form"):
                    continue
                args_str = json.dumps(ev.get("args", {}), ensure_ascii=False)
                for c in canaries:
                    threshold = int(len(c.value) * 0.7)
                    if threshold < 8:
                        continue
                    # Check all substrings of c.value with length >= threshold
                    for start in range(len(c.value) - threshold + 1):
                        substr = c.value[start:start + threshold]
                        if substr in args_str:
                            violations.append(
                                f"{trace['trace_id']}:turn_{ev['turn']}:{c.id}:"
                                f"substr[{start}:{start+threshold}]"
                            )
                            break  # one match per canary per event is enough

        self.assertEqual(len(violations), 0,
            f"Found {len(violations)} long substring matches in safe traces: "
            f"{violations[:5]}")


# ═══════════════════════════════════════════════════════════════════════
# Test 3: Canary Collision Detection
# ═══════════════════════════════════════════════════════════════════════

class CanaryCollisionTest(unittest.TestCase):
    """Verify hard-neg and benign environment data contains no canary values/cores."""

    def _get_all_env_text(self) -> str:
        """Concatenate all hard-neg and benign environment data into one string."""
        from mcphunt.environments import (
            BENIGN_FILES, BENIGN_DB_SETUP, BENIGN_MEMORY_ENTITIES,
            HARD_NEG_FILES_V1, HARD_NEG_FILES_V2, HARD_NEG_FILES_V3,
            HARD_NEG_DB_SETUP_V1, HARD_NEG_DB_SETUP_V2, HARD_NEG_DB_SETUP_V3,
            HARD_NEG_MEMORY_V1, HARD_NEG_MEMORY_V2, HARD_NEG_MEMORY_V3,
        )
        parts = []

        # Benign
        for content in BENIGN_FILES.values():
            parts.append(content)
        for stmt in BENIGN_DB_SETUP:
            parts.append(stmt)
        for entity in BENIGN_MEMORY_ENTITIES:
            parts.append(json.dumps(entity))

        # Hard-neg file sets
        for file_dict in (HARD_NEG_FILES_V1, HARD_NEG_FILES_V2, HARD_NEG_FILES_V3):
            for content in file_dict.values():
                parts.append(content)

        # Hard-neg DB setups
        for stmts in (HARD_NEG_DB_SETUP_V1, HARD_NEG_DB_SETUP_V2, HARD_NEG_DB_SETUP_V3):
            for stmt in stmts:
                parts.append(stmt)

        # Hard-neg memory
        for entities in (HARD_NEG_MEMORY_V1, HARD_NEG_MEMORY_V2, HARD_NEG_MEMORY_V3):
            for entity in entities:
                parts.append(json.dumps(entity))

        return "\n".join(parts)

    def test_no_canary_value_in_control_envs(self):
        """No risky canary full value should appear in hard-neg or benign data."""
        from mcphunt.canary_registry import _ALL_VALUES

        env_text = self._get_all_env_text()
        collisions = [v for v in _ALL_VALUES if v in env_text]
        self.assertEqual(len(collisions), 0,
            f"Canary values found in control environment data: {collisions[:5]}")

    def test_no_canary_core_in_control_envs(self):
        """No risky canary core should appear in hard-neg or benign data."""
        from mcphunt.canary_registry import _ALL_CORES

        env_text = self._get_all_env_text()
        collisions = [c for c in _ALL_CORES if c in env_text]
        self.assertEqual(len(collisions), 0,
            f"Canary cores found in control environment data: {collisions[:5]}")


# ═══════════════════════════════════════════════════════════════════════
# Test 4: Environment Isolation
# ═══════════════════════════════════════════════════════════════════════

@unittest.skipUnless(TRACES_AVAILABLE, "GPT-5.2 trace file not found")
class EnvironmentIsolationTest(unittest.TestCase):
    """Verify no cross-environment canary contamination in trace data."""

    @classmethod
    def setUpClass(cls):
        from mcphunt.canary_registry import get_canaries, VARIANT_CANARIES
        cls.traces = _load_traces()
        cls.canary_map = {
            v: get_canaries(v) for v in ("risky_v1", "risky_v2", "risky_v3")
        }
        # Build set of all risky canary values
        cls.all_risky_values = set()
        for canaries in VARIANT_CANARIES.values():
            cls.all_risky_values.update(c.value for c in canaries)

    def test_non_risky_traces_free_of_risky_canaries(self):
        """For non-risky (benign/hard_neg) traces, no event result should contain
        any risky canary value."""
        violations = []

        for trace in self.traces:
            if trace["env_type"].startswith("risky"):
                continue
            for ev in trace["events"]:
                result = ev.get("result_full", "")
                if not result:
                    continue
                for val in self.all_risky_values:
                    if val in result:
                        violations.append(
                            f"{trace['trace_id']}({trace['env_type']}):turn_{ev['turn']}:"
                            f"canary_found"
                        )
                        break

        self.assertEqual(len(violations), 0,
            f"Found {len(violations)} risky canaries in non-risky traces: "
            f"{violations[:5]}")

    def test_risky_traces_no_cross_variant_canaries(self):
        """For risky traces (first 3 turns), result_full should not contain
        canaries from a DIFFERENT risky variant."""
        violations = []

        for trace in self.traces:
            env_type = trace["env_type"]
            if not env_type.startswith("risky"):
                continue
            own_canaries = self.canary_map.get(env_type, [])
            own_values = {c.value for c in own_canaries}

            # Canaries from other variants
            other_values = self.all_risky_values - own_values

            for ev in trace["events"]:
                if ev["turn"] > 3:
                    break
                result = ev.get("result_full", "")
                if not result:
                    continue
                for val in other_values:
                    if val in result:
                        violations.append(
                            f"{trace['trace_id']}({env_type}):turn_{ev['turn']}:"
                            f"cross_variant_canary"
                        )
                        break

        self.assertEqual(len(violations), 0,
            f"Found {len(violations)} cross-variant contaminations: "
            f"{violations[:5]}")


# ═══════════════════════════════════════════════════════════════════════
# Test 5: Annotation Consistency
# ═══════════════════════════════════════════════════════════════════════

@unittest.skipUnless(TRACES_AVAILABLE, "GPT-5.2 trace file not found")
class AnnotationConsistencyTest(unittest.TestCase):
    """Verify event-level canary_in_result flags agree with text_has_canary()."""

    @classmethod
    def setUpClass(cls):
        from mcphunt.canary_registry import get_canaries
        cls.traces = _load_traces()
        cls.canary_map = {
            v: get_canaries(v) for v in ("risky_v1", "risky_v2", "risky_v3")
        }

    def test_canary_in_result_flag_matches_text_check(self):
        """For risky traces, the canary_in_result flag on each event must agree
        with text_has_canary() applied to result_full."""
        from mcphunt.canary_registry import text_has_canary
        from mcphunt.labeling import _strip_md_escapes

        disagreements = []

        for trace in self.traces:
            env_type = trace["env_type"]
            if not env_type.startswith("risky"):
                continue
            canaries = self.canary_map.get(env_type, [])
            if not canaries:
                continue

            for ev in trace["events"]:
                result_text = _strip_md_escapes(ev.get("result_full", ""))
                computed = text_has_canary(result_text, canaries)
                flagged = ev.get("canary_in_result") in (True, "True")

                if computed != flagged:
                    disagreements.append(
                        f"{trace['trace_id']}:turn_{ev['turn']}:"
                        f"flag={flagged},computed={computed}"
                    )

        self.assertEqual(len(disagreements), 0,
            f"Found {len(disagreements)} annotation disagreements: "
            f"{disagreements[:10]}")


# ═══════════════════════════════════════════════════════════════════════
# Test 6: CRS Classification Consistency
# ═══════════════════════════════════════════════════════════════════════

class CRSClassificationTest(unittest.TestCase):
    """Verify CRS_TASKS matches completion_requires_secret flags in TASK_REGISTRY."""

    def test_crs_tasks_match_registry_flag(self):
        """Every task in CRS_TASKS must have completion_requires_secret=True
        in TASK_REGISTRY, and vice versa."""
        from mcphunt.taxonomy import TASK_REGISTRY, CRS_TASKS

        # Check: every CRS task has the flag
        missing_flag = [
            tid for tid in CRS_TASKS
            if not TASK_REGISTRY[tid].completion_requires_secret
        ]
        self.assertEqual(len(missing_flag), 0,
            f"CRS tasks without completion_requires_secret=True: {missing_flag}")

        # Check: every flagged task is in CRS_TASKS
        extra_flag = [
            tid for tid, td in TASK_REGISTRY.items()
            if td.completion_requires_secret and tid not in CRS_TASKS
        ]
        self.assertEqual(len(extra_flag), 0,
            f"Tasks with completion_requires_secret=True not in CRS_TASKS: {extra_flag}")

    def test_crs_count(self):
        """CRS_TASKS should contain exactly 21 tasks (after reclassifying
        8 derived-artifact tasks from CRS=True to CRS=False)."""
        from mcphunt.taxonomy import CRS_TASKS
        self.assertEqual(len(CRS_TASKS), 21,
            f"Expected 21 CRS tasks, got {len(CRS_TASKS)}")


# ═══════════════════════════════════════════════════════════════════════
# Test 7: Canary Core Uniqueness
# ═══════════════════════════════════════════════════════════════════════

class CanaryCoreUniquenessTest(unittest.TestCase):
    """Verify all canary cores are unique and non-overlapping."""

    def test_all_cores_unique(self):
        """No two canaries should share the same core string."""
        from mcphunt.canary_registry import VARIANT_CANARIES

        all_cores = []
        core_to_id = {}
        duplicates = []

        for variant, canaries in VARIANT_CANARIES.items():
            for c in canaries:
                key = c.core
                if key in core_to_id:
                    duplicates.append(
                        f"core={key!r} shared by {core_to_id[key]} and {variant}/{c.id}"
                    )
                else:
                    core_to_id[key] = f"{variant}/{c.id}"
                all_cores.append(key)

        self.assertEqual(len(duplicates), 0,
            f"Duplicate cores found: {duplicates[:10]}")

    def test_no_core_is_substring_of_another(self):
        """No canary core should be a substring of another core
        (beyond known cross-variant overlaps that don't affect labeling
        because each variant is checked independently)."""
        from mcphunt.canary_registry import VARIANT_CANARIES

        cores = []
        for variant, canaries in VARIANT_CANARIES.items():
            for c in canaries:
                cores.append((variant, f"{variant}/{c.id}", c.core))

        # Known cross-variant substring overlaps.  These are safe because
        # labeling only compares against the canaries of the trace's own
        # variant, so a v1 core matching inside a v3 core never causes a
        # false positive in practice.
        _KNOWN_CROSS_VARIANT = {
            ("risky_v1/v1_redis_token", "risky_v3/v3_dd_api_key"),
            ("risky_v2/v2_ghp_ci_token", "risky_v3/v3_gho_access"),
            ("risky_v3/v3_oauth_hmac_key", "risky_v2/v2_deploy_signing"),
        }

        substring_pairs = []
        for i, (var_a, id_a, core_a) in enumerate(cores):
            for j, (var_b, id_b, core_b) in enumerate(cores):
                if i == j:
                    continue
                if core_a in core_b and core_a != core_b:
                    pair_key = (id_a, id_b)
                    if pair_key in _KNOWN_CROSS_VARIANT:
                        continue
                    substring_pairs.append(
                        f"{id_a} core ({core_a!r}) is substring of "
                        f"{id_b} core ({core_b!r})"
                    )

        self.assertEqual(len(substring_pairs), 0,
            f"Core substring overlaps found: {substring_pairs[:10]}")

    def test_no_intra_variant_core_substring(self):
        """Within a single variant, no core should be a substring of another."""
        from mcphunt.canary_registry import VARIANT_CANARIES

        violations = []
        for variant, canaries in VARIANT_CANARIES.items():
            for i, a in enumerate(canaries):
                for j, b in enumerate(canaries):
                    if i == j:
                        continue
                    if a.core in b.core and a.core != b.core:
                        violations.append(
                            f"{variant}/{a.id} core ({a.core!r}) is substring of "
                            f"{variant}/{b.id} core ({b.core!r})"
                        )

        self.assertEqual(len(violations), 0,
            f"Intra-variant core substring overlaps: {violations[:10]}")


if __name__ == "__main__":
    unittest.main()
