"""Pin the paired live-guard collection slice for the browser_to_local mechanism.

The live-guard mini-run (docs/b3_live_guard_mini_run_plan.md) collects a
baseline vs. taint_tracking-defense arm over the SAME risky-env schedule that
evaluate_mitigation uses for its live-guard comparison population. To bill only
that population — not a ~10x superset — the collector filters to the resolved
slice via taxonomy.resolve_live_guard_slice.

These tests are the offline ground truth for that resolver: they pin the exact
cell count (39), its risk/HN split, the frozen task-id set, and the fact that
dropping the risky-env restriction would yield the larger 75-combo pool. If a
taxonomy edit silently moves the slice, the paid-run guardrail size shifts with
it, so this file must fail loudly first.

Pure-logic tests over the registry; no trace file, no paid path.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from mcphunt.taxonomy import (  # noqa: E402
    TASK_REGISTRY,
    VALID_TASK_ENV_COMBOS,
    is_risky_env,
    is_valid_combo,
    resolve_live_guard_slice,
)

MECHANISM = "browser_to_local"

# Frozen task-id set backing the mini-run schedule (taxonomy source of truth,
# see docs/b3_live_guard_mini_run_plan.md 2). 12 risk + 3 hard-negative.
EXPECTED_RISK_TASK_IDS = frozenset({
    "bw_admin_export", "bw_api_key_export", "bw_cache_settings",
    "bw_config_to_db", "bw_dashboard_report", "bw_full_audit",
    "bw_full_site_crawl", "bw_index_site", "bw_monitor_export",
    "bw_sync_dashboard", "bw_team_export", "bw_users_to_db",
})
EXPECTED_HN_TASK_IDS = frozenset({
    "hn_bl_admin", "hn_bl_dashboard", "hn_bl_team",
})

EXPECTED_SLICE_CELLS = 39   # paired live-guard population per arm
EXPECTED_PAID_CAP = 78      # 39 x 2 arms (baseline + defense)


class LiveGuardSliceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.cells = resolve_live_guard_slice(MECHANISM)

    def test_slice_cell_count_is_pinned(self) -> None:
        # The per-arm paid volume the guardrail asserts against.
        self.assertEqual(len(self.cells), EXPECTED_SLICE_CELLS)
        self.assertEqual(len(self.cells) * 2, EXPECTED_PAID_CAP)

    def test_slice_is_all_risky_and_valid(self) -> None:
        for task_id, task_type, env_type in self.cells:
            self.assertTrue(is_risky_env(env_type),
                            f"{task_id}/{env_type} not risky")
            self.assertTrue(is_valid_combo(task_id, env_type),
                            f"{task_id}/{env_type} not a valid combo")
            self.assertEqual(TASK_REGISTRY[task_id].mechanism, MECHANISM)

    def test_risk_hn_split(self) -> None:
        risk = [c for c in self.cells if c[1] == "risk"]
        hn = [c for c in self.cells if c[1] == "hard_negative"]
        self.assertEqual(len(risk), 36)  # 12 risk tasks x 3 risky envs
        self.assertEqual(len(hn), 3)      # 3 HN tasks x 1 risky env (risky_v1)

    def test_frozen_task_id_set(self) -> None:
        slice_ids = {c[0] for c in self.cells}
        self.assertEqual(slice_ids,
                         EXPECTED_RISK_TASK_IDS | EXPECTED_HN_TASK_IDS)

    def test_dropping_risky_restriction_yields_larger_pool(self) -> None:
        # Guards against the failure mode the atomic flag exists to prevent:
        # a mechanism-only filter (no risky-env restriction) bills ~75/arm,
        # NOT the A3 paired surface. This pins that the restriction matters.
        full = [
            (tid, td.task_type, e)
            for tid, td in TASK_REGISTRY.items()
            if td.mechanism == MECHANISM
            for e in VALID_TASK_ENV_COMBOS.get(td.task_type, [])
            if is_valid_combo(tid, e)
        ]
        self.assertEqual(len(full), 75)
        self.assertGreater(len(full), len(self.cells))

    def test_resolver_is_deterministic(self) -> None:
        self.assertEqual(resolve_live_guard_slice(MECHANISM), self.cells)

    def test_unknown_mechanism_is_empty(self) -> None:
        self.assertEqual(resolve_live_guard_slice("no_such_mechanism"), [])


if __name__ == "__main__":
    unittest.main()
