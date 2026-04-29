"""Dataset loading and splitting logic for agent traces."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, Optional

import pandas as pd

from .agent_traces import AGENT_DATASET, build_agent_rows, load_agent_traces


def _sorted_frame(frame: pd.DataFrame) -> pd.DataFrame:
    return frame.sort_values(["group_id", "record_id"]).reset_index(drop=True)


def _stable_hash(value: str) -> int:
    return int(hashlib.sha256(value.encode()).hexdigest()[:8], 16)


def load_records(
    traces_dir: Optional[Path] = None,
) -> pd.DataFrame:
    traces = load_agent_traces(traces_dir=traces_dir)
    if not traces:
        raise ValueError("No agent traces found. Run collect_agent_traces.py first.")
    rows = build_agent_rows(traces)
    frame = pd.DataFrame(rows)
    if frame.empty:
        raise ValueError("No records loaded.")
    return _sorted_frame(frame)


def build_splits(
    records: pd.DataFrame,
    seed: int = 0,
    calibration_fraction: float = 0.15,
    validation_fraction: float = 0.35,
) -> Dict[str, pd.DataFrame]:
    """Split records into calibration / validation / test by group_id.

    The split is deterministic given the seed.  Groups are hashed so the
    assignment is stable across dataset size changes.
    """
    working = records.copy()
    if working.empty:
        raise ValueError("Empty dataset for split.")

    groups = working[["group_id"]].drop_duplicates().copy()
    groups["order_key"] = groups["group_id"].map(
        lambda gid: _stable_hash(f"{seed}:{gid}")
    )
    groups = groups.sort_values(["order_key", "group_id"]).reset_index(drop=True)

    n = len(groups)
    n_cal = max(1, int(round(n * calibration_fraction)))
    n_val = max(1, int(round(n * validation_fraction)))
    n_test = max(1, n - n_cal - n_val)
    if n_cal + n_val + n_test > n:
        n_val = max(1, n_val - 1)

    cal = set(groups.iloc[:n_cal]["group_id"])
    val = set(groups.iloc[n_cal : n_cal + n_val]["group_id"])
    test_set = set(groups.iloc[n_cal + n_val :]["group_id"])

    working["split"] = working["group_id"].map(
        lambda gid: "calibration" if gid in cal else "validation" if gid in val else "test"
    )
    return {
        "validation": _sorted_frame(working.loc[working["split"] == "validation"]),
        "calibration": _sorted_frame(working.loc[working["split"] == "calibration"]),
        "test": _sorted_frame(working.loc[working["split"] == "test"]),
        "pooled": _sorted_frame(working),
    }
