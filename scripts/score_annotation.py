"""Score the completed CRS blind-annotation sheets and report the
inter-annotator reliability statistic.

Headline statistic (the reliability number the paper reports): the
**inter-annotator agreement between the two independent annotators**. Run it on
the two filled annotation sheets:

    python scripts/score_annotation.py annotation_1.csv annotation_2.csv

It reports:

  - raw agreement (matches / n)
  - Cohen's kappa + bootstrap 95% CI (percentile, 10000 resamples, fixed seed)
  - 2x2 confusion matrix (annotator-1 x annotator-2)
  - the list of disagreements (task_id, a1 label, a2 label)

Each sheet has one row per task with a ``your_crs_label`` column
(accepts TRUE/FALSE, T/F, 1/0, yes/no, case-insensitive) and a ``task_id``
column. Both sheets must cover exactly the same task set.

Secondary diagnostic (optional): compare each annotator against the frozen
registry labels (``completion_requires_secret`` in ``taxonomy.py``) as an audit
cross-check. This is NOT the inter-annotator reliability statistic and does not
substitute for it:

    python scripts/score_annotation.py annotation_1.csv annotation_2.csv \
        --registry-check

This script is deterministic and offline. It has NO paid or live-model path. It
exists so the restored reliability statistic is reproducible from the raw labels
(per the project's provenance-before-value invariant): the filled sheets plus
this script's output are the whole audit trail.

Usage (stdlib only; the MCPHunt env is required only for --registry-check):
    python scripts/score_annotation.py <sheet_a.csv> <sheet_b.csv> [--registry-check]
"""
from __future__ import annotations

import csv
import random
import sys
from pathlib import Path

TRUE_TOKENS = {"true", "t", "1", "yes", "y", "crs"}
FALSE_TOKENS = {"false", "f", "0", "no", "n", "non-crs", "noncrs"}

BOOTSTRAP_RESAMPLES = 10_000
BOOTSTRAP_SEED = 20260728


def _parse_label(raw: str, task_id: str, where: str) -> bool:
    v = (raw or "").strip().lower()
    if v in TRUE_TOKENS:
        return True
    if v in FALSE_TOKENS:
        return False
    raise SystemExit(
        f"Unrecognized label {raw!r} for task {task_id!r} in {where}. "
        f"Use TRUE/FALSE (also accepts T/F, 1/0, yes/no)."
    )


def _cohen_kappa(a: list[bool], b: list[bool]) -> float:
    """Cohen's kappa for two binary raters over the same items."""
    n = len(a)
    if n == 0:
        return float("nan")
    agree = sum(1 for x, y in zip(a, b) if x == y)
    po = agree / n
    pa_true = sum(a) / n
    pb_true = sum(b) / n
    pe = pa_true * pb_true + (1 - pa_true) * (1 - pb_true)
    if pe == 1.0:
        return 1.0  # perfect + no variance => define as 1.0
    return (po - pe) / (1 - pe)


def _bootstrap_kappa_ci(
    a: list[bool], b: list[bool], resamples: int, seed: int
) -> tuple[float, float]:
    """Percentile 95% CI for Cohen's kappa via item resampling.

    NaN kappas (degenerate resamples with no expected-agreement variance) are
    dropped before taking percentiles; the count is not reported here but such
    resamples are rare unless the class is nearly constant.
    """
    n = len(a)
    rng = random.Random(seed)
    stats: list[float] = []
    idx = range(n)
    for _ in range(resamples):
        pick = [rng.randrange(n) for _ in idx]
        ra = [a[i] for i in pick]
        rb = [b[i] for i in pick]
        k = _cohen_kappa(ra, rb)
        if k == k:  # drop NaN
            stats.append(k)
    if not stats:
        return (float("nan"), float("nan"))
    stats.sort()
    lo = stats[int(0.025 * len(stats))]
    hi = stats[min(len(stats) - 1, int(0.975 * len(stats)))]
    return (lo, hi)


def _load_sheet(sheet_path: Path) -> dict[str, bool]:
    """Load one annotation sheet into ``task_id -> bool``.

    Insertion order follows the sheet's row order and is preserved (Python dicts
    are ordered); the headline scoring uses annotator-1's row order as the
    canonical item order so the bootstrap CI is deterministic and reproducible
    (the percentile CI depends on the index->item mapping under a fixed seed).

    Integrity checks (all fatal — a real reliability statistic is computed over
    exactly the right item set, once each): missing columns, blank task_id,
    duplicate task_id, blank label.
    """
    labels: dict[str, bool] = {}
    blank: list[str] = []
    with sheet_path.open(encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames is None or "task_id" not in reader.fieldnames:
            raise SystemExit(f"{sheet_path.name}: missing 'task_id' column.")
        if "your_crs_label" not in reader.fieldnames:
            raise SystemExit(f"{sheet_path.name}: missing 'your_crs_label' column.")
        for row in reader:
            tid = (row["task_id"] or "").strip()
            if not tid:
                raise SystemExit(f"{sheet_path.name}: blank task_id row.")
            if tid in labels or tid in blank:
                raise SystemExit(f"{sheet_path.name}: duplicate task_id {tid!r}.")
            raw = row.get("your_crs_label", "")
            if not (raw or "").strip():
                blank.append(tid)
                continue
            labels[tid] = _parse_label(raw, tid, sheet_path.name)
    if blank:
        raise SystemExit(
            f"{sheet_path.name}: {len(blank)} task(s) still unlabeled: "
            f"{blank[:10]}" + (" ..." if len(blank) > 10 else "")
        )
    if not labels:
        raise SystemExit(f"{sheet_path.name}: no rows.")
    return labels


def _registry_gold() -> dict[str, bool]:
    """Frozen registry CRS labels, for the optional secondary diagnostic.

    Imported lazily so the headline inter-annotator path stays stdlib-only and
    does not require the MCPHunt package to be importable.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
    from mcphunt.taxonomy import CRS_TASKS, TASK_REGISTRY

    return {tid: (tid in CRS_TASKS) for tid in TASK_REGISTRY}


def _report_pair(
    label: str,
    ids: list[str],
    a: dict[str, bool],
    b: dict[str, bool],
    a_name: str,
    b_name: str,
) -> None:
    a_vals = [a[t] for t in ids]
    b_vals = [b[t] for t in ids]
    n = len(ids)
    agree = sum(1 for x, y in zip(a_vals, b_vals) if x == y)
    kappa = _cohen_kappa(a_vals, b_vals)
    ci_lo, ci_hi = _bootstrap_kappa_ci(
        a_vals, b_vals, BOOTSTRAP_RESAMPLES, BOOTSTRAP_SEED
    )

    both_true = sum(1 for x, y in zip(a_vals, b_vals) if x and y)
    both_false = sum(1 for x, y in zip(a_vals, b_vals) if not x and not y)
    a_true_b_false = sum(1 for x, y in zip(a_vals, b_vals) if x and not y)
    a_false_b_true = sum(1 for x, y in zip(a_vals, b_vals) if not x and y)

    print(f"=== {label} ===")
    print(f"Items                : {n}")
    print(f"Raw agreement        : {agree}/{n} = {agree / n:.4f}")
    print(f"Cohen's kappa        : {kappa:.4f}")
    print(
        f"Bootstrap 95% CI     : [{ci_lo:.4f}, {ci_hi:.4f}] "
        f"({BOOTSTRAP_RESAMPLES} resamples, seed {BOOTSTRAP_SEED})"
    )
    print()
    print(f"Confusion (rows={a_name}, cols={b_name}):")
    print(f"                {b_name}=TRUE   {b_name}=FALSE")
    print(f"  {a_name}=TRUE  {both_true:>10} {a_true_b_false:>13}")
    print(f"  {a_name}=FALSE {a_false_b_true:>10} {both_false:>13}")
    print()

    disagreements = [
        (t, a[t], b[t]) for t in ids if a[t] != b[t]
    ]
    if disagreements:
        print(f"Disagreements ({len(disagreements)}):")
        for t, av, bv in disagreements:
            print(f"  {t:<24} {a_name}={av!s:<5} {b_name}={bv!s:<5}")
    else:
        print("No disagreements.")
    print()


def main() -> None:
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    if len(args) != 2 or (flags - {"--registry-check"}):
        raise SystemExit(
            "usage: python scripts/score_annotation.py "
            "<sheet_a.csv> <sheet_b.csv> [--registry-check]"
        )
    path_a = Path(args[0])
    path_b = Path(args[1])

    a = _load_sheet(path_a)
    b = _load_sheet(path_b)

    # Exact task-set equality between the two annotators: no missing, no extra.
    only_a = set(a) - set(b)
    only_b = set(b) - set(a)
    if only_a or only_b:
        raise SystemExit(
            "annotation sheets cover different task sets: "
            f"only in {path_a.name}: {sorted(only_a)[:10]}; "
            f"only in {path_b.name}: {sorted(only_b)[:10]}"
        )
    # Canonical item order = annotator-1's row order (see _load_sheet): keeps
    # the bootstrap CI deterministic and reproducible under the fixed seed.
    ids = list(a)

    # Headline: inter-annotator agreement between the two independent annotators.
    _report_pair(
        "INTER-ANNOTATOR (headline)", ids, a, b, "a1", "a2"
    )

    if "--registry-check" in flags:
        gold = _registry_gold()
        gold_missing = set(ids) - set(gold)
        if gold_missing:
            raise SystemExit(
                f"registry missing {len(gold_missing)} annotated task_id(s): "
                f"{sorted(gold_missing)[:10]}"
            )
        # Secondary diagnostic only — NOT the reliability statistic.
        _report_pair(
            "SECONDARY: annotator-1 vs frozen registry (audit cross-check)",
            ids, a, gold, "a1", "reg",
        )
        _report_pair(
            "SECONDARY: annotator-2 vs frozen registry (audit cross-check)",
            ids, b, gold, "a2", "reg",
        )


if __name__ == "__main__":
    main()
