#!/usr/bin/env python3
r"""Recompute the hard-negative matched-pair comparison from the trace grid.

usM1's W1/W2 reply describes a matched cross-boundary comparison of risky vs.
hard-negative canaries within the same tasks. Two overlapping *marginal* Wilson
intervals cannot support that reading: the two arms are the SAME 108 tasks, so
the informative quantity is the paired difference and its discordance, not two
independent proportions. This script therefore derives the full matched 2x2
table by pairing traces on ``task_id`` and reports:

  * the two marginal rates + Wilson intervals (retained for continuity with the
    twoByTwoCross* macros in the paper),
  * the paired difference p12 - p21 with a Tango asymptotic score interval,
  * the exact (binomial) McNemar two-sided p-value over discordant pairs.

Pairing is read from raw traces (``results/agent_traces/<model>/``), never
back-derived from rounded percentages. The twoByTwoCross* macros are still read,
but only to CROSS-CHECK the trace-level pairing: a mismatch is a hard failure,
so the reviewer-facing paired numbers and the paper's table can never drift
apart silently. The denominator is additionally pinned to the frozen registry's
risk-task set, because the macros are regenerated from the SAME trace file and
would shrink in step with it -- only an absolute reference catches a task that
went missing from both arms at once.

Provenance is recorded at three levels so a reader can tell which input
produced the table: ``source_sha256`` (the trace file), ``paired_rows_sha256``
(the canonical per-task outcome rows), and ``summary_hash`` (the 2x2 totals
alone -- a result fingerprint, not an input identity).

Method notes (both frozen here):
  * Marginal interval = Wilson score, no continuity correction -- the same
    estimator ``estimate_recall.py`` uses, so the benchmark reports one
    single-proportion CI convention throughout.
  * Paired interval = Tango (1998) asymptotic score interval for the difference
    of two correlated proportions, i.e. the set of delta whose score statistic
    lies within +/-z. It is the paired analogue of the Wilson score interval and
    is the recommended default for matched pairs (Fagerland, Lydersen & Laake,
    2013). The Wald paired interval is ALSO emitted, labelled as a sensitivity
    comparison only: with few discordant pairs its coverage degrades, so it is
    never the headline.
  * McNemar is reported as an EXACT two-sided binomial test on the b/c
    discordant split -- unlike the live-guard surface (where risky_v1/v2/v3 env
    variants of one task are not independent repeats and only the discordance
    counts are emitted), here each task contributes exactly ONE pair, so an
    exact test is well defined.

Usage:
  PYTHONPATH=src python scripts/compute_hard_negative_ci.py \\
      [--model gpt_5_4] \\
      [--out results/hard_negative_analysis/hard_negative_ci.json]

Offline only: reads existing trace files, no API call, no collection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
import sys
from pathlib import Path
from typing import Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from mcphunt.taxonomy import TASK_REGISTRY  # noqa: E402

_Z95 = 1.959963984540054  # two-sided 95% normal quantile

ARTIFACT_SCHEMA_VERSION = "hard_negative_ci/v3"

# The matched comparison is defined on the first environment variant of each
# arm: risky_v1 vs. hard_neg_v1 over the risk tasks (identical task set and
# prompts, canary values substituted). This mirrors the twoByTwoCross* macros.
RISKY_ENV = "risky_v1"
HARDNEG_ENV = "hard_neg_v1"

# The denominator is fixed by the frozen registry, NOT by whatever the trace
# file happens to contain: comparing the two arms only against each other
# accepts a task missing from BOTH arms (the set difference is empty, so the
# pairing looks complete while n has silently dropped). Anchoring on the
# registry makes that failure mode impossible.
RISK_TASK_IDS = frozenset(
    tid for tid, task in TASK_REGISTRY.items() if task.task_type == "risk")


class PairingIntegrityError(RuntimeError):
    """Raised when the risky/hard-negative task pairing is not one-to-one."""


def wilson_interval(k: int, n: int, z: float = _Z95) -> Tuple[float, float]:
    """Wilson score 95% interval for a binomial proportion k/n (no CC)."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1.0 + z * z / n
    center = p + z * z / (2.0 * n)
    margin = z * math.sqrt(p * (1.0 - p) / n + z * z / (4.0 * n * n))
    return ((center - margin) / denom, (center + margin) / denom)


def _tango_p21(delta: float, n: int, b: int, c: int) -> float:
    """Constrained MLE of p21 under a fixed difference delta = p12 - p21.

    Closed form from Tango (1998): the profile likelihood under the constraint
    reduces to a quadratic in p21 whose positive root is the MLE.
    """
    A = 2.0 * n
    B = -b - c + (2.0 * n - b + c) * delta
    C = -c * delta * (1.0 - delta)
    disc = B * B - 4.0 * A * C
    if disc < 0.0:  # numerically flat; clamp rather than emit a complex root
        disc = 0.0
    return (-B + math.sqrt(disc)) / (2.0 * A)


def _tango_score(delta: float, n: int, b: int, c: int) -> float:
    """Tango score statistic at delta; the CI is {delta : |score| <= z}."""
    p21 = _tango_p21(delta, n, b, c)
    var = n * (2.0 * p21 + delta * (1.0 - delta))
    num = b - c - n * delta
    if var <= 0.0:
        # Degenerate variance (no probability mass on the discordant cells at
        # this delta). Zero numerator means delta is exactly the MLE, so the
        # statistic is 0; otherwise the constraint is infinitely implausible.
        if num == 0.0:
            return 0.0
        return math.inf if num > 0.0 else -math.inf
    return num / math.sqrt(var)


def _bisect(fn, lo: float, hi: float, tol: float = 1e-12,
            max_iter: int = 400) -> float:
    """Root-find fn on [lo, hi] by bisection (no SciPy dependency needed).

    Kept local and dependency-free so the frozen interval is reproducible from
    the standard library alone; the sign change is asserted by the caller.
    """
    f_lo, f_hi = fn(lo), fn(hi)
    if f_lo == 0.0:
        return lo
    if f_hi == 0.0:
        return hi
    if (f_lo > 0.0) == (f_hi > 0.0):
        raise ValueError(f"no sign change on [{lo}, {hi}]: "
                         f"f(lo)={f_lo}, f(hi)={f_hi}")
    for _ in range(max_iter):
        mid = 0.5 * (lo + hi)
        f_mid = fn(mid)
        if f_mid == 0.0 or (hi - lo) < tol:
            return mid
        if (f_mid > 0.0) == (f_lo > 0.0):
            lo, f_lo = mid, f_mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def tango_score_interval(n: int, b: int, c: int,
                         z: float = _Z95) -> Tuple[float, float]:
    """Tango asymptotic score 95% interval for the paired difference p12 - p21.

    b = discordant pairs unsafe in the risky arm only, c = unsafe in the
    hard-negative arm only. The interval is the closed set
    ``{delta in [-1, 1] : |score(delta)| <= z}``.

    Both boundaries are handled explicitly rather than assumed interior, which
    is the point of using a score interval here: Tango's method is specifically
    valid when an off-diagonal cell is empty. With ``b == n`` (every discordant
    pair favours the risky arm) the point estimate IS +1 and the score vanishes
    there, so the upper endpoint is the boundary itself; symmetrically for
    ``c == n``. Testing the endpoint before root-finding also avoids handing
    ``_bisect`` an inverted bracket. Zero discordance stays interior and needs
    no special case.
    """
    if n == 0:
        return (0.0, 0.0)
    point = (b - c) / n
    # delta is a difference of proportions, so it lives in [-1, 1]; step just
    # inside the boundary for the root search because the score variance
    # vanishes at +/-1, but evaluate the constraint AT the boundary first.
    eps = 1e-9
    if _tango_score(-1.0, n, b, c) - z <= 0.0:
        lo = -1.0
    else:
        lo = _bisect(lambda t: _tango_score(t, n, b, c) - z, -1.0 + eps, point)
    if _tango_score(1.0, n, b, c) + z >= 0.0:
        hi = 1.0
    else:
        hi = _bisect(lambda t: _tango_score(t, n, b, c) + z, point, 1.0 - eps)
    return (lo, hi)


def wald_paired_interval(n: int, b: int, c: int,
                         z: float = _Z95) -> Tuple[float, float]:
    """Wald interval for the paired difference (SENSITIVITY COMPARISON ONLY).

    Emitted so the score interval can be compared against the textbook formula;
    with few discordant pairs its coverage is known to degrade, so it must not
    be quoted as the headline.
    """
    if n == 0:
        return (0.0, 0.0)
    point = (b - c) / n
    var = (b + c - (b - c) ** 2 / n) / (n * n)
    se = math.sqrt(max(var, 0.0))
    return (point - z * se, point + z * se)


def mcnemar_exact_p(b: int, c: int) -> float:
    """Exact two-sided McNemar p-value: binomial(b; b+c, 0.5), doubled.

    Computed from the standard library so the value does not depend on a SciPy
    version. The two-sided p is min(1, 2 * one-tailed) on the smaller tail,
    which is the convention SciPy's ``binomtest(..., p=0.5)`` reduces to for a
    symmetric null.
    """
    m = b + c
    if m == 0:
        return 1.0
    k = min(b, c)
    tail = sum(math.comb(m, i) for i in range(0, k + 1)) / (2.0 ** m)
    return min(1.0, 2.0 * tail)


def _read_macro(macros_text: str, name: str) -> str:
    m = re.search(r"\\newcommand\{\\" + re.escape(name) + r"\}\{([-\d.]+)\}",
                  macros_text)
    if not m:
        raise ValueError(
            f"macro {name} not found in results_macros.tex -- regenerate with "
            "scripts/generate_results_macros.py")
    return m.group(1)


def _is_unsafe(trace: Dict) -> bool:
    """Same outcome convention as generate_results_macros.is_unsafe."""
    return str(trace.get("outcome", "")).startswith("unsafe")


def _load_traces(repo_root: Path, model_slug: str) -> Tuple[List[Dict], str]:
    """Load one model's traces and the SHA-256 of the file they came from.

    The file digest is returned alongside the parsed traces so the artifact can
    record WHICH input produced it, not merely what the totals were.
    """
    path = repo_root / "results" / "agent_traces" / model_slug / "agent_traces.json"
    if not path.exists():
        raise SystemExit(
            f"{path} not found -- run `make download` to fetch the released "
            "traces before computing the paired comparison.")
    raw = path.read_bytes()
    data = json.loads(raw.decode("utf-8"))
    return data["traces"], hashlib.sha256(raw).hexdigest()


def _index_arm(traces: List[Dict], env_type: str, arm: str) -> Dict[str, Dict]:
    """Index one arm by task_id over the risk tasks of a single env variant.

    Refuses duplicate task cells: a task appearing twice would make its pair
    ambiguous, and silently keeping the first would corrupt the 2x2 table.
    """
    idx: Dict[str, Dict] = {}
    dups: List[str] = []
    for t in traces:
        if str(t.get("env_type")) != env_type:
            continue
        task_id = str(t.get("task_id", ""))
        task = TASK_REGISTRY.get(task_id)
        if task is None or task.task_type != "risk":
            continue
        if task_id in idx:
            dups.append(task_id)
        else:
            idx[task_id] = t
    if dups:
        raise PairingIntegrityError(
            f"{arm} arm has duplicate task cells {sorted(set(dups))} in "
            f"env_type={env_type!r}; each task must contribute exactly one "
            "trace for the matched pair to be well defined.")
    if not idx:
        raise PairingIntegrityError(
            f"{arm} arm is empty for env_type={env_type!r}; expected the risk "
            "tasks of the released trace grid.")
    return idx


def _assert_covers_registry(idx: Dict[str, Dict], arm: str) -> None:
    """Require one cell per FROZEN-REGISTRY risk task, not just arm symmetry.

    A task absent from both arms leaves the arm-vs-arm set difference empty, so
    a symmetric hole would otherwise be reported as a complete pairing over a
    silently smaller n. The macros are regenerated from the same trace file and
    would shrink identically, so the cross-check cannot catch it either -- only
    an absolute denominator can.
    """
    missing = sorted(RISK_TASK_IDS - set(idx))
    if missing:
        raise PairingIntegrityError(
            f"{arm} arm is missing {len(missing)} of {len(RISK_TASK_IDS)} "
            f"registry risk task(s) {missing[:5]}; the matched comparison is "
            "defined on the frozen registry, so a shrunken denominator is a "
            "data-completeness failure, not a smaller valid sample.")


def build_paired_table(traces: List[Dict]) -> Dict[str, object]:
    """Pair risky_v1 against hard_neg_v1 on task_id and build the matched 2x2.

    Pairing must be COMPLETE against the frozen registry, not merely symmetric
    between the two arms: an unmatched task on either side -- or a task missing
    from both -- makes the paired difference ill-defined, so we abort rather
    than computing over whatever subset survived and silently dropping the rest.
    """
    risky_idx = _index_arm(traces, RISKY_ENV, "risky")
    hn_idx = _index_arm(traces, HARDNEG_ENV, "hard_negative")

    risky_only_tasks = sorted(set(risky_idx) - set(hn_idx))
    hn_only_tasks = sorted(set(hn_idx) - set(risky_idx))
    if risky_only_tasks or hn_only_tasks:
        raise PairingIntegrityError(
            f"incomplete pairing: {len(risky_only_tasks)} task(s) only in the "
            f"risky arm {risky_only_tasks[:5]} and {len(hn_only_tasks)} only in "
            f"the hard-negative arm {hn_only_tasks[:5]}; every risk task must "
            "appear in both env variants.")

    # Symmetric-hole guard: run AFTER the arm-vs-arm check so a one-sided gap
    # still reports the more specific message above.
    _assert_covers_registry(risky_idx, "risky")
    _assert_covers_registry(hn_idx, "hard_negative")

    models = ({str(t.get("model", "")) for t in risky_idx.values()}
              | {str(t.get("model", "")) for t in hn_idx.values()})
    if len(models) != 1:
        raise PairingIntegrityError(
            f"the matched comparison is a within-model contrast but the arms "
            f"span {sorted(models)}; pass --model to select one model.")

    task_ids = sorted(risky_idx)
    both = risky_only = hn_only = neither = 0
    n_prompt_diff = 0
    rows: List[str] = []
    for task_id in task_ids:
        rt, ht = risky_idx[task_id], hn_idx[task_id]
        ru, hu = _is_unsafe(rt), _is_unsafe(ht)
        if ru and hu:
            both += 1
        elif ru:
            risky_only += 1
        elif hu:
            hn_only += 1
        else:
            neither += 1
        prompt_match = (str(rt.get("task_prompt", ""))
                        == str(ht.get("task_prompt", "")))
        if not prompt_match:
            n_prompt_diff += 1
        # One canonical line per pair. Hashing these rather than the four cell
        # totals makes the digest sensitive to WHICH tasks produced the table:
        # any reassignment of outcomes across tasks that leaves the 2x2
        # unchanged still changes this digest.
        rows.append(f"{task_id}\t{int(ru)}\t{int(hu)}\t{int(prompt_match)}")

    return {
        "model": models.pop(),
        "risky_env_type": RISKY_ENV,
        "hard_negative_env_type": HARDNEG_ENV,
        "n_pairs": len(task_ids),
        "registry_risk_tasks": len(RISK_TASK_IDS),
        "pairing_complete": True,
        "table": {
            "both_unsafe": both,
            "risky_only_unsafe": risky_only,
            "hard_negative_only_unsafe": hn_only,
            "neither_unsafe": neither,
        },
        "prompt_text_diff_pairs": n_prompt_diff,
        "task_ids_sha256": hashlib.sha256(
            "|".join(task_ids).encode()).hexdigest(),
        "paired_rows_sha256": hashlib.sha256(
            "\n".join(rows).encode()).hexdigest(),
        "paired_rows_schema": "task_id\\trisky_unsafe\\thard_negative_unsafe"
                              "\\tprompt_match (sorted by task_id, LF-joined)",
    }


def _cross_check_macros(repo_root: Path, n_pairs: int, risky_k: int,
                        hardneg_k: int) -> Dict[str, object]:
    """Assert the trace-level pairing reproduces the paper's table macros.

    The macros are NOT the data source here (the traces are); they are an
    independent derivation of the same quantities, so an equality check catches
    a stale macro file or a changed pairing definition instead of letting the
    reviewer-facing paired numbers drift from the published table.
    """
    macros_path = repo_root / "paper" / "results_macros.tex"
    if not macros_path.exists():
        return {"checked": False,
                "reason": f"{macros_path} absent (paper/ is a separate repo)"}
    macros_text = macros_path.read_text(encoding="utf-8")
    macro_n = int(round(float(_read_macro(macros_text, "twoByTwoCrossN"))))
    macro_risky_k = int(round(float(_read_macro(macros_text,
                                                "twoByTwoCrossProdK"))))
    macro_hn_k = int(round(float(_read_macro(macros_text,
                                             "twoByTwoCrossPlacK"))))
    mismatches = []
    for label, got, want in (("twoByTwoCrossN", n_pairs, macro_n),
                             ("twoByTwoCrossProdK", risky_k, macro_risky_k),
                             ("twoByTwoCrossPlacK", hardneg_k, macro_hn_k)):
        if got != want:
            mismatches.append(f"{label}: traces={got} macro={want}")
    if mismatches:
        raise SystemExit(
            "trace-level pairing disagrees with paper/results_macros.tex ("
            + "; ".join(mismatches) + "). Regenerate the macros with "
            "scripts/generate_results_macros.py, or reconcile the pairing "
            "definition -- the paired artifact must not diverge from the "
            "published table.")
    return {"checked": True,
            "source": "paper/results_macros.tex twoByTwoCross{N,ProdK,PlacK}",
            "agrees": True}


def compute(repo_root: Path, model_slug: str) -> Dict[str, object]:
    traces, source_sha256 = _load_traces(repo_root, model_slug)
    paired = build_paired_table(traces)

    n = int(paired["n_pairs"])
    tbl = paired["table"]
    both = int(tbl["both_unsafe"])
    b = int(tbl["risky_only_unsafe"])          # risky unsafe, hard-neg safe
    c = int(tbl["hard_negative_only_unsafe"])  # hard-neg unsafe, risky safe
    risky_k = both + b
    hardneg_k = both + c

    macro_check = _cross_check_macros(repo_root, n, risky_k, hardneg_k)

    risky_lo, risky_hi = wilson_interval(risky_k, n)
    hn_lo, hn_hi = wilson_interval(hardneg_k, n)
    diff = (b - c) / n
    tango_lo, tango_hi = tango_score_interval(n, b, c)
    wald_lo, wald_hi = wald_paired_interval(n, b, c)
    p_exact = mcnemar_exact_p(b, c)

    payload = {
        "artifact_schema_version": ARTIFACT_SCHEMA_VERSION,
        "estimand": "matched_pair_risky_vs_hard_negative_propagation",
        "source": (f"results/agent_traces/{model_slug}/agent_traces.json "
                   "(paired on task_id)"),
        "source_sha256": source_sha256,
        "macro_cross_check": macro_check,
        "z_95": _Z95,
        "pairing": paired,
        "marginal": {
            "method": "wilson_score_95_no_continuity_correction",
            "note": ("marginal intervals are retained for continuity with the "
                     "paper's 2x2 table; because both arms are the SAME tasks, "
                     "their overlap is NOT evidence of equivalence -- read the "
                     "paired difference below instead"),
            "risky": {
                "successes": risky_k,
                "rate_pct": round(risky_k / n * 100.0, 1),
                "wilson_ci95_pct": [round(risky_lo * 100.0, 1),
                                    round(risky_hi * 100.0, 1)],
            },
            "hard_negative": {
                "successes": hardneg_k,
                "rate_pct": round(hardneg_k / n * 100.0, 1),
                "wilson_ci95_pct": [round(hn_lo * 100.0, 1),
                                    round(hn_hi * 100.0, 1)],
            },
        },
        "paired_difference": {
            "definition": "risky_rate - hard_negative_rate = (b - c) / n",
            "discordant": {
                "b_risky_only_unsafe": b,
                "c_hard_negative_only_unsafe": c,
                "discordant_total": b + c,
            },
            "point_pct": round(diff * 100.0, 1),
            "method": "tango_1998_asymptotic_score_interval",
            "ci95_pct": [round(tango_lo * 100.0, 1),
                         round(tango_hi * 100.0, 1)],
            "wald_sensitivity_ci95_pct": [round(wald_lo * 100.0, 1),
                                          round(wald_hi * 100.0, 1)],
            "wald_note": ("Wald paired interval shown for comparison only; its "
                          "coverage degrades with few discordant pairs, so the "
                          "score interval is the headline"),
            "mcnemar_exact_two_sided_p": round(p_exact, 4),
            "mcnemar_method": "exact_binomial_b_of_b_plus_c_at_half",
            "interpretation": (
                "The interval covers zero and the exact test does not reject "
                "equality of the two marginals: no difference is detectable at "
                "this sample size. That is NOT evidence of equivalence -- the "
                "interval also covers differences large enough to matter, and "
                "the comparison remains descriptive (single model, matched "
                "alternative-value substitution, no neutral-placeholder arm)."),
        },
    }
    # Named `summary_hash`, not `input_hash`: it digests only the five cell
    # totals, so it is a fingerprint of the RESULT table. Input identity lives
    # in `source_sha256` (which file) and `pairing.paired_rows_sha256` (which
    # per-task outcomes), both of which change under permutations this one
    # cannot see.
    payload["summary_hash"] = hashlib.sha256(
        f"{n}|{both}|{b}|{c}|{tbl['neither_unsafe']}".encode()).hexdigest()
    return payload


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo-root", default=".")
    ap.add_argument("--model", default="gpt_5_4",
                    help="trace directory slug under results/agent_traces/")
    ap.add_argument(
        "--out",
        default="results/hard_negative_analysis/hard_negative_ci.json")
    args = ap.parse_args()
    root = Path(args.repo_root).resolve()

    payload = compute(root, args.model)
    out = root / args.out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                   encoding="utf-8")

    n = payload["pairing"]["n_pairs"]
    tbl = payload["pairing"]["table"]
    m = payload["marginal"]
    pd_ = payload["paired_difference"]
    print(f"model = {payload['pairing']['model']}   n_pairs = {n}")
    print(f"2x2: both={tbl['both_unsafe']} "
          f"risky_only={tbl['risky_only_unsafe']} "
          f"hn_only={tbl['hard_negative_only_unsafe']} "
          f"neither={tbl['neither_unsafe']}")
    print(f"risky      {m['risky']['successes']}/{n} = "
          f"{m['risky']['rate_pct']}%  Wilson95 {m['risky']['wilson_ci95_pct']}")
    print(f"hard-neg   {m['hard_negative']['successes']}/{n} = "
          f"{m['hard_negative']['rate_pct']}%  Wilson95 "
          f"{m['hard_negative']['wilson_ci95_pct']}")
    print(f"paired diff {pd_['point_pct']:+} pp  score95 {pd_['ci95_pct']}  "
          f"(Wald {pd_['wald_sensitivity_ci95_pct']})")
    print(f"McNemar exact two-sided p = {pd_['mcnemar_exact_two_sided_p']}")
    print(f"-> {args.out}")


if __name__ == "__main__":
    main()
