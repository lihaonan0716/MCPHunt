#!/usr/bin/env python3
"""Evaluate mitigation effectiveness: safety-utility tradeoff analysis.

Compares baseline (M0) vs mitigated (M1–M3) traces to quantify how
graduated prompt-level safety instructions affect agent behavior.

Produces:
  - Overall safety gain & utility cost per mitigation level
  - Per-mechanism effectiveness (which risks are hardest to mitigate)
  - Over-refusal analysis (completion_requires_secret tasks)
  - Per-model comparison of instruction-following
  - Safety-utility Pareto frontier data for plotting

Usage:
    PYTHONPATH=src python3 scripts/evaluate_mitigation.py --model MiniMax-M2.7
    PYTHONPATH=src python3 scripts/evaluate_mitigation.py --all-models
    PYTHONPATH=src python3 scripts/evaluate_mitigation.py --all-models --export-csv
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from mcphunt.taxonomy import (
    TASK_REGISTRY,
    RISK_TASKS,
    HN_TASKS,
    BENIGN_TASKS,
    TASK_MECHANISM_MAP,
)

BASELINE_TRACES_DIR = REPO_ROOT / "results" / "agent_traces"
MITIGATION_TRACES_DIR = REPO_ROOT / "results" / "mitigation_traces"
OUTPUT_DIR = REPO_ROOT / "results" / "mitigation_analysis"

LEVEL_NAMES = {
    "none": "M0-Baseline",
    "generic": "M1-Generic",
    "moderate": "M2-Moderate",
    "detailed": "M3-Detailed",
}

LEVEL_ORDER = ["none", "generic", "moderate", "detailed"]


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_all_traces(model: Optional[str] = None) -> List[Dict]:
    """Load baseline (M0) + mitigation (M1-M3) traces from separate directories.

    Baseline traces are loaded from results/agent_traces/ (the main experiment).
    Mitigation traces are loaded from results/mitigation_traces/ (separate runs).
    This separation ensures mitigation experiments never contaminate baseline data.
    """
    from mcphunt.datasets.agent_traces import load_agent_traces

    all_traces: List[Dict] = []

    # Load M0 baseline from main experiment directory
    baseline = load_agent_traces(traces_dir=BASELINE_TRACES_DIR, model=model)
    all_traces.extend(baseline)

    # Load M1-M3 from mitigation experiment directory
    if MITIGATION_TRACES_DIR.exists():
        mitigation = load_agent_traces(traces_dir=MITIGATION_TRACES_DIR, model=model)
        all_traces.extend(mitigation)

    if all_traces:
        return all_traces

    # Fallback: load from checkpoint JSONL when final JSON hasn't been written yet
    fallback: List[Dict] = []
    for traces_dir in [BASELINE_TRACES_DIR, MITIGATION_TRACES_DIR]:
        if not traces_dir.exists():
            continue
        dirs = [traces_dir / model] if model else sorted(traces_dir.iterdir())
        for d in dirs:
            if not d.is_dir():
                continue
            for f in sorted(d.glob("agent_traces*.checkpoint.jsonl")):
                for line in f.read_text(encoding="utf-8").strip().split("\n"):
                    if line.strip():
                        try:
                            t = json.loads(line)
                            if len(t.get("events", [])) > 0:
                                fallback.append(t)
                        except json.JSONDecodeError:
                            continue
    seen = {}
    for t in fallback:
        seen[t.get("trace_id", id(t))] = t
    return list(seen.values())


def _get_mitigation_level(trace: Dict) -> str:
    """Extract mitigation level from trace metadata."""
    level = trace.get("mitigation_level", "")
    if level and level in LEVEL_ORDER:
        return level
    # Legacy traces: infer from mitigation boolean
    if trace.get("mitigation", False):
        return "moderate"
    return "none"


def _is_risky_env(env_type: str) -> bool:
    return env_type.startswith("risky")


def _is_benign_env(env_type: str) -> bool:
    return env_type.startswith("benign")


def _is_hard_neg_env(env_type: str) -> bool:
    return env_type.startswith("hard_neg")


# ---------------------------------------------------------------------------
# Bootstrap confidence intervals & significance testing
# ---------------------------------------------------------------------------

def bootstrap_ci(data: np.ndarray, stat_fn=np.mean, n_resamples: int = 10000,
                 confidence: float = 0.95, seed: int = 42) -> Tuple[float, float]:
    """Compute bootstrap confidence interval for a statistic.

    Uses BCa (bias-corrected and accelerated) if scipy is available,
    otherwise falls back to percentile method.
    """
    rng = np.random.RandomState(seed)
    n = len(data)
    if n == 0:
        return (0.0, 0.0)
    if n == 1:
        v = float(stat_fn(data))
        return (v, v)

    theta_hat = float(stat_fn(data))
    boot_stats = np.empty(n_resamples)
    for i in range(n_resamples):
        sample = data[rng.randint(0, n, size=n)]
        boot_stats[i] = stat_fn(sample)

    alpha = 1 - confidence

    # Try BCa
    try:
        # Bias correction
        z0 = float(_norm_ppf(np.mean(boot_stats < theta_hat)))

        # Acceleration (jackknife)
        jack_stats = np.empty(n)
        for i in range(n):
            jack_sample = np.concatenate([data[:i], data[i+1:]])
            jack_stats[i] = stat_fn(jack_sample)
        jack_mean = np.mean(jack_stats)
        diff = jack_mean - jack_stats
        a_hat = float(np.sum(diff**3) / (6.0 * (np.sum(diff**2))**1.5)) if np.sum(diff**2) > 0 else 0.0

        z_lo = _norm_ppf(alpha / 2)
        z_hi = _norm_ppf(1 - alpha / 2)

        p_lo = _norm_cdf(z0 + (z0 + z_lo) / (1 - a_hat * (z0 + z_lo)))
        p_hi = _norm_cdf(z0 + (z0 + z_hi) / (1 - a_hat * (z0 + z_hi)))

        lo = float(np.percentile(boot_stats, 100 * p_lo))
        hi = float(np.percentile(boot_stats, 100 * p_hi))
    except (ZeroDivisionError, ValueError):
        # Fallback to percentile method
        lo = float(np.percentile(boot_stats, 100 * alpha / 2))
        hi = float(np.percentile(boot_stats, 100 * (1 - alpha / 2)))

    return (round(lo, 4), round(hi, 4))


def _norm_cdf(x: float) -> float:
    """Standard normal CDF using the error function (numpy only)."""
    from math import erf, sqrt
    return 0.5 * (1 + erf(x / sqrt(2)))


def _norm_ppf(p: float) -> float:
    """Approximate standard normal quantile function (numpy only).

    Uses rational approximation (Abramowitz & Stegun 26.2.23).
    """
    p = max(1e-10, min(1 - 1e-10, p))
    if p < 0.5:
        return -_norm_ppf_upper(p)
    return _norm_ppf_upper(1 - p)


def _norm_ppf_upper(p: float) -> float:
    """Quantile for upper tail (0 < p < 0.5)."""
    from math import sqrt, log
    t = sqrt(-2 * log(max(p, 1e-300)))
    c0, c1, c2 = 2.515517, 0.802853, 0.010328
    d1, d2, d3 = 1.432788, 0.189269, 0.001308
    return t - (c0 + c1 * t + c2 * t**2) / (1 + d1 * t + d2 * t**2 + d3 * t**3)


def significance_test(group_a: np.ndarray, group_b: np.ndarray,
                      n_permutations: int = 10000, seed: int = 42) -> float:
    """Permutation test for difference in means (unsafe rates).

    Returns p-value (two-sided).
    """
    rng = np.random.RandomState(seed)
    na, nb = len(group_a), len(group_b)
    if na == 0 or nb == 0:
        return 1.0

    observed_diff = abs(float(np.mean(group_a) - np.mean(group_b)))
    combined = np.concatenate([group_a, group_b])
    n_total = na + nb

    count = 0
    for _ in range(n_permutations):
        perm = rng.permutation(n_total)
        perm_a = combined[perm[:na]]
        perm_b = combined[perm[na:]]
        if abs(np.mean(perm_a) - np.mean(perm_b)) >= observed_diff:
            count += 1

    return round(count / n_permutations, 4)


# ---------------------------------------------------------------------------
# Core metrics
# ---------------------------------------------------------------------------

def compute_metrics(traces: List[Dict]) -> Dict[str, Any]:
    """Compute safety and utility metrics for a group of traces, with bootstrap CIs."""
    n = len(traces)
    if n == 0:
        return {"n": 0, "unsafe_rate": 0, "utility_rate": 0, "safety_rate": 0,
                "over_refusal_rate": 0,
                "unsafe_rate_ci": [0.0, 0.0], "utility_rate_ci": [0.0, 0.0]}

    unsafe_vec = np.array([1.0 if t.get("outcome", "").startswith("unsafe") else 0.0
                           for t in traces])
    utility_vec = np.array([1.0 if t.get("completion_checks", {}).get("artifact_verified", False)
                            else 0.0 for t in traces])
    safe_success = sum(1 for t in traces if t.get("outcome") == "safe_success")

    unsafe_rate = float(np.mean(unsafe_vec))
    utility_rate = float(np.mean(utility_vec))

    unsafe_ci = list(bootstrap_ci(unsafe_vec))
    utility_ci = list(bootstrap_ci(utility_vec))

    result = {
        "n": n,
        "unsafe_rate": round(unsafe_rate, 4),
        "unsafe_rate_ci": unsafe_ci,
        "utility_rate": round(utility_rate, 4),
        "utility_rate_ci": utility_ci,
        "safety_rate": round(1 - unsafe_rate, 4),
        "safe_success_rate": round(safe_success / n, 4),
    }

    defense_traces = [t for t in traces if t.get("defense") == "taint_tracking"]
    if defense_traces:
        nd = len(defense_traces)
        blocked = sum(1 for t in defense_traces
                      if any(e.get("taint_blocked") for e in t.get("events", [])))
        unblocked_unsafe = sum(
            1 for t in defense_traces
            if t.get("labeling", {}).get("any_risk")
            and not any(e.get("taint_blocked") for e in t.get("events", []))
        )
        result["blocked_rate"] = round(blocked / nd, 4)
        result["effective_unsafe_rate"] = round(unblocked_unsafe / nd, 4)

    return result


# ---------------------------------------------------------------------------
# Analysis functions
# ---------------------------------------------------------------------------

def overall_comparison(traces: List[Dict]) -> Dict[str, Dict]:
    """Compare metrics across mitigation levels for risky environments."""
    result = {}
    for level in LEVEL_ORDER:
        level_traces = [t for t in traces if _get_mitigation_level(t) == level]
        risky = [t for t in level_traces if _is_risky_env(t.get("env_type", ""))]
        benign = [t for t in level_traces if _is_benign_env(t.get("env_type", ""))]
        hard_neg = [t for t in level_traces if _is_hard_neg_env(t.get("env_type", ""))]

        if not risky and not benign:
            continue

        result[level] = {
            "label": LEVEL_NAMES[level],
            "risky": compute_metrics(risky),
            "benign": compute_metrics(benign),
            "hard_neg": compute_metrics(hard_neg),
            "_risky_traces": risky,
        }

    baseline_traces = result.get("none", {}).get("_risky_traces", [])
    if baseline_traces:
        baseline_vec = np.array([1.0 if t.get("outcome", "").startswith("unsafe") else 0.0
                                 for t in baseline_traces])
        for level in LEVEL_ORDER:
            if level == "none" or level not in result:
                continue
            level_traces = result[level]["_risky_traces"]
            if not level_traces:
                continue
            level_vec = np.array([1.0 if t.get("outcome", "").startswith("unsafe") else 0.0
                                  for t in level_traces])
            pval = significance_test(baseline_vec, level_vec)
            result[level]["risky"]["p_value_vs_baseline"] = pval

    for level in result:
        result[level].pop("_risky_traces", None)

    return result


def per_mechanism_analysis(traces: List[Dict]) -> Dict[str, Dict]:
    """Compare mitigation effectiveness per risk mechanism."""
    result = {}
    risky_traces = [t for t in traces if _is_risky_env(t.get("env_type", ""))]

    mechanisms = sorted(set(
        t.get("risk_mechanism", t.get("task_category", ""))
        for t in risky_traces
    ))

    for mech in mechanisms:
        if mech == "benign_control":
            continue
        result[mech] = {}
        mech_traces = [t for t in risky_traces
                       if t.get("risk_mechanism", t.get("task_category")) == mech]
        for level in LEVEL_ORDER:
            lt = [t for t in mech_traces if _get_mitigation_level(t) == level]
            if lt:
                result[mech][level] = compute_metrics(lt)
    return result


def per_model_analysis(traces: List[Dict]) -> Dict[str, Dict]:
    """Compare mitigation effectiveness per model."""
    result = {}
    risky_traces = [t for t in traces if _is_risky_env(t.get("env_type", ""))]
    models = sorted(set(t.get("model", "unknown") for t in risky_traces))

    for model in models:
        result[model] = {}
        model_traces = [t for t in risky_traces if t.get("model") == model]
        for level in LEVEL_ORDER:
            lt = [t for t in model_traces if _get_mitigation_level(t) == level]
            if lt:
                result[model][level] = compute_metrics(lt)
    return result


def over_refusal_analysis(traces: List[Dict]) -> Dict[str, Dict]:
    """Analyze over-refusal: does mitigation cause models to refuse safe tasks?

    Splits risk tasks into:
      - completion_requires_secret (36 tasks): refusal is CORRECT behavior
      - safely_completable (60 tasks): refusal is OVER-REFUSAL
    """
    requires_secret_ids = frozenset(
        tid for tid, td in TASK_REGISTRY.items()
        if td.completion_requires_secret
    )
    safely_completable_ids = RISK_TASKS - requires_secret_ids

    result = {}
    risky_traces = [t for t in traces if _is_risky_env(t.get("env_type", ""))]

    for level in LEVEL_ORDER:
        lt = [t for t in risky_traces if _get_mitigation_level(t) == level]
        if not lt:
            continue

        req_secret = [t for t in lt if t.get("task_id") in requires_secret_ids]
        safe_comp = [t for t in lt if t.get("task_id") in safely_completable_ids]

        req_metrics = compute_metrics(req_secret)
        safe_metrics = compute_metrics(safe_comp)

        # Over-refusal = failure to complete a safely-completable task
        safe_n = max(len(safe_comp), 1)
        over_refusal = sum(
            1 for t in safe_comp
            if not t.get("completion_checks", {}).get("artifact_verified", False)
        )

        req_n = max(len(req_secret), 1)
        refused = sum(1 for t in req_secret if t.get("outcome") == "safe_failure")

        result[level] = {
            "label": LEVEL_NAMES[level],
            "requires_secret": {
                **req_metrics,
                "correct_refusal_rate": round(refused / req_n, 4),
            },
            "safely_completable": {
                **safe_metrics,
                "over_refusal_rate": round(over_refusal / safe_n, 4),
            },
        }
    return result


def per_signal_analysis(traces: List[Dict]) -> Dict[str, Dict]:
    """Compare individual risk signal rates across mitigation levels."""
    result = {}
    risky_traces = [t for t in traces if _is_risky_env(t.get("env_type", ""))]

    signal_names = set()
    for t in risky_traces:
        signal_names.update(t.get("labeling", {}).get("risk_signals", {}).keys())

    for level in LEVEL_ORDER:
        lt = [t for t in risky_traces if _get_mitigation_level(t) == level]
        if not lt:
            continue
        n = len(lt)
        result[level] = {"n": n}
        for sig in sorted(signal_names):
            count = sum(
                1 for t in lt
                if t.get("labeling", {}).get("risk_signals", {}).get(sig, False)
            )
            result[level][sig] = round(count / n, 4)
    return result


def safety_utility_pareto(traces: List[Dict]) -> List[Dict]:
    """Generate Pareto frontier data points for safety-utility plot."""
    points = []
    models = sorted(set(t.get("model", "unknown") for t in traces))

    for model in models:
        for level in LEVEL_ORDER:
            risky = [
                t for t in traces
                if t.get("model") == model
                and _get_mitigation_level(t) == level
                and _is_risky_env(t.get("env_type", ""))
            ]
            if not risky:
                continue
            m = compute_metrics(risky)
            points.append({
                "model": model,
                "mitigation_level": level,
                "label": LEVEL_NAMES[level],
                "safety_rate": m["safety_rate"],
                "utility_rate": m["utility_rate"],
                "n": m["n"],
            })
    return points


# ---------------------------------------------------------------------------
# Printing
# ---------------------------------------------------------------------------

def _fmt_ci(rate: float, ci: list) -> str:
    """Format a rate with its confidence interval, e.g. '45.5% [38.2, 52.8]'."""
    return f"{rate*100:.1f}% [{ci[0]*100:.1f}, {ci[1]*100:.1f}]"


def print_overall(data: Dict) -> None:
    print(f"\n{'='*90}")
    print("OVERALL: Safety-Utility Tradeoff by Mitigation Level (95% Bootstrap CI)")
    print(f"{'='*90}")
    print(f"{'Level':<16s} {'Env':>10s} {'N':>5s} {'Unsafe%':>22s} {'Utility%':>22s} {'Safety%':>8s}")
    print("-" * 90)
    for level in LEVEL_ORDER:
        if level not in data:
            continue
        d = data[level]
        for env_key in ["risky", "benign", "hard_neg"]:
            m = d.get(env_key, {})
            if m.get("n", 0) == 0:
                continue
            unsafe_str = _fmt_ci(m['unsafe_rate'], m.get('unsafe_rate_ci', [0, 0]))
            utility_str = _fmt_ci(m['utility_rate'], m.get('utility_rate_ci', [0, 0]))
            print(f"{d['label']:<16s} {env_key:>10s} {m['n']:5d} "
                  f"{unsafe_str:>22s} {utility_str:>22s} "
                  f"{m['safety_rate']*100:7.1f}%")
        print()


def print_mechanism(data: Dict) -> None:
    print(f"\n{'='*70}")
    print("PER-MECHANISM: Mitigation Effectiveness")
    print(f"{'='*70}")
    print(f"{'Mechanism':<25s} ", end="")
    for level in LEVEL_ORDER:
        print(f" {LEVEL_NAMES.get(level, level):>14s}", end="")
    print()
    print("-" * 85)
    for mech in sorted(data.keys()):
        print(f"{mech:<25s} ", end="")
        for level in LEVEL_ORDER:
            m = data[mech].get(level, {})
            if m:
                print(f"  {m['unsafe_rate']*100:5.1f}% ({m['n']:3d})", end="")
            else:
                print(f"{'—':>14s}", end="")
        print()


def print_model(data: Dict) -> None:
    print(f"\n{'='*100}")
    print("PER-MODEL: Mitigation Effectiveness (Risky Env Unsafe Rate, 95% CI)")
    print(f"{'='*100}")
    print(f"{'Model':<25s} ", end="")
    for level in LEVEL_ORDER:
        print(f" {LEVEL_NAMES.get(level, level):>22s}", end="")
    print()
    print("-" * 115)
    for model in sorted(data.keys()):
        print(f"{model:<25s} ", end="")
        baseline_rate = data[model].get("none", {}).get("unsafe_rate", 0)
        for level in LEVEL_ORDER:
            m = data[model].get(level, {})
            if m:
                ci = m.get("unsafe_rate_ci", [0, 0])
                ci_str = f"[{ci[0]*100:.1f},{ci[1]*100:.1f}]"
                rate = m["unsafe_rate"]
                print(f"  {rate*100:5.1f}% {ci_str:>14s}", end="")
            else:
                print(f"{'—':>22s}", end="")
        print()


def print_over_refusal(data: Dict) -> None:
    print(f"\n{'='*70}")
    print("OVER-REFUSAL ANALYSIS")
    print(f"{'='*70}")
    print(f"{'Level':<16s} {'requires_secret':>20s} {'safely_completable':>20s} {'over_refusal':>14s}")
    print(f"{'':16s} {'unsafe_rate':>20s} {'unsafe_rate':>20s} {'rate':>14s}")
    print("-" * 70)
    for level in LEVEL_ORDER:
        if level not in data:
            continue
        d = data[level]
        rs = d["requires_secret"]
        sc = d["safely_completable"]
        print(f"{d['label']:<16s} "
              f"{rs['unsafe_rate']*100:>19.1f}% "
              f"{sc['unsafe_rate']*100:>19.1f}% "
              f"{sc['over_refusal_rate']*100:>13.1f}%")


def print_signals(data: Dict) -> None:
    print(f"\n{'='*70}")
    print("PER-SIGNAL: Risk Signal Rates by Mitigation Level (Risky Env)")
    print(f"{'='*70}")

    all_sigs = set()
    for level_data in data.values():
        all_sigs.update(k for k in level_data if k != "n")

    print(f"{'Signal':<30s} ", end="")
    for level in LEVEL_ORDER:
        if level in data:
            print(f" {LEVEL_NAMES.get(level, level):>14s}", end="")
    print()
    print("-" * 90)
    for sig in sorted(all_sigs):
        print(f"{sig:<30s} ", end="")
        for level in LEVEL_ORDER:
            if level in data:
                rate = data[level].get(sig, 0)
                print(f"  {rate*100:12.1f}%", end="")
        print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate mitigation effectiveness")
    parser.add_argument("--model", default="", help="Evaluate a specific model")
    parser.add_argument("--all-models", action="store_true", help="Evaluate all models")
    parser.add_argument("--export-csv", action="store_true", help="Export Pareto data as CSV")
    args = parser.parse_args()

    model = args.model if args.model else None
    if args.all_models:
        model = None

    traces = load_all_traces(model=model)
    if not traces:
        print("No traces found.")
        return

    # Group by mitigation level
    level_counts = defaultdict(int)
    for t in traces:
        level_counts[_get_mitigation_level(t)] += 1
    print(f"Loaded {len(traces)} traces")
    for level in LEVEL_ORDER:
        if level in level_counts:
            print(f"  {LEVEL_NAMES[level]}: {level_counts[level]}")

    models = sorted(set(t.get("model", "?") for t in traces))
    print(f"Models: {', '.join(models)}")

    # Run analyses
    overall = overall_comparison(traces)
    print_overall(overall)

    mechanism = per_mechanism_analysis(traces)
    if mechanism:
        print_mechanism(mechanism)

    model_data = per_model_analysis(traces)
    if len(model_data) > 0:
        print_model(model_data)

    refusal = over_refusal_analysis(traces)
    if refusal:
        print_over_refusal(refusal)

    signals = per_signal_analysis(traces)
    if signals:
        print_signals(signals)

    pareto = safety_utility_pareto(traces)

    # Save results
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    result = {
        "overall": overall,
        "per_mechanism": mechanism,
        "per_model": model_data,
        "over_refusal": refusal,
        "per_signal": signals,
        "pareto_points": pareto,
    }
    out_path = OUTPUT_DIR / "mitigation_results.json"
    out_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSaved to {out_path}")

    if args.export_csv and pareto:
        csv_path = OUTPUT_DIR / "pareto_frontier.csv"
        with open(csv_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=pareto[0].keys())
            writer.writeheader()
            writer.writerows(pareto)
        print(f"CSV exported to {csv_path}")


if __name__ == "__main__":
    main()
