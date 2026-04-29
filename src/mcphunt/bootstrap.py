"""Bootstrap confidence interval utilities for MCPHunt.

Provides BCa bootstrap CIs and a per-mechanism analysis function that
produces paper-ready statistics with confidence intervals for leak_rate,
intrinsic_leak_rate, utility_rate, and data_flow_rate.

Sampling unit is the individual trace (task × env × model).  Each
risk mechanism has 12 risk tasks × N_envs × N_models traces, giving
enough mass for meaningful CIs even with single-seed experiments.
"""
from __future__ import annotations

from math import erf, log, sqrt
from typing import Any, Callable, Dict, List, Optional, Tuple

import numpy as np

from .taxonomy import (
    RISK_MECHANISMS,
    is_crs_task as _is_crs,
)


# ─── BCa bootstrap CI ────────────────────────────────────────────

def bootstrap_ci(
    data: np.ndarray,
    stat_fn: Callable = np.mean,
    n_resamples: int = 10000,
    confidence: float = 0.95,
    seed: int = 42,
) -> Tuple[float, float]:
    """BCa bootstrap confidence interval with percentile fallback."""
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

    try:
        z0 = float(_norm_ppf(np.mean(boot_stats < theta_hat)))
        jack_stats = np.empty(n)
        for i in range(n):
            jack_sample = np.concatenate([data[:i], data[i + 1:]])
            jack_stats[i] = stat_fn(jack_sample)
        jack_mean = np.mean(jack_stats)
        diff = jack_mean - jack_stats
        sum_sq = float(np.sum(diff ** 2))
        a_hat = float(np.sum(diff ** 3) / (6.0 * sum_sq ** 1.5)) if sum_sq > 0 else 0.0

        z_lo = _norm_ppf(alpha / 2)
        z_hi = _norm_ppf(1 - alpha / 2)
        p_lo = _norm_cdf(z0 + (z0 + z_lo) / (1 - a_hat * (z0 + z_lo)))
        p_hi = _norm_cdf(z0 + (z0 + z_hi) / (1 - a_hat * (z0 + z_hi)))
        lo = float(np.percentile(boot_stats, 100 * p_lo))
        hi = float(np.percentile(boot_stats, 100 * p_hi))
    except (ZeroDivisionError, ValueError):
        lo = float(np.percentile(boot_stats, 100 * alpha / 2))
        hi = float(np.percentile(boot_stats, 100 * (1 - alpha / 2)))

    return (round(lo, 4), round(hi, 4))


def _norm_cdf(x: float) -> float:
    return 0.5 * (1 + erf(x / sqrt(2)))


def _norm_ppf(p: float) -> float:
    p = max(1e-10, min(1 - 1e-10, p))
    return -_norm_ppf_upper(p) if p < 0.5 else _norm_ppf_upper(1 - p)


def _norm_ppf_upper(p: float) -> float:
    t = sqrt(-2 * log(max(p, 1e-300)))
    c0, c1, c2 = 2.515517, 0.802853, 0.010328
    d1, d2, d3 = 1.432788, 0.189269, 0.001308
    return t - (c0 + c1 * t + c2 * t ** 2) / (1 + d1 * t + d2 * t ** 2 + d3 * t ** 3)


def fmt_ci(rate: float, ci: Tuple[float, float]) -> str:
    """Format rate and CI as '72.2% [61.1, 83.3]'."""
    return f"{rate * 100:.1f}% [{ci[0] * 100:.1f}, {ci[1] * 100:.1f}]"


# ─── Helpers ──────────────────────────────────────────────────────

def _env_match(env_type: str, env_class: str) -> bool:
    if env_class == "all":
        return True
    if env_class == "risky":
        return env_type.startswith("risky")
    if env_class == "hard_neg":
        return env_type.startswith("hard_neg")
    if env_class == "benign":
        return env_type == "benign"
    return env_type == env_class


def _extract_vectors(traces: List[Dict]) -> Dict[str, np.ndarray]:
    """Extract binary metric vectors from a list of traces."""
    n = len(traces)
    if n == 0:
        empty = np.array([], dtype=float)
        return {"leak": empty, "intrinsic": empty,
                "utility": empty, "data_flow": empty}

    leak = np.zeros(n)
    intrinsic = np.zeros(n)
    utility = np.zeros(n)
    data_flow = np.zeros(n)

    for i, t in enumerate(traces):
        lab = t.get("labeling", {})
        signals = lab.get("risk_signals", {})
        checks = t.get("completion_checks", {})
        tid = t.get("task_id", "")

        any_risk = lab.get("any_risk", False)
        crs = lab.get("completion_requires_secret", _is_crs(tid))

        leak[i] = float(any_risk)
        intrinsic[i] = float(any_risk and not crs)
        utility[i] = float(checks.get("artifact_verified", False))
        data_flow[i] = float(signals.get("data_flow", False))

    return {"leak": leak, "intrinsic": intrinsic,
            "utility": utility, "data_flow": data_flow}


def _compute_group_stats(
    traces: List[Dict],
    n_resamples: int,
    confidence: float,
    seed: int,
) -> Dict[str, Any]:
    """Compute rates + CIs for one group of traces."""
    n = len(traces)
    if n == 0:
        return {"n": 0}

    vecs = _extract_vectors(traces)
    result: Dict[str, Any] = {"n": n}

    for metric, vec in vecs.items():
        rate = float(np.mean(vec))
        ci = bootstrap_ci(vec, n_resamples=n_resamples,
                          confidence=confidence, seed=seed)
        result[f"{metric}_rate"] = round(rate, 4)
        result[f"{metric}_ci"] = list(ci)

    return result


# ─── Main analysis function ──────────────────────────────────────

def compute_mechanism_ci(
    traces: List[Dict[str, Any]],
    env_class: str = "risky",
    n_resamples: int = 10000,
    confidence: float = 0.95,
    seed: int = 42,
) -> Dict[str, Any]:
    """Per-mechanism bootstrap CI analysis for paper tables.

    Parameters
    ----------
    traces : list of trace dicts from agent trace collection.
    env_class : environment filter — "risky", "hard_neg", "benign", "all",
                or a specific env_type like "risky_v1".
    n_resamples : bootstrap iterations (10000 is standard).
    confidence : CI level (0.95 = 95%).
    seed : RNG seed for reproducibility.

    Returns
    -------
    Dict with ``aggregate``, ``per_mechanism``, and ``per_model`` entries,
    each containing rates and CIs for leak, intrinsic, utility, data_flow.
    """
    filtered = [t for t in traces if _env_match(t.get("env_type", ""), env_class)]

    result: Dict[str, Any] = {
        "env_filter": env_class,
        "confidence": confidence,
        "n_resamples": n_resamples,
        "n_total_traces": len(traces),
        "n_filtered": len(filtered),
    }

    # Aggregate
    result["aggregate"] = _compute_group_stats(
        filtered, n_resamples, confidence, seed)

    # Per mechanism
    per_mech: Dict[str, Any] = {}
    for mech in sorted(RISK_MECHANISMS):
        mt = [t for t in filtered
              if t.get("risk_mechanism", t.get("task_category", "")) == mech]
        if mt:
            per_mech[mech] = _compute_group_stats(
                mt, n_resamples, confidence, seed)
    result["per_mechanism"] = per_mech

    # Per model
    models = sorted(set(t.get("model", "unknown") for t in filtered))
    if len(models) >= 1:
        per_model: Dict[str, Any] = {}
        for model in models:
            mt = [t for t in filtered if t.get("model") == model]
            stats = _compute_group_stats(mt, n_resamples, confidence, seed)
            # Per-mechanism breakdown within this model
            model_mechs: Dict[str, Any] = {}
            for mech in sorted(RISK_MECHANISMS):
                mmt = [t for t in mt
                       if t.get("risk_mechanism", t.get("task_category", "")) == mech]
                if mmt:
                    model_mechs[mech] = _compute_group_stats(
                        mmt, n_resamples, confidence, seed)
            stats["per_mechanism"] = model_mechs
            per_model[model] = stats
        result["per_model"] = per_model

    return result


def print_mechanism_ci(analysis: Dict[str, Any]) -> None:
    """Pretty-print the mechanism CI analysis for terminal output."""
    conf_pct = int(analysis.get("confidence", 0.95) * 100)
    env = analysis.get("env_filter", "?")
    n = analysis.get("n_filtered", 0)

    print(f"\n{'=' * 72}")
    print(f"Per-Mechanism Bootstrap CI ({conf_pct}%, env={env}, n={n})")
    print(f"{'=' * 72}")

    # Aggregate
    agg = analysis.get("aggregate", {})
    if agg.get("n", 0) > 0:
        print(f"\n  Aggregate (n={agg['n']}):")
        for metric in ("leak", "intrinsic", "utility", "data_flow"):
            rate = agg.get(f"{metric}_rate", 0)
            ci = tuple(agg.get(f"{metric}_ci", [0, 0]))
            print(f"    {metric + '_rate':25s}: {fmt_ci(rate, ci)}")

    # Per mechanism table
    per_mech = analysis.get("per_mechanism", {})
    if per_mech:
        print(f"\n  {'Mechanism':25s} {'n':>4s}  {'Leak Rate':>22s}  "
              f"{'Intrinsic':>22s}  {'Utility':>22s}")
        print(f"  {'-' * 25} {'-' * 4}  {'-' * 22}  {'-' * 22}  {'-' * 22}")
        for mech in sorted(per_mech):
            m = per_mech[mech]
            lr = fmt_ci(m["leak_rate"], tuple(m["leak_ci"]))
            ir = fmt_ci(m["intrinsic_rate"], tuple(m["intrinsic_ci"]))
            ur = fmt_ci(m["utility_rate"], tuple(m["utility_ci"]))
            print(f"  {mech:25s} {m['n']:4d}  {lr:>22s}  {ir:>22s}  {ur:>22s}")

    # Per model summary
    per_model = analysis.get("per_model", {})
    if len(per_model) >= 2:
        print(f"\n  {'Model':30s} {'n':>4s}  {'Leak Rate':>22s}  "
              f"{'Intrinsic':>22s}  {'Utility':>22s}")
        print(f"  {'-' * 30} {'-' * 4}  {'-' * 22}  {'-' * 22}  {'-' * 22}")
        for model in sorted(per_model):
            m = per_model[model]
            lr = fmt_ci(m["leak_rate"], tuple(m["leak_ci"]))
            ir = fmt_ci(m["intrinsic_rate"], tuple(m["intrinsic_ci"]))
            ur = fmt_ci(m["utility_rate"], tuple(m["utility_ci"]))
            print(f"  {model:30s} {m['n']:4d}  {lr:>22s}  {ir:>22s}  {ur:>22s}")
