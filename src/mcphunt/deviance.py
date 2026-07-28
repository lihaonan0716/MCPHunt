"""Compute McFadden pseudo-R² shares for the deviance decomposition reported
in the paper (appendix.tex §Regression Analysis, Deviance decomposition).

Definition (paper appendix.tex:596-598 verbatim, quoted):
    "Comparing McFadden pseudo-R^2 from single-predictor logistic regressions
     on the non-CRS subset (n=1,440), mechanism family alone accounts for X%
     of the full-model pseudo-R^2 improvement versus Y% for model identity."

Formula:
    R2_single = 1 - LL(M_single) / LL(M_null)
    R2_full   = 1 - LL(M_full)   / LL(M_null)
    share_mech  = R2_mech-only  / R2_full
    share_model = R2_model-only / R2_full

The two shares do not have to sum to 100%: the remainder captures shared
variance, interaction between mechanism and model, and model-implicit CRS
influence not carried by either single-predictor model. Expected snapshot
band under the current registry is ~90%-98% (empirically ~94%).

Inputs are read from results/regression_data.csv (columns:
model, task_id, mechanism, env_variant, is_crs, leaked, utility).
The non-CRS subset (is_crs == 0) is used exclusively, matching the
appendix's stated scope of n=1,440.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, Optional

import numpy as np
import pandas as pd
from statsmodels.api import Logit
from statsmodels.tools import add_constant


LOGIT_METHOD_PRIMARY = "newton"
LOGIT_METHOD_FALLBACK = "bfgs"
LOGIT_MAXITER = 200


def _fit_llf(y: np.ndarray, X: np.ndarray) -> float:
    """Fit a logistic regression and return its log-likelihood.

    Uses Newton by default (fast, exact on well-conditioned Logit problems);
    falls back to BFGS if Newton fails to converge (rare-event / near-separation
    guard). Both are unpenalised MLE — no shrinkage that would silently
    alter the reported pseudo-R^2.
    """
    try:
        return Logit(y, X).fit(
            disp=False, method=LOGIT_METHOD_PRIMARY, maxiter=LOGIT_MAXITER
        ).llf
    except Exception:  # noqa: BLE001 (Newton can raise many types on singular Hessian)
        return Logit(y, X).fit(
            disp=False, method=LOGIT_METHOD_FALLBACK, maxiter=LOGIT_MAXITER * 2
        ).llf


def _mcfadden_pseudo_r2(ll_model: float, ll_null: float) -> float:
    """McFadden's pseudo-R² = 1 - LL_model / LL_null.

    Both log-likelihoods are negative; ratio is in (0, 1] for a null-worst-case
    model. Guard against ll_null == 0 (which cannot occur for a non-degenerate
    binary outcome but is asserted anyway).
    """
    if ll_null == 0.0:
        raise ValueError("null-model log-likelihood is 0; degenerate outcome vector")
    return 1.0 - ll_model / ll_null


def _hash_input(df: pd.DataFrame) -> str:
    """Content hash over the deterministic-order CSV representation.

    Reproducibility guarantee: same CSV → same hash → same shares. Any drift
    in the input pins itself in the emitted macros' provenance.
    """
    canonical = df.sort_values(list(df.columns)).to_csv(index=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_deviance_shares(
    regression_data_path: Path | str,
    non_crs_only: bool = True,
) -> Dict[str, float | int | str]:
    """Compute mechanism vs. model pseudo-R² share for the deviance decomposition.

    Returns a dict with:
      - mech_pseudo_r2 (float)   : McFadden R² of mechanism-only model
      - model_pseudo_r2 (float)  : McFadden R² of model-only model
      - full_pseudo_r2 (float)   : McFadden R² of full (mechanism + model) model
      - mech_share_pct (float)   : mech_pseudo_r2 / full_pseudo_r2 * 100
      - model_share_pct (float)  : model_pseudo_r2 / full_pseudo_r2 * 100
      - n_rows_used (int)        : rows used in the fit (must equal 1,440 for
                                   the currently-registered non-CRS subset)
      - input_hash (str)         : SHA-256 of the deterministically-sorted CSV

    The full model here is `leaked ~ mechanism + model` (CRS is already filtered
    out by the non_crs_only=True default, so it is not a predictor); this
    matches the appendix's "share of the full-model pseudo-R^2 improvement" on
    the non-CRS subset.
    """
    path = Path(regression_data_path)
    df = pd.read_csv(path)

    required_cols = {"model", "task_id", "mechanism", "env_variant", "is_crs",
                     "leaked", "utility"}
    missing = required_cols - set(df.columns)
    if missing:
        raise ValueError(
            f"regression_data.csv missing required columns: {sorted(missing)}"
        )

    input_hash = _hash_input(df)

    if non_crs_only:
        df = df[df["is_crs"] == 0].copy()

    y = df["leaked"].astype(int).values
    if len(y) == 0:
        raise ValueError("empty subset after filtering; nothing to fit")

    mech_dummies = pd.get_dummies(df["mechanism"], prefix="mech", drop_first=True).astype(int)
    model_dummies = pd.get_dummies(df["model"], prefix="model", drop_first=True).astype(int)

    X_null = np.ones((len(y), 1))
    X_mech = add_constant(mech_dummies.values.astype(float))
    X_model = add_constant(model_dummies.values.astype(float))
    X_full = add_constant(
        pd.concat([mech_dummies, model_dummies], axis=1).values.astype(float)
    )

    ll_null = _fit_llf(y, X_null)
    ll_mech = _fit_llf(y, X_mech)
    ll_model = _fit_llf(y, X_model)
    ll_full = _fit_llf(y, X_full)

    r2_mech = _mcfadden_pseudo_r2(ll_mech, ll_null)
    r2_model = _mcfadden_pseudo_r2(ll_model, ll_null)
    r2_full = _mcfadden_pseudo_r2(ll_full, ll_null)

    if r2_full <= 0:
        raise ValueError(
            f"full-model pseudo-R² is non-positive ({r2_full}); refuse to divide"
        )

    return {
        "mech_pseudo_r2": r2_mech,
        "model_pseudo_r2": r2_model,
        "full_pseudo_r2": r2_full,
        "mech_share_pct": r2_mech / r2_full * 100.0,
        "model_share_pct": r2_model / r2_full * 100.0,
        "n_rows_used": len(y),
        "input_hash": input_hash,
    }
