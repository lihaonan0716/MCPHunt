#!/usr/bin/env python3
"""
Reproduce every numeric claim in the MCPHunt paper from raw trace files.

Covers all 16 data-bearing tables in paper.tex and appendix.tex:
  Main:     Tables 1(skip), 2(skip), 3, 4, 5, 6, 7, 8
  Appendix: A1(skip), A2(skip), A3, A4, A5, A6, A7, A8, A9, A10, A11, A12

Tables 1 (related work) and 2 (mechanism taxonomy) are static text.
Tables A1 (task list) and A2 (CRS examples) are static text.

Usage:
    PYTHONPATH=src python3 scripts/reproduce_paper_tables.py
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcphunt.labeling import (
    STRICT_LEAKAGE_SIGNALS,
    TAINTED_BOUNDARY_SIGNALS,
    NETWORK_RISK_SIGNALS,
)
from mcphunt.taxonomy import RISK_TASKS, HN_TASKS, BENIGN_TASKS, CRS_TASKS, RISK_MECHANISMS

REPO = Path(__file__).resolve().parents[1]
TRACES_DIR = REPO / "results" / "agent_traces"
MIT_DIR = REPO / "results" / "mitigation_traces"

PRIMARY_MODEL = "gpt_5_4"
PRIMARY_LABEL = "GPT-5.4"

PAPER_MODELS = {
    "gpt_5_4": "GPT-5.4",
    "gpt_5_2": "GPT-5.2",
    "deepseek_v4_flash": "DeepSeek-V4-Flash",
    "gemini_3_1_pro_preview": "Gemini-3.1-Pro",
    "MiniMax_M2_7": "MiniMax-M2.7",
}

MECH_IDS = RISK_TASKS | HN_TASKS
ALL_SIGNALS = sorted(STRICT_LEAKAGE_SIGNALS | TAINTED_BOUNDARY_SIGNALS | NETWORK_RISK_SIGNALS)
MECH_ORDER = [
    "browser_to_local", "forced_multi_hop", "file_to_file", "db_to_artifact",
    "config_to_script", "git_history_leak", "sensitive_to_shell", "file_to_doc",
    "indirect_exposure",
]

MIT_LEVELS_PRIMARY = {
    "M0 (baseline)": "gpt54_m0",
    "M1 (reminder)": "gpt54_m1",
    "M2 (redaction)": "gpt54_m2",
    "M3 (boundary)": "gpt54_m3",
}

MIT_LEVELS_CROSS = {
    "deepseek_v4_flash": {
        "M0": "deepseek_m0_rv1", "M1": "deepseek_m1_rv1",
        "M2": "deepseek_m2_rv1", "M3": "deepseek_m3_rv1",
    },
    "MiniMax_M2_7": {
        "M0": "minimax_m0_rv1", "M1": "minimax_m1_rv1",
        "M2": "minimax_m2_rv1", "M3": "minimax_m3_rv1",
    },
}


# ── Helpers ──────────────────────────────────────────────────────────

def load_traces(path: Path) -> List[Dict]:
    """Load traces from a file or find the first trace JSON in a directory."""
    if path.is_file():
        data = json.loads(path.read_text())
        return data["traces"] if isinstance(data, dict) and "traces" in data else data
    if path.is_dir():
        for f in sorted(path.glob("agent_traces*.json")):
            if "collection_summary" in f.name:
                continue
            data = json.loads(f.read_text())
            return data["traces"] if isinstance(data, dict) and "traces" in data else data
    return []


def load_all_main() -> Dict[str, List[Dict]]:
    result = {}
    for slug, display in PAPER_MODELS.items():
        traces = load_traces(TRACES_DIR / slug / "agent_traces.json")
        if traces:
            result[slug] = traces
        else:
            print(f"  WARNING: {slug} not found, skipping")
    return result


def leaked(t: Dict) -> bool:
    return t["labeling"]["any_risk"]


def util(t: Dict) -> bool:
    return t.get("outcome", "") in ("safe_success", "unsafe_success")


def pct(n: int, d: int) -> str:
    return f"{n/max(d,1)*100:.1f}%" if d > 0 else "n/a"


def wilson(n: int, d: int) -> str:
    if d == 0:
        return "[n/a]"
    from math import sqrt
    z = 1.96
    p = n / d
    denom = 1 + z*z/d
    center = (p + z*z/(2*d)) / denom
    margin = z * sqrt((p*(1-p) + z*z/(4*d)) / d) / denom
    lo, hi = max(0, center - margin), min(1, center + margin)
    return f"[{lo*100:.1f}, {hi*100:.1f}]"


def risky(traces: List[Dict]) -> List[Dict]:
    return [t for t in traces if t["env_type"].startswith("risky")]


def mech_tagged(traces: List[Dict]) -> List[Dict]:
    return [t for t in traces if t.get("task_id", "") in MECH_IDS]


def by_mechanism(traces: List[Dict]) -> Dict[str, List[Dict]]:
    d: Dict[str, List[Dict]] = defaultdict(list)
    for t in traces:
        m = t.get("risk_mechanism", "")
        if m and t.get("task_id", "") in MECH_IDS:
            d[m].append(t)
    return d


def section(title: str) -> None:
    print(f"\n{'='*72}")
    print(title)
    print(f"{'='*72}")


def fisher_exact(a: int, b: int, c: int, d: int) -> float:
    from scipy.stats import fisher_exact as _fe
    _, p = _fe([[a, b], [c, d]])
    return p


# ── Main ─────────────────────────────────────────────────────────────

def main() -> int:
    print("=" * 72)
    print("MCPHunt: Full Paper Reproduction Report")
    print("=" * 72)
    print(f"Tier-1 signals: {sorted(STRICT_LEAKAGE_SIGNALS)}")
    print(f"Tier-2 signals: {sorted(TAINTED_BOUNDARY_SIGNALS | NETWORK_RISK_SIGNALS)}")
    print(f"Mechanisms:      {len(RISK_MECHANISMS)} families")
    print(f"Tasks:           {len(RISK_TASKS)} risk + {len(HN_TASKS)} HN + {len(BENIGN_TASKS)} benign = {len(RISK_TASKS)+len(HN_TASKS)+len(BENIGN_TASKS)}")
    print(f"CRS tasks:       {len(CRS_TASKS)}")

    all_traces = load_all_main()
    if not all_traces:
        print("No traces found. Run `make download` first.")
        return
    total = sum(len(v) for v in all_traces.values())
    print(f"\nLoaded {total} traces across {len(all_traces)} models")

    gpt = all_traces.get(PRIMARY_MODEL, [])
    ok = True

    # ================================================================
    # TABLE 3 (tab:main): Per-environment (primary model)
    # ================================================================
    section("TABLE 3 (tab:main): Propagation rate by environment (GPT-5.4)")

    env_groups = defaultdict(list)
    for t in gpt:
        env_groups[t["env_type"]].append(t)

    for label in ["risky (pooled)", "risky_v1", "risky_v2", "risky_v3", "benign",
                   "hard_neg (pooled)", "risk in hard_neg", "HN in hard_neg"]:
        if label == "risky (pooled)":
            sub = risky(gpt)
        elif label == "hard_neg (pooled)":
            sub = [t for t in gpt if t["env_type"].startswith("hard_neg")]
        elif label == "risk in hard_neg":
            sub = [t for t in gpt if t["env_type"].startswith("hard_neg") and t["task_id"] in RISK_TASKS]
        elif label == "HN in hard_neg":
            sub = [t for t in gpt if t["env_type"].startswith("hard_neg") and t["task_id"] in HN_TASKS]
        else:
            sub = env_groups.get(label, [])
        n = len(sub)
        lk = sum(1 for t in sub if leaked(t))
        u = sum(1 for t in sub if util(t))
        print(f"  {label:25s}  n={n:4d}  prop={pct(lk,n):>6s} {wilson(lk,n):>16s}  utility={pct(u,n):>6s}")

    # ================================================================
    # TABLE 4 (tab:causal): 2×2 factorial
    # ================================================================
    section("TABLE 4 (tab:causal): 2×2 factorial (GPT-5.4, v1)")

    for label, tid_set, env in [
        ("Cross-boundary×Production", RISK_TASKS, "risky_v1"),
        ("Cross-boundary×Placeholder", RISK_TASKS, "hard_neg_v1"),
        ("Surface-level×Production", BENIGN_TASKS, "risky_v1"),
        ("Surface-level×Placeholder", HN_TASKS, "hard_neg_v1"),
    ]:
        sub = [t for t in gpt if t["task_id"] in tid_set and t["env_type"] == env]
        lk = sum(1 for t in sub if leaked(t))
        print(f"  {label:30s}  {lk}/{len(sub)} = {pct(lk, len(sub))} {wilson(lk, len(sub))}")

    # ================================================================
    # TABLE 5 (tab:mechanism): Per-mechanism (primary, risky)
    # ================================================================
    section("TABLE 5 (tab:mechanism): Per-mechanism propagation (GPT-5.4, risky)")

    mechs = by_mechanism(risky(gpt))
    for m in MECH_ORDER:
        sub = mechs.get(m, [])
        lk = sum(1 for t in sub if leaked(t))
        print(f"  {m:25s}  {lk:2d}/{len(sub):2d}  {pct(lk,len(sub)):>6s} {wilson(lk,len(sub))}")

    # ================================================================
    # TABLE 6 (tab:crs_summary): CRS stratification (primary)
    # ================================================================
    section("TABLE 6 (tab:crs_summary): CRS stratification (GPT-5.4, risky)")

    mr = mech_tagged(risky(gpt))
    crs = [t for t in mr if t["task_id"] in CRS_TASKS]
    non_crs = [t for t in mr if t["task_id"] not in CRS_TASKS]
    for label, sub in [("All mechanism", mr), ("CRS (task-mandated)", crs), ("Non-CRS (policy-viol.)", non_crs)]:
        lk = sum(1 for t in sub if leaked(t))
        print(f"  {label:30s}  n={len(sub):4d}  leaked={lk:3d}  rate={pct(lk,len(sub))}")

    # ================================================================
    # TABLE 7 (tab:cross_model_main): Cross-model summary
    # ================================================================
    section("TABLE 7 (tab:cross_model_main): Cross-model summary (risky)")

    print(f"  {'Model':25s} {'All':>5s} {'Risky':>6s} {'Prop%':>7s} {'CI':>16s} {'Util%':>7s} {'PV%':>7s}")
    for slug, display in PAPER_MODELS.items():
        if slug not in all_traces:
            continue
        tr = all_traces[slug]
        r = risky(tr)
        lk = sum(1 for t in r if leaked(t))
        u = sum(1 for t in r if util(t))
        nc = [t for t in mech_tagged(r) if t["task_id"] not in CRS_TASKS]
        pv = sum(1 for t in nc if leaked(t))
        print(f"  {display:25s} {len(tr):5d} {len(r):6d} {pct(lk,len(r)):>7s} {wilson(lk,len(r)):>16s} {pct(u,len(r)):>7s} {pct(pv,len(nc)):>7s}")

    # ================================================================
    # TABLE 8 (tab:mitigation_cross): Cross-model mitigation (rv1)
    # ================================================================
    section("TABLE 8 (tab:mitigation_cross): Cross-model mitigation (rv1 risk tasks)")

    cross_models = {"gpt_5_4": MIT_LEVELS_PRIMARY}
    cross_models.update(MIT_LEVELS_CROSS)
    for model_slug, levels in cross_models.items():
        display = PAPER_MODELS.get(model_slug, model_slug)
        row = f"  {display:20s}"
        for lname, dname in levels.items():
            tr = load_traces(MIT_DIR / dname)
            r = [t for t in tr if t.get("env_type", "") == "risky_v1" and t.get("task_id", "") in RISK_TASKS]
            lk = sum(1 for t in r if leaked(t))
            row += f"  {lname}={pct(lk,len(r)):>6s} ({len(r)})"
        print(row)

    # ================================================================
    # APPENDIX TABLE A3 (tab:crs_mechanism): Per-mechanism CRS breakdown
    # ================================================================
    section("APP TABLE A3 (tab:crs_mechanism): Per-mechanism CRS breakdown (GPT-5.4, risky)")

    print(f"  {'Mechanism':25s} {'CRS_n':>5s} {'CRS%':>6s}  {'nonCRS_n':>8s} {'PV%':>6s}  {'Overall':>7s}")
    for m in MECH_ORDER:
        sub = mechs.get(m, [])
        c = [t for t in sub if t["task_id"] in CRS_TASKS]
        nc = [t for t in sub if t["task_id"] not in CRS_TASKS]
        c_lk = sum(1 for t in c if leaked(t))
        nc_lk = sum(1 for t in nc if leaked(t))
        all_lk = sum(1 for t in sub if leaked(t))
        c_pct = pct(c_lk, len(c)) if c else "n/a"
        print(f"  {m:25s} {len(c):5d} {c_pct:>6s}  {len(nc):8d} {pct(nc_lk,len(nc)):>6s}  {pct(all_lk,len(sub)):>7s}")

    # ================================================================
    # APPENDIX TABLE A4 (tab:mechanism_heterogeneity): Risky vs Control
    # ================================================================
    section("APP TABLE A4 (tab:mechanism_heterogeneity): Risky vs Control + Fisher's exact (GPT-5.4)")

    ctrl_traces = [t for t in gpt if t["env_type"] in ("benign", "hard_neg_v1", "hard_neg_v2", "hard_neg_v3")]
    ctrl_mechs = by_mechanism(ctrl_traces)

    print(f"  {'Mechanism':25s} {'Risky':>7s} {'Control':>8s} {'Δ':>8s} {'p':>8s}")
    for m in MECH_ORDER:
        r_sub = mechs.get(m, [])
        c_sub = ctrl_mechs.get(m, [])
        r_lk = sum(1 for t in r_sub if leaked(t))
        c_lk = sum(1 for t in c_sub if leaked(t))
        r_rate = r_lk / max(len(r_sub), 1) * 100
        c_rate = c_lk / max(len(c_sub), 1) * 100
        delta = r_rate - c_rate
        p = fisher_exact(r_lk, len(r_sub)-r_lk, c_lk, len(c_sub)-c_lk)
        sig = "***" if p < 0.001 else "**" if p < 0.01 else "*" if p < 0.05 else ""
        p_str = "<0.001" if p < 0.001 else f"{p:.3f}"
        print(f"  {m:25s} {r_rate:6.1f}% {c_rate:7.1f}% {delta:>+7.1f}pp {p_str:>8s} {sig}")

    # ================================================================
    # APPENDIX TABLE A5 (tab:signals): Signal distribution (primary, risky)
    # ================================================================
    section("APP TABLE A5 (tab:signals): Signal distribution (GPT-5.4, risky, n=387)")

    r = risky(gpt)
    print(f"  {'Signal':30s} {'Tier':>4s} {'Count':>6s}")
    for sig in ALL_SIGNALS:
        tier = "1" if sig in STRICT_LEAKAGE_SIGNALS else "2"
        cnt = sum(1 for t in r if t["labeling"]["risk_signals"].get(sig))
        if cnt > 0:
            print(f"  {sig:30s} {tier:>4s} {cnt:6d}")

    # ================================================================
    # APPENDIX TABLE A6 (tab:quadrants): Outcome quadrants (primary)
    # ================================================================
    section("APP TABLE A6 (tab:quadrants): Outcome quadrant distribution (GPT-5.4)")

    for env_label, sub in [("Risky", risky(gpt)),
                           ("Benign", [t for t in gpt if t["env_type"] == "benign"]),
                           ("Hard-neg", [t for t in gpt if t["env_type"].startswith("hard_neg")])]:
        n = len(sub)
        ss = sum(1 for t in sub if t["outcome"] == "safe_success")
        us = sum(1 for t in sub if t["outcome"] == "unsafe_success")
        sf = sum(1 for t in sub if t["outcome"] == "safe_failure")
        uf = sum(1 for t in sub if t["outcome"] == "unsafe_failure")
        u = ss + us
        print(f"  {env_label:10s}  n={n:4d}  safe_succ={ss:3d}({ss/max(n,1)*100:4.1f}%)  "
              f"unsafe_succ={us:3d}({us/max(n,1)*100:4.1f}%)  "
              f"safe_fail={sf:3d}({sf/max(n,1)*100:4.1f}%)  "
              f"unsafe_fail={uf:3d}({uf/max(n,1)*100:4.1f}%)  util={u/max(n,1)*100:.1f}%")

    # ================================================================
    # APPENDIX TABLE A7 (tab:multi_model_aggregate): Cross-model + CRS
    # ================================================================
    section("APP TABLE A7 (tab:multi_model_aggregate): Cross-model with CRS column")

    print(f"  {'Model':25s} {'Risky':>6s} {'Prop%':>7s} {'CI':>16s} {'Util%':>7s} {'PV%':>7s} {'CRS%':>6s}")
    for slug, display in PAPER_MODELS.items():
        if slug not in all_traces:
            continue
        tr = all_traces[slug]
        r = risky(tr)
        lk = sum(1 for t in r if leaked(t))
        u = sum(1 for t in r if util(t))
        mr_r = mech_tagged(r)
        crs_sub = [t for t in mr_r if t["task_id"] in CRS_TASKS]
        nc = [t for t in mr_r if t["task_id"] not in CRS_TASKS]
        crs_lk = sum(1 for t in crs_sub if leaked(t))
        pv = sum(1 for t in nc if leaked(t))
        print(f"  {display:25s} {len(r):6d} {pct(lk,len(r)):>7s} {wilson(lk,len(r)):>16s} "
              f"{pct(u,len(r)):>7s} {pct(pv,len(nc)):>7s} {pct(crs_lk,len(crs_sub)):>6s}")

    # ================================================================
    # APPENDIX TABLE A8 (tab:multi_model_mechanism): Per-mechanism × model
    # ================================================================
    section("APP TABLE A8 (tab:multi_model_mechanism): Per-mechanism × model (risky)")

    header = f"  {'Mechanism':25s}"
    for display in PAPER_MODELS.values():
        header += f" {display:>18s}"
    print(header)

    for m in MECH_ORDER:
        row = f"  {m:25s}"
        for slug in PAPER_MODELS:
            if slug not in all_traces:
                row += f" {'n/a':>18s}"
                continue
            sub = [t for t in risky(all_traces[slug])
                   if t.get("risk_mechanism") == m and t.get("task_id", "") in MECH_IDS]
            lk = sum(1 for t in sub if leaked(t))
            row += f" {lk:2d}/{len(sub):2d} {lk/max(len(sub),1)*100:5.1f}%"
        print(row)

    # ================================================================
    # APPENDIX TABLE A9 (tab:multi_model_signals): Signal counts × model
    # ================================================================
    section("APP TABLE A9 (tab:multi_model_signals): Signal counts per model (risky)")

    header = f"  {'Signal':30s}"
    for display in PAPER_MODELS.values():
        header += f" {display:>12s}"
    print(header)

    for sig in ALL_SIGNALS:
        counts = []
        any_nonzero = False
        for slug in PAPER_MODELS:
            if slug not in all_traces:
                counts.append(0)
                continue
            c = sum(1 for t in risky(all_traces[slug]) if t["labeling"]["risk_signals"].get(sig))
            counts.append(c)
            if c > 0:
                any_nonzero = True
        if any_nonzero:
            row = f"  {sig:30s}"
            for c in counts:
                row += f" {c:12d}"
            print(row)

    # ================================================================
    # APPENDIX TABLE A10 (tab:odds_ratios): GEE regression
    # ================================================================
    section("APP TABLE A10 (tab:odds_ratios): GEE logistic regression (non-CRS risky)")

    try:
        import numpy as np
        from scipy.stats import norm as _norm
        import statsmodels.api as sm
        from statsmodels.genmod.generalized_estimating_equations import GEE
        from statsmodels.genmod.families import Binomial
        from statsmodels.genmod.cov_struct import Exchangeable

        rows = []
        for slug in PAPER_MODELS:
            if slug not in all_traces:
                continue
            for t in risky(all_traces[slug]):
                if t.get("task_id", "") not in MECH_IDS or t["task_id"] in CRS_TASKS:
                    continue
                rows.append({
                    "leaked": int(leaked(t)),
                    "mechanism": t.get("risk_mechanism", ""),
                    "model": slug,
                    "task_id": t["task_id"],
                })

        import pandas as pd
        df = pd.DataFrame(rows)
        df["mechanism"] = pd.Categorical(df["mechanism"], categories=MECH_ORDER)
        model_order = list(PAPER_MODELS.keys())
        df["model"] = pd.Categorical(df["model"], categories=model_order)

        X_mech = pd.get_dummies(df["mechanism"], drop_first=False, dtype=float)
        X_model = pd.get_dummies(df["model"], drop_first=False, dtype=float)
        ref_mech = "indirect_exposure"
        ref_model = "gpt_5_2"
        X_mech = X_mech.drop(columns=[ref_mech])
        X_model = X_model.drop(columns=[ref_model])
        X = pd.concat([X_mech, X_model], axis=1)
        X = sm.add_constant(X)

        groups = df["task_id"].astype("category").cat.codes
        gee = GEE(df["leaked"], X, groups=groups,
                   family=Binomial(), cov_struct=Exchangeable())
        res = gee.fit()

        print(f"  {'Predictor':30s} {'OR':>8s} {'95% CI':>18s} {'p':>8s}")
        print(f"  {'(ref: '+ref_mech+')':30s}")
        for name in X_mech.columns:
            coef = res.params[name]
            se = res.bse[name]
            OR = np.exp(coef)
            ci_lo, ci_hi = np.exp(coef - 1.96*se), np.exp(coef + 1.96*se)
            p = res.pvalues[name]
            sig = "***" if p < 0.001 else "**" if p < 0.01 else "*" if p < 0.05 else ""
            print(f"  {name:30s} {OR:8.1f} [{ci_lo:7.1f}, {ci_hi:7.1f}] {p:8.3f} {sig}")

        print(f"  {'(ref: '+ref_model+')':30s}")
        for name in X_model.columns:
            coef = res.params[name]
            se = res.bse[name]
            OR = np.exp(coef)
            ci_lo, ci_hi = np.exp(coef - 1.96*se), np.exp(coef + 1.96*se)
            p = res.pvalues[name]
            sig = "***" if p < 0.001 else "**" if p < 0.01 else "*" if p < 0.05 else ""
            print(f"  {PAPER_MODELS.get(name, name):30s} {OR:8.1f} [{ci_lo:7.1f}, {ci_hi:7.1f}] {p:8.3f} {sig}")

        print(f"\n  N={len(df)}, clusters={df['task_id'].nunique()}")

    except ImportError as e:
        print(f"  ERROR: missing dependency: {e}")
        print("  Install with: pip install -e .")
        print("  Required packages: statsmodels, pandas, numpy, scipy")
        ok = False

    # ================================================================
    # APPENDIX TABLE A11 (tab:mitigation_aggregate): GPT-5.4 mitigation
    # ================================================================
    section("APP TABLE A11 (tab:mitigation_aggregate): Mitigation (GPT-5.4, risky pooled)")

    baseline_rate = None
    for level_name, slug in MIT_LEVELS_PRIMARY.items():
        tr = load_traces(MIT_DIR / slug)
        r = [t for t in tr if t.get("env_type", "").startswith("risky")]
        if not r:
            print(f"  {level_name:20s}  (no traces)")
            continue
        n = len(r)
        lk = sum(1 for t in r if leaked(t))
        u = sum(1 for t in r if util(t))
        nc = [t for t in r if t.get("task_id", "") in MECH_IDS and t.get("task_id", "") not in CRS_TASKS]
        pv = sum(1 for t in nc if leaked(t))
        rate = lk / max(n, 1) * 100
        if baseline_rate is None:
            baseline_rate = rate
            delta = "---"
        else:
            delta = f"{rate - baseline_rate:+.1f}pp"
        print(f"  {level_name:20s}  n={n:4d}  prop={pct(lk,n):>6s}  Δ={delta:>8s}  "
              f"utility={pct(u,n):>6s}  PV={pct(pv,len(nc)):>6s}")

    # ================================================================
    # APPENDIX TABLE A12 (tab:mitigation_mechanism): Per-mechanism mitigation
    # ================================================================
    section("APP TABLE A12 (tab:mitigation_mechanism): Per-mechanism mitigation (GPT-5.4, risky)")

    header = f"  {'Mechanism':25s}"
    for lname in MIT_LEVELS_PRIMARY:
        header += f" {lname:>16s}"
    print(header)

    mit_data: Dict[str, Dict[str, List[Dict]]] = {}
    for lname, slug in MIT_LEVELS_PRIMARY.items():
        tr = load_traces(MIT_DIR / slug)
        r = [t for t in tr if t.get("env_type", "").startswith("risky")]
        mit_data[lname] = by_mechanism(r)

    for m in MECH_ORDER:
        row = f"  {m:25s}"
        for lname in MIT_LEVELS_PRIMARY:
            sub = mit_data[lname].get(m, [])
            lk = sum(1 for t in sub if leaked(t))
            row += f" {lk:2d}/{len(sub):2d} {lk/max(len(sub),1)*100:5.1f}%"
        print(row)

    # ================================================================
    # CONSISTENCY CHECKS
    # ================================================================
    section("CONSISTENCY CHECKS")

    for slug, traces in all_traces.items():
        for t in risky(traces):
            t1 = any(t["labeling"]["risk_signals"].get(s) for s in STRICT_LEAKAGE_SIGNALS)
            ar = t["labeling"]["any_risk"]
            if t1 != ar:
                print(f"  ✗ MISMATCH: {slug}/{t['trace_id']}: tier1={t1}, any_risk={ar}")
                ok = False
    print("  ✓ Tier-1 == any_risk for all risky traces") if ok else None

    benign_leaks = [f"{s}/{t['trace_id']}" for s, tr in all_traces.items()
                    for t in tr if t["env_type"] == "benign" and leaked(t)]
    if benign_leaks:
        print(f"  ✗ BENIGN LEAKS: {benign_leaks}")
        ok = False
    else:
        print("  ✓ Zero benign-environment leaks across all models")

    print(f"\n{'='*72}")
    print("ALL TABLES REPRODUCED" if ok else "ISSUES FOUND")
    print(f"{'='*72}")
    return 0 if ok else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
