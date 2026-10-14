#!/usr/bin/env python3
r"""
Generate paper/results_macros.tex from raw trace data.

Every numeric claim in the paper and appendix is derived from this single
script. Run after any data change:

    PYTHONPATH=src python3 scripts/generate_results_macros.py

The output file is \input'd by paper.tex and provides \newcommand macros
for all table cells, inline numbers, and cross-model ranges.
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcphunt.taxonomy import (
    TASK_REGISTRY, RISK_TASKS, HN_TASKS, BENIGN_TASKS, CRS_TASKS,
    MECHANISM_INCIDENT_GROUNDING, FAMILY_WORKFLOW_GROUNDING,
)
from mcphunt.deviance import compute_deviance_shares

REPO = Path(__file__).resolve().parents[1]
TRACES_DIR = REPO / "results" / "agent_traces"
MITIG_DIR = REPO / "results" / "mitigation_traces"
B3_REPLICATION_DIR = REPO / "results" / "agent_traces_b3_replication"
REGRESSION_DATA = REPO / "results" / "regression_data.csv"
OUT = REPO / "paper" / "results_macros.tex"

# Supplemental-evidence artifacts. These are analysis products with their own
# provenance records (input hashes, seeds, sampling frames), so the macros READ
# them rather than recomputing: re-deriving here would fork the statistics away
# from the artifact that documents how they were produced.
LIVE_GUARD_ARTIFACT = (REPO / "results" / "live_guard_replication"
                       / "paired_live_guard_analysis.json")
HARD_NEG_ARTIFACT = (REPO / "results" / "hard_negative_analysis"
                     / "hard_negative_ci.json")
MISS_PREVALENCE_ARTIFACT = (
    REPO / "results" / "recall_evaluation"
    / "recall_estimation_claude-opus-4-8_seed20260729_n150.json"
)
# Historical single-model guarded collection run. DISTINCT from the same-day
# live pilot above: different arms, different denominators, weaker control.
# Macro names are deliberately prefixed `guardedRun*` (never `liveGuard*`) so a
# reader of the .tex cannot conflate the two bodies of evidence.
GUARDED_RUN_ARTIFACT = (REPO / "results" / "live_guard_replication"
                        / "guarded_run_provenance.json")

PRIMARY_SLUG = "gpt_5_4"

MODEL_SLUGS = {
    "gpt_5_4": "GPT-5.4",
    "gpt_5_2": "GPT-5.2",
    "deepseek_v4_flash": "DeepSeek-V4-Flash",
    "gemini_3_1_pro_preview": "Gemini-3.1-Pro",
    "MiniMax_M2_7": "MiniMax-M2.7",
}

MECHANISMS = [
    "browser_to_local", "forced_multi_hop", "file_to_file",
    "db_to_artifact", "config_to_script", "git_history_leak",
    "sensitive_to_shell", "file_to_doc", "indirect_exposure",
]


def is_unsafe(t: Dict) -> bool:
    return t.get("outcome", "").startswith("unsafe")

def is_success(t: Dict) -> bool:
    return t.get("outcome", "") in ("safe_success", "unsafe_success")

def fmt_pct(num: int, den: int) -> str:
    if den == 0:
        return "0.0"
    return f"{num / den * 100:.1f}"

def wilson_ci(num: int, den: int) -> tuple:
    if den == 0:
        return (0.0, 0.0)
    z = 1.96
    p = num / den
    denom = 1 + z * z / den
    center = (p + z * z / (2 * den)) / denom
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * den)) / den) / denom
    return (max(0, center - margin) * 100, min(1, center + margin) * 100)

def fmt_num(n: int) -> str:
    if n >= 1000:
        return f"{n:,}".replace(",", "{,}")
    return str(n)


def load_traces(slug: str) -> List[Dict]:
    path = TRACES_DIR / slug / "agent_traces.json"
    data = json.loads(path.read_text(encoding="utf-8"))
    return data["traces"]


def _rel(path: Path) -> str:
    """Repo-relative POSIX path, falling back to the absolute path.

    ``relative_to`` raises for anything outside the repo, which would replace a
    clear "artifact missing" message with an unrelated ValueError.
    """
    try:
        return str(path.relative_to(REPO)).replace("\\", "/")
    except ValueError:
        return str(path).replace("\\", "/")


def require_artifact(path: Path, schema_key: str, expected_schema: str) -> Dict:
    """Load a supplemental-evidence artifact, failing loudly if it is absent.

    A missing artifact must never degrade into a silently-omitted macro: the
    paper would then \\input a file whose numbers vanished without a build error,
    which is exactly how the release checksums were once lost (see
    artifacts/submission_archive/README.md). Absent or schema-drifted input is a
    hard error.
    """
    if not path.exists():
        raise SystemExit(
            f"ERROR: required artifact missing: {_rel(path)}\n"
            f"  The paper cites numbers from this file. Regenerate it before\n"
            f"  regenerating macros, or the manuscript loses reproducible values."
        )
    data = json.loads(path.read_text(encoding="utf-8"))
    actual = data.get(schema_key)
    if actual != expected_schema:
        raise SystemExit(
            f"ERROR: schema drift in {_rel(path)}\n"
            f"  expected {schema_key}={expected_schema!r}, found {actual!r}\n"
            f"  Field paths below may have moved; do NOT paper over this."
        )
    return data


def require_recorded_inputs(artifact: Dict, path: Path) -> None:
    """Re-hash an artifact's declared inputs and fail on drift.

    An artifact records the SHA-256 of the files it was computed from. Those
    hashes are only worth recording if something re-checks them: otherwise a
    relabel can silently change the traces while the artifact -- and every macro
    read from it -- keeps reporting statistics computed from the old bytes.
    """
    for arm, meta in artifact.get("inputs", {}).items():
        src = REPO / meta["path"]
        if not src.exists():
            raise SystemExit(
                f"ERROR: {_rel(path)} declares input {meta['path']}\n"
                f"  which no longer exists. Regenerate the artifact."
            )
        h = hashlib.sha256()
        with src.open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                h.update(chunk)
        if h.hexdigest() != meta["sha256"]:
            raise SystemExit(
                f"ERROR: input drift for {_rel(path)} [{arm}]\n"
                f"  {meta['path']}\n"
                f"  recorded {meta['sha256']}\n"
                f"  on disk  {h.hexdigest()}\n"
                f"  The artifact's statistics were computed from different bytes\n"
                f"  than the traces now on disk. Regenerate it before the macros."
            )


def pct1(x: float) -> str:
    """Format a 0-1 proportion as a 1-decimal percentage (no % sign)."""
    return f"{x * 100:.1f}"


def signed_pp(x: float) -> str:
    """Format a 0-1 proportion difference as a signed percentage-point value.

    Uses LaTeX math minus ($-$) rather than a hyphen so the sign typesets
    correctly in text mode.
    """
    return signed_pct(x * 100)


def signed_pct(v: float) -> str:
    """Format an already-percentage value with a typeset LaTeX sign.

    Applies to CI bounds too: a bound emitted as ``-48.8`` would typeset as a
    hyphen, which reads as a range dash next to the other bound. Negative bounds
    are common here (the utility interval spans zero), so every signed value
    goes through this.
    """
    return f"$-${abs(v):.1f}" if v < 0 else f"$+${v:.1f}"


def ci_bound(v: float) -> str:
    """Format a CI bound: math minus when negative, bare digits when positive.

    Unlike signed_pct this does NOT force a ``+`` -- a bracket reading
    ``[$+$4.6, $+$13.5]`` is noise, while ``[$-$48.8, $-$10.8]`` needs the signs.
    """
    return f"$-${abs(v):.1f}" if v < 0 else f"{v:.1f}"


def risky(traces: List[Dict]) -> List[Dict]:
    return [t for t in traces if t["env_type"].startswith("risky")]


def mech_tagged(traces: List[Dict]) -> List[Dict]:
    return [t for t in traces
            if TASK_REGISTRY.get(t["task_id"])
            and TASK_REGISTRY[t["task_id"]].mechanism not in ("benign_control", None)]


def noncrs_mech(traces: List[Dict]) -> List[Dict]:
    return [t for t in mech_tagged(traces) if t["task_id"] not in CRS_TASKS]


def crs_only(traces: List[Dict]) -> List[Dict]:
    return [t for t in traces
            if TASK_REGISTRY.get(t["task_id"])
            and TASK_REGISTRY[t["task_id"]].task_type == "risk"
            and t["task_id"] in CRS_TASKS]


def by_mechanism(traces: List[Dict]) -> Dict[str, List[Dict]]:
    result = defaultdict(list)
    for t in traces:
        td = TASK_REGISTRY.get(t["task_id"])
        if td and td.mechanism not in ("benign_control", None):
            result[td.mechanism].append(t)
    return result


def main() -> None:
    lines = [
        "% Auto-generated by scripts/generate_results_macros.py",
        "% DO NOT EDIT — regenerate with: PYTHONPATH=src python3 scripts/generate_results_macros.py",
        "",
    ]

    def cmd(name: str, value: str, comment: str = ""):
        c = f"  % {comment}" if comment else ""
        lines.append(f"\\newcommand{{\\{name}}}{{{value}}}{c}")

    # ── Load all models ──
    all_data = {}
    total_main = 0
    for slug in MODEL_SLUGS:
        tr = load_traces(slug)
        all_data[slug] = tr
        total_main += len(tr)

    primary = all_data[PRIMARY_SLUG]

    # ── Global counts ──
    cmd("numModels", str(len(MODEL_SLUGS)))
    cmd("totalTracesMain", fmt_num(total_main))
    cmd("modelPrimary", MODEL_SLUGS[PRIMARY_SLUG])

    model_keys = list(MODEL_SLUGS.keys())
    non_primary = [s for s in model_keys if s != PRIMARY_SLUG]
    for i, slug in enumerate(non_primary):
        letter = chr(ord("B") + i)
        cmd(f"model{letter}", MODEL_SLUGS[slug])

    lines.append("")

    # ── Grounding mapping counts (registry-derived; static, trace-independent) ──
    # Every number here is re-derived from TASK_REGISTRY / the grounding maps.
    # Cohorts are kept explicit per the plan's naming rule (risk vs HN vs benign
    # vs total; per-mechanism vs per-family vs global) so the rebuttal text can
    # never conflate the 12 / 3 / 43 / 108 / 27 / 147 figures.
    lines.append("% === Grounding mapping counts (registry-derived) ===")
    _reg = TASK_REGISTRY
    _risk_tasks = [t for t in _reg.values() if t.task_type == "risk"]
    _hn_tasks = [t for t in _reg.values() if t.task_type == "hard_negative"]
    _benign_tasks = [t for t in _reg.values() if t.task_type == "benign"]
    _risk_mechs = sorted({t.mechanism for t in _risk_tasks})
    _families = sorted({t.family for t in _reg.values()})

    # Per-mechanism task split (uniform across the 9 risk mechanisms: 12 risk + 3 HN).
    _risk_per_mech = {m: sum(1 for t in _risk_tasks if t.mechanism == m) for m in _risk_mechs}
    _hn_per_mech = {m: sum(1 for t in _hn_tasks if t.mechanism == m) for m in _risk_mechs}
    _uniform_risk = sorted(set(_risk_per_mech.values()))
    _uniform_hn = sorted(set(_hn_per_mech.values()))

    cmd("groundingMechanismCount", str(len(MECHANISM_INCIDENT_GROUNDING)),
        "risk mechanisms with an incident-class referent (benign_control excluded)")
    cmd("groundingFamilyCount", str(len(FAMILY_WORKFLOW_GROUNDING)),
        "distinct scenario families with a workflow referent")
    if len(_uniform_risk) == 1:
        cmd("groundingRiskTasksPerMechanism", str(_uniform_risk[0]))
    else:
        cmd("groundingRiskTasksPerMechanism", "varies",
            f"non-uniform risk tasks/mechanism: {_risk_per_mech}")
    if len(_uniform_hn) == 1:
        cmd("groundingHNTasksPerMechanism", str(_uniform_hn[0]))
    else:
        cmd("groundingHNTasksPerMechanism", "varies",
            f"non-uniform HN tasks/mechanism: {_hn_per_mech}")
    cmd("groundingRiskTaskTotal", str(len(_risk_tasks)))
    cmd("groundingHNTaskTotal", str(len(_hn_tasks)))
    cmd("groundingBenignTaskTotal", str(len(_benign_tasks)))
    cmd("groundingTaskTotal", str(len(_reg)))

    # Per-family task counts (denominator = tasks registered to that family).
    for fam in _families:
        n_fam = sum(1 for t in _reg.values() if t.family == fam)
        tag = fam.title().replace("_", "")
        cmd(f"groundingFamily{tag}Tasks", str(n_fam),
            f"registered tasks in family '{fam}'")

    # Consistency guard: derived cohorts must sum to the registry total.
    assert len(_risk_tasks) + len(_hn_tasks) + len(_benign_tasks) == len(_reg), (
        "grounding cohort counts do not sum to the registry total"
    )
    assert len(MECHANISM_INCIDENT_GROUNDING) == len(_risk_mechs), (
        "grounding mechanism count != number of risk mechanisms"
    )
    assert len(FAMILY_WORKFLOW_GROUNDING) == len(_families), (
        "grounding family count != number of distinct registry families"
    )

    lines.append("")

    # ── CRS independent-audit reliability (post-submission; CSV-derived) ──
    # Derived from the committed raw labels under artifacts/release/crs_audit/
    # via the verified helpers in scripts/score_annotation.py, so the paper's
    # audit numbers are reproducible and never hand-typed (invariant #1). This
    # is a post-submission independent audit, not a pre-submission study.
    lines.append("% === CRS independent-audit reliability (post-submission) ===")
    import sys as _sys
    if str(REPO / "scripts") not in _sys.path:
        _sys.path.insert(0, str(REPO / "scripts"))
    import score_annotation as _sa
    _audit_dir = REPO / "artifacts" / "release" / "crs_audit"
    _aa = _sa._load_sheet(_audit_dir / "annotation_1.csv")
    _ab = _sa._load_sheet(_audit_dir / "annotation_2.csv")
    assert set(_aa) == set(_ab), "crs_audit: annotation sheets cover different task sets"
    _aids = list(_aa)  # annotator-1 canonical order (matches scorer + its test)
    _va = [_aa[t] for t in _aids]
    _vb = [_ab[t] for t in _aids]
    _an = len(_aids)
    _aagree = sum(1 for x, y in zip(_va, _vb) if x == y)
    _akappa = _sa._cohen_kappa(_va, _vb)
    _alo, _ahi = _sa._bootstrap_kappa_ci(
        _va, _vb, _sa.BOOTSTRAP_RESAMPLES, _sa.BOOTSTRAP_SEED
    )
    cmd("crsAuditTasks", str(_an), "tasks in the post-submission CRS audit")
    cmd("crsAuditAgreeCount", str(_aagree), "inter-annotator agreements")
    cmd("crsAuditAgreePct", f"{100.0 * _aagree / _an:.1f}\\%")
    cmd("crsAuditKappa", f"{_akappa:.2f}", "Cohen's kappa (inter-annotator)")
    cmd("crsAuditKappaCILow", f"{_alo:.2f}")
    cmd("crsAuditKappaCIHigh", f"{_ahi:.2f}")

    lines.append("")

    # ── Deviance-share decomposition (appendix Regression Analysis) ──
    # McFadden pseudo-R² for three single-predictor / full logistic models on the
    # non-CRS subset of results/regression_data.csv (n=1,440). Shares are
    # relative to the FULL-model pseudo-R² (appendix.tex:596 verbatim: "share of
    # the full-model pseudo-R^2 improvement"). Not a causal variance
    # decomposition; the two shares do NOT sum to 100 by construction — the
    # remainder is shared variance / interaction / model-implicit CRS influence.
    lines.append("% === Deviance-share decomposition (non-CRS subset, n=1,440) ===")
    _ds = compute_deviance_shares(REGRESSION_DATA)
    # Hard sanity: shape sensibly (denominator = full-model R²; two singles
    # must not exceed the full or be nonsensical); if this trips, the schema /
    # subset / reference category has drifted, do NOT paper-over.
    assert 0.0 < _ds["mech_share_pct"] <= 100.0, _ds
    assert 0.0 < _ds["model_share_pct"] <= 100.0, _ds
    assert 60.0 <= _ds["mech_share_pct"] + _ds["model_share_pct"] <= 100.0, _ds
    cmd("mechDevianceShare", f"{_ds['mech_share_pct']:.1f}",
        "% of full-model pseudo-R^2 attributable to mechanism (single-predictor)")
    cmd("modelDevianceShare", f"{_ds['model_share_pct']:.1f}",
        "% of full-model pseudo-R^2 attributable to model (single-predictor)")
    cmd("mechPseudoR", f"{_ds['mech_pseudo_r2']:.4f}")
    cmd("modelPseudoR", f"{_ds['model_pseudo_r2']:.4f}")
    cmd("fullPseudoR", f"{_ds['full_pseudo_r2']:.4f}")
    cmd("devianceNonCrsN", str(_ds["n_rows_used"]))

    lines.append("")

    # ── Primary model: Table 3 (per-environment) ──
    lines.append("% === Primary model per-environment (Table 3) ===")
    r = risky(primary)
    n, k = len(r), sum(is_unsafe(t) for t in r)
    lo, hi = wilson_ci(k, n)
    u = sum(is_success(t) for t in r)
    cmd("primaryRiskyN", str(n))
    cmd("primaryRiskyProp", fmt_pct(k, n))
    cmd("primaryRiskyCILo", f"{lo:.1f}")
    cmd("primaryRiskyCIHi", f"{hi:.1f}")
    cmd("primaryRiskyUtil", fmt_pct(u, n))

    vnum_words = {1: "one", 2: "two", 3: "three"}
    for vnum in [1, 2, 3]:
        vname = f"risky_v{vnum}"
        vtag = vnum_words[vnum]
        sub = [t for t in primary if t["env_type"] == vname]
        ns, ks = len(sub), sum(is_unsafe(t) for t in sub)
        vlo, vhi = wilson_ci(ks, ns)
        us = sum(is_success(t) for t in sub)
        cmd(f"primaryRV{vtag}N", str(ns))
        cmd(f"primaryRV{vtag}Prop", fmt_pct(ks, ns))
        cmd(f"primaryRV{vtag}CILo", f"{vlo:.1f}")
        cmd(f"primaryRV{vtag}CIHi", f"{vhi:.1f}")
        cmd(f"primaryRV{vtag}Util", fmt_pct(us, ns))

    ben = [t for t in primary if t["env_type"] == "benign"]
    cmd("primaryBenignN", str(len(ben)))
    cmd("primaryBenignProp", fmt_pct(sum(is_unsafe(t) for t in ben), len(ben)))
    cmd("primaryBenignUtil", fmt_pct(sum(is_success(t) for t in ben), len(ben)))

    hn = [t for t in primary if t["env_type"].startswith("hard_neg")]
    hn_k = sum(is_unsafe(t) for t in hn)
    hn_lo, hn_hi = wilson_ci(hn_k, len(hn))
    cmd("primaryHNPooledN", str(len(hn)))
    cmd("primaryHNPooledProp", fmt_pct(hn_k, len(hn)))
    cmd("primaryHNPooledCILo", f"{hn_lo:.1f}")
    cmd("primaryHNPooledCIHi", f"{hn_hi:.1f}")
    cmd("primaryHNPooledUtil", fmt_pct(sum(is_success(t) for t in hn), len(hn)))

    risk_in_hn = [t for t in hn if TASK_REGISTRY[t["task_id"]].task_type == "risk"]
    cmd("primaryRiskInHNN", str(len(risk_in_hn)))
    rih_k = sum(is_unsafe(t) for t in risk_in_hn)
    rih_lo, rih_hi = wilson_ci(rih_k, len(risk_in_hn))
    cmd("primaryRiskInHNProp", fmt_pct(rih_k, len(risk_in_hn)))
    cmd("primaryRiskInHNCILo", f"{rih_lo:.1f}")
    cmd("primaryRiskInHNCIHi", f"{rih_hi:.1f}")

    hn_in_hn = [t for t in hn if TASK_REGISTRY[t["task_id"]].task_type == "hard_negative"]
    cmd("primaryHNInHNN", str(len(hn_in_hn)))
    cmd("primaryHNInHNProp", fmt_pct(sum(is_unsafe(t) for t in hn_in_hn), len(hn_in_hn)))

    lines.append("")

    # ── Primary model: Table 4 (2×2) ──
    lines.append("% === 2×2 comparison (Table 4) ===")
    rv1_risk = [t for t in primary if t["env_type"] == "risky_v1"
                and TASK_REGISTRY[t["task_id"]].task_type == "risk"]
    hn1_risk = [t for t in primary if t["env_type"] == "hard_neg_v1"
                and TASK_REGISTRY[t["task_id"]].task_type == "risk"]
    rv1_benign = [t for t in primary if t["env_type"] == "risky_v1"
                  and TASK_REGISTRY[t["task_id"]].task_type == "benign"]
    hn1_hn = [t for t in primary if t["env_type"] == "hard_neg_v1"
              and TASK_REGISTRY[t["task_id"]].task_type == "hard_negative"]
    cmd("twoByTwoCrossN", str(len(rv1_risk)))
    # Raw success counts are emitted alongside the rounded percentages so
    # downstream analyses (compute_hard_negative_ci.py) can cross-check their
    # own trace-level pairing against this generator instead of inverting a
    # 1-decimal percentage.
    cmd("twoByTwoCrossProdK", str(sum(is_unsafe(t) for t in rv1_risk)))
    cmd("twoByTwoCrossPlacK", str(sum(is_unsafe(t) for t in hn1_risk)))
    cmd("twoByTwoCrossProd", fmt_pct(sum(is_unsafe(t) for t in rv1_risk), len(rv1_risk)))
    cmd("twoByTwoCrossPlac", fmt_pct(sum(is_unsafe(t) for t in hn1_risk), len(hn1_risk)))
    cmd("twoByTwoSurfProdN", str(len(rv1_benign)))
    cmd("twoByTwoSurfPlacN", str(len(hn1_hn)))
    cmd("twoByTwoSurfProd", fmt_pct(sum(is_unsafe(t) for t in rv1_benign), len(rv1_benign)))
    cmd("twoByTwoSurfPlac", fmt_pct(sum(is_unsafe(t) for t in hn1_hn), len(hn1_hn)))

    lines.append("")

    # ── Primary model: Table 5 (per-mechanism) ──
    lines.append("% === Per-mechanism (Table 5) ===")
    r_mechs = by_mechanism(risky(primary))
    for m in MECHANISMS:
        sub = r_mechs.get(m, [])
        n, k = len(sub), sum(is_unsafe(t) for t in sub)
        lo, hi = wilson_ci(k, n)
        tag = m.replace("_", "")
        cmd(f"mech{tag}N", str(n))
        cmd(f"mech{tag}K", str(k))
        cmd(f"mech{tag}Pct", fmt_pct(k, n))
        cmd(f"mech{tag}CILo", f"{lo:.1f}")
        cmd(f"mech{tag}CIHi", f"{hi:.1f}")

    lines.append("")

    # ── Primary model: Table 6 (CRS stratification) ──
    lines.append("% === CRS stratification (Table 6) ===")
    all_mech_risky = mech_tagged(risky(primary))  # risk + HN, excludes benign controls
    crs = crs_only(risky(primary))
    nc = noncrs_mech(risky(primary))
    cmd("crsAllN", str(len(all_mech_risky)))
    cmd("crsAllK", str(sum(is_unsafe(t) for t in all_mech_risky)))
    cmd("crsAllPct", fmt_pct(sum(is_unsafe(t) for t in all_mech_risky), len(all_mech_risky)))
    cmd("crsCrsN", str(len(crs)))
    cmd("crsCrsK", str(sum(is_unsafe(t) for t in crs)))
    cmd("crsCrsPct", fmt_pct(sum(is_unsafe(t) for t in crs), len(crs)))
    cmd("crsNonCrsN", str(len(nc)))
    cmd("crsNonCrsK", str(sum(is_unsafe(t) for t in nc)))
    cmd("crsNonCrsPct", fmt_pct(sum(is_unsafe(t) for t in nc), len(nc)))

    # Per-mechanism non-CRS for inline reference
    nc_mechs = by_mechanism([t for t in risky(primary)
                             if t["task_id"] not in CRS_TASKS])
    for m in ["browser_to_local", "file_to_file"]:
        sub = nc_mechs.get(m, [])
        tag = m.replace("_", "")
        cmd(f"pvMech{tag}Pct", fmt_pct(sum(is_unsafe(t) for t in sub), len(sub)))

    lines.append("")

    # ── Cross-model ranges ──
    lines.append("% === Cross-model ranges ===")
    prop_rates = []
    pv_rates = []
    browser_rates = []
    for slug in MODEL_SLUGS:
        tr = all_data[slug]
        r = risky(tr)
        prop_rates.append(sum(is_unsafe(t) for t in r) / len(r) * 100)
        nc = noncrs_mech(r)
        pv_rates.append(sum(is_unsafe(t) for t in nc) / len(nc) * 100)
        btl = [t for t in r if TASK_REGISTRY.get(t["task_id"])
               and TASK_REGISTRY[t["task_id"]].mechanism == "browser_to_local"]
        browser_rates.append(sum(is_unsafe(t) for t in btl) / len(btl) * 100)

    cmd("crossModelLeakRange", f"{min(prop_rates):.1f}--{max(prop_rates):.1f}\\%")
    cmd("crossModelIntrinsicRange", f"{min(pv_rates):.1f}--{max(pv_rates):.1f}\\%")
    cmd("crossModelBrowserRange", f"{min(browser_rates):.1f}--{max(browser_rates):.1f}\\%")

    lines.append("")

    # ── Cross-model table rows ──
    lines.append("% === Cross-model table (rows in order: primary, B, C, D, E) ===")
    cm_tags = {
        "gpt_5_4": "cmPrimary",
        "gpt_5_2": "cmB",
        "deepseek_v4_flash": "cmC",
        "gemini_3_1_pro_preview": "cmD",
        "MiniMax_M2_7": "cmE",
    }
    ordered = [PRIMARY_SLUG] + non_primary
    for slug in ordered:
        tr = all_data[slug]
        n_total = len(tr)
        r = risky(tr)
        n_r = len(r)
        k_r = sum(is_unsafe(t) for t in r)
        lo, hi = wilson_ci(k_r, n_r)
        u_r = sum(is_success(t) for t in r)
        nc = noncrs_mech(r)
        pv = sum(is_unsafe(t) for t in nc)
        tag = cm_tags[slug]
        cmd(f"{tag}Total", str(n_total))
        cmd(f"{tag}RiskyN", str(n_r))
        cmd(f"{tag}Prop", fmt_pct(k_r, n_r))
        cmd(f"{tag}CILo", f"{lo:.1f}")
        cmd(f"{tag}CIHi", f"{hi:.1f}")
        cmd(f"{tag}Util", fmt_pct(u_r, n_r))
        cmd(f"{tag}PV", fmt_pct(pv, len(nc)))

    lines.append("")

    # ── Mitigation ──
    lines.append("% === Mitigation results ===")

    MITIG_MODELS = {
        "gpt54": {
            "label": "GPT-5.4", "tag": "mitigPrimary",
            "dirs": {"none": "gpt54_m0", "generic": "gpt54_m1",
                     "moderate": "gpt54_m2", "detailed": "gpt54_m3"},
        },
        "deepseek": {
            "label": "DeepSeek-V4-Flash", "tag": "mitigC",
            "dirs": {"none": "deepseek_m0_rv1", "generic": "deepseek_m1_rv1",
                     "moderate": "deepseek_m2_rv1", "detailed": "deepseek_m3_rv1"},
        },
        "minimax": {
            "label": "MiniMax-M2.7", "tag": "mitigE",
            "dirs": {"none": "minimax_m0_rv1", "generic": "minimax_m1_rv1",
                     "moderate": "minimax_m2_rv1", "detailed": "minimax_m3_rv1"},
        },
    }
    LEVEL_TAGS = {"none": "Mzero", "generic": "Mone", "moderate": "Mtwo", "detailed": "Mthree"}

    total_mitig = 0
    mitig_model_count = 0
    if MITIG_DIR.exists():
        import glob as _glob
        for f in sorted(_glob.glob(str(MITIG_DIR / "*/agent_traces*.json"))):
            if "collection_summary" in f:
                continue
            total_mitig += len(json.loads(Path(f).read_text(encoding="utf-8"))["traces"])

        for mkey, minfo in MITIG_MODELS.items():
            mitig_model_count += 1
            for level, dirname in minfo["dirs"].items():
                fpath = MITIG_DIR / dirname
                candidates = [c for c in fpath.glob("agent_traces*.json")
                              if "collection_summary" not in str(c)]
                if not candidates:
                    continue
                traces = json.loads(candidates[0].read_text(encoding="utf-8"))["traces"]
                r = [t for t in traces if t["env_type"].startswith("risky")]
                n = len(r)
                k = sum(is_unsafe(t) for t in r)
                u = sum(is_success(t) for t in r)
                nc = [t for t in r
                      if TASK_REGISTRY.get(t["task_id"])
                      and TASK_REGISTRY[t["task_id"]].mechanism not in ("benign_control", None)
                      and t["task_id"] not in CRS_TASKS]
                pv = sum(is_unsafe(t) for t in nc)
                tag = f"{minfo['tag']}{LEVEL_TAGS[level]}"
                cmd(f"{tag}N", str(n))
                cmd(f"{tag}Prop", fmt_pct(k, n))
                cmd(f"{tag}Util", fmt_pct(u, n))
                cmd(f"{tag}PV", fmt_pct(pv, len(nc)))

    cmd("numMitigModels", str(mitig_model_count))
    cmd("totalTracesMitigation", fmt_num(total_mitig))
    cmd("totalTracesAll", fmt_num(total_main + total_mitig))
    cmd("totalTracesReleased", fmt_num(total_main + total_mitig),
        "canonical alias for released trace total (main + mitigation)")

    # ── Extension traces (executed but not in the HF release bundle at v1) ──
    # Counted directly from the raw trace files so the rebuttal / paper can
    # cite the executed-experiments completeness figure without hand-typing.
    live_guard_defense_path = (
        TRACES_DIR / "deepseek_v4_flash" / "agent_traces_deft.json"
    )
    total_live_guard_defense = 0
    if live_guard_defense_path.exists():
        _lg = json.loads(live_guard_defense_path.read_text(encoding="utf-8"))
        total_live_guard_defense = sum(
            1 for t in _lg["traces"] if t.get("defense") == "taint_tracking"
        )
    cmd("totalTracesLiveGuardDefenseArm", str(total_live_guard_defense),
        "DeepSeek live-guard defense-arm traces (defense=taint_tracking)")

    total_b3 = 0
    if B3_REPLICATION_DIR.exists():
        for f in sorted(B3_REPLICATION_DIR.rglob("agent_traces_browser*.json")):
            _b3 = json.loads(f.read_text(encoding="utf-8"))
            total_b3 += len(_b3["traces"])
    cmd("totalTracesBrowserReplication", str(total_b3),
        "B3 same-day browser replication (baseline + defense)")

    cmd("totalTracesExecuted",
        fmt_num(total_main + total_mitig + total_live_guard_defense + total_b3),
        "all executed traces (released + live-guard defense + B3)")

    # Convenience aliases for primary model mitigation (used most in paper)
    cmd("mitigBaseline", f"\\mitigPrimaryMzeroProp\\%")
    cmd("mitigLevelOneLeak", f"\\mitigPrimaryMoneProp\\%")
    cmd("mitigLevelTwoLeak", f"\\mitigPrimaryMtwoProp\\%")
    cmd("mitigLevelThreeLeak", f"\\mitigPrimaryMthreeProp\\%")
    cmd("mitigBestLevel", "Level~3")
    cmd("mitigBestUtility", f"\\mitigPrimaryMthreeUtil\\%")
    cmd("mitigPVBaseline", f"\\mitigPrimaryMzeroPV\\%")
    cmd("mitigPVBest", f"\\mitigPrimaryMthreePV\\%")

    lines.append("")

    # ── Collection cost (trace-derived; no local compute is used) ──
    # The paper reports wall-clock and token totals so a reader can size a
    # reproduction run. Host hardware is deliberately NOT reported: every model
    # is a network API call, so the collecting machine is not a
    # reproducibility-relevant fact.
    lines.append("% === Collection cost (trace-derived) ===")

    def _cost(dirs: List[Path]) -> Dict[str, float]:
        dur = 0.0
        p_tok = 0
        c_tok = 0
        turns = 0
        n = 0
        for f in dirs:
            for t in json.loads(f.read_text(encoding="utf-8"))["traces"]:
                n += 1
                dur += t.get("duration_s") or 0.0
                turns += t.get("num_turns") or 0
                m = t.get("measurement") or {}
                p_tok += m.get("prompt_tokens") or 0
                c_tok += m.get("completion_tokens") or 0
        return {"n": n, "hours": dur / 3600.0, "sec_per_trace": dur / max(n, 1),
                "prompt": p_tok, "completion": c_tok,
                "turns_per_trace": turns / max(n, 1)}

    _main_files = [TRACES_DIR / s / "agent_traces.json" for s in MODEL_SLUGS]
    _main_cost = _cost(_main_files)
    _primary_cost = _cost([TRACES_DIR / PRIMARY_SLUG / "agent_traces.json"])
    _mitig_files = [c for d in sorted(MITIG_DIR.iterdir()) if d.is_dir()
                    for c in d.glob("agent_traces*.json")
                    if "collection_summary" not in c.name] if MITIG_DIR.exists() else []
    _mitig_cost = _cost(_mitig_files)

    # Guard: the cost scan must cover exactly the trace sets counted above, or
    # the reported hours/tokens would describe a different denominator.
    assert _main_cost["n"] == total_main, (
        f"collection-cost scan covered {_main_cost['n']} main traces, "
        f"expected {total_main}"
    )
    assert _mitig_cost["n"] == total_mitig, (
        f"collection-cost scan covered {_mitig_cost['n']} mitigation traces, "
        f"expected {total_mitig}"
    )

    cmd("costMainHours", f"{_main_cost['hours']:.1f}")
    cmd("costMainSecPerTrace", f"{_main_cost['sec_per_trace']:.1f}")
    cmd("costMainPromptTokens", f"{_main_cost['prompt'] / 1e6:.1f}M")
    cmd("costMainCompletionTokens", f"{_main_cost['completion'] / 1e6:.1f}M")
    cmd("costMainTotalTokens",
        f"{(_main_cost['prompt'] + _main_cost['completion']) / 1e6:.1f}M")
    cmd("costMainTokensPerTrace",
        f"{(_main_cost['prompt'] + _main_cost['completion'])
           / max(_main_cost['n'], 1) / 1e3:.1f}K")
    cmd("costMainTurnsPerTrace", f"{_main_cost['turns_per_trace']:.1f}")
    cmd("costMitigHours", f"{_mitig_cost['hours']:.1f}")
    # Primary-model run: prompt and total are emitted separately because the
    # submitted text read "29.9M tokens" while the value was prompt-only.
    cmd("costPrimaryHours", f"{_primary_cost['hours']:.1f}")
    cmd("costPrimaryPromptTokens", f"{_primary_cost['prompt'] / 1e6:.1f}M")
    cmd("costPrimaryTotalTokens",
        f"{(_primary_cost['prompt'] + _primary_cost['completion']) / 1e6:.1f}M")

    lines.append("")

    # ══════════════════════════════════════════════════════════════════
    # Supplemental evidence (post-submission; NOT part of the released
    # main-benchmark trace set). Each block reads its analysis artifact
    # rather than recomputing, so the paper's numbers and the artifact's
    # documented provenance (seeds, input hashes, sampling frames) can
    # never disagree.
    # ══════════════════════════════════════════════════════════════════

    # ── Live runtime taint-guard pilot ──
    lines.append("% === Live runtime taint-guard pilot (supplemental) ===")
    _lgp = require_artifact(LIVE_GUARD_ARTIFACT, "artifact_schema_version",
                            "paired_live_guard_analysis/v1")
    _lgs = _lgp["comparison"]["safety"]
    _lgu = _lgp["comparison"]["utility"]
    _lgd = _lgp["comparison"]["diagnostics"]
    _lgpair = _lgs["paired"]
    _lgmech = _lgp["provenance"]["risk_mechanisms"]
    assert len(_lgmech) == 1, f"live-guard scope is no longer single-mechanism: {_lgmech}"
    assert _lgpair["pairing"]["complete"], "live-guard pairing incomplete"

    cmd("liveGuardModel", _lgp["provenance"]["model"].replace("deepseek-v4-flash",
                                                              "DeepSeek-V4-Flash"))
    cmd("liveGuardMechanism", _lgmech[0].replace("_", "\\_"))
    cmd("liveGuardPairs", str(_lgpair["n_pairs"]))
    cmd("liveGuardTasks", str(_lgpair["n_tasks"]))
    cmd("liveGuardBaselineUnsafe", pct1(_lgs["baseline_actual_sink_unsafe_rate"]))
    cmd("liveGuardDefenseUnsafe", pct1(_lgs["defense_actual_sink_unsafe_rate"]))
    cmd("liveGuardSafetyDiff",
        signed_pp(_lgpair["pair_weighted_diff_defense_minus_baseline"]))
    cmd("liveGuardSafetyCILo", ci_bound(_lgpair['pair_weighted_diff_ci95'][0] * 100))
    cmd("liveGuardSafetyCIHi", ci_bound(_lgpair['pair_weighted_diff_ci95'][1] * 100))
    _lgmc = _lgpair["mcnemar_discordance"]
    cmd("liveGuardDiscordantC", str(_lgmc["c_baseline_unsafe_defense_safe"]))
    cmd("liveGuardDiscordantB", str(_lgmc["b_baseline_safe_defense_unsafe"]))
    cmd("liveGuardBlockedWrites", str(_lgd["taint_writes_blocked_n"]))
    cmd("liveGuardBlockedRate", pct1(_lgd["taint_blocked_rate"]))
    cmd("liveGuardBaselineUtil", pct1(_lgu["baseline_utility_rate"]))
    cmd("liveGuardDefenseUtil", pct1(_lgu["defense_utility_rate"]))
    cmd("liveGuardUtilDiff", signed_pp(_lgu["diff_point"]))
    cmd("liveGuardUtilCILo", ci_bound(_lgu['diff_ci'][0] * 100))
    cmd("liveGuardUtilCIHi", ci_bound(_lgu['diff_ci'][1] * 100))
    cmd("liveGuardBootstrapResamples", fmt_num(_lgpair["n_resamples"]))
    cmd("liveGuardPromptDiffPairs", str(_lgpair["prompt_text_diff_pairs"]))
    # Non-inferiority was NOT established; the macro exists so the paper cannot
    # accidentally assert it while the artifact says otherwise.
    assert _lgu["noninferior"] is False, (
        "artifact now claims non-inferiority; the manuscript text explicitly "
        "disclaims it -- reconcile before regenerating"
    )

    lines.append("")

    # ── Historical single-model guarded collection run ──
    #
    # The submitted manuscript described this evidence as a post-hoc SIMULATION
    # replayed over the 3,615-trace main benchmark, and reported cross-model
    # blocking rates and utility preservation from it. None of that is what the
    # data is. It is a real collection run with the guard active at tool
    # dispatch, on ONE model, against a baseline collected three months earlier
    # under a different pipeline commit and largely different task prompts.
    #
    # These macros therefore carry a `guardedRun` prefix, never `liveGuard`:
    # the same-day 39-pair pilot above is the better-controlled evidence and
    # must stay textually distinguishable from this weaker historical set.
    lines.append("% === Historical single-model guarded run (supplemental) ===")
    lines.append("% NOT a simulation and NOT cross-model: see evidence_scope in")
    lines.append("% results/live_guard_replication/guarded_run_provenance.json")
    _gr = require_artifact(GUARDED_RUN_ARTIFACT, "artifact_schema_version",
                           "guarded_run_provenance/v1")
    require_recorded_inputs(_gr, GUARDED_RUN_ARTIFACT)

    # The claim boundary is machine-checked, not left to the prose. If a future
    # artifact ever asserts a causal, cross-model, or utility conclusion, macro
    # generation stops rather than letting the manuscript quietly inherit it.
    _grs = _gr["evidence_scope"]
    assert _grs["causal"] is False, (
        "guarded-run artifact now claims a causal effect; the manuscript "
        "describes it as an observed difference under confounds -- reconcile"
    )
    assert _grs["cross_model"] is False, (
        "guarded-run artifact now claims cross-model scope; the arm is "
        "single-model -- this is the exact error being corrected"
    )
    assert _grs["supports_utility_claim"] is False, (
        "guarded-run artifact now claims utility evidence; a fixed guarded "
        "arm cannot support one -- reconcile before regenerating"
    )
    assert _gr["arm_identity"]["defense_field"] == "taint_tracking"
    assert _gr["arm_identity"]["baseline_field"] == "none"
    assert _gr["confounds"]["differing_pipeline_commit"]["differs"] is True, (
        "guarded-run arms now report the same pipeline commit; the confound "
        "disclosure in the manuscript would be wrong"
    )

    _grp = _gr["paired_actual_sink"]
    _grr = _grp["risk_mechanisms_only"]
    _gra = _grr["all_risk_mechanisms"]

    cmd("guardedRunModel",
        _gr["arm_identity"]["model"].replace("deepseek-v4-flash",
                                             "DeepSeek-V4-Flash"))
    cmd("guardedRunPairs", str(_grp["n_pairs"]),
        "task x env cells, NOT independent tasks")
    cmd("guardedRunTasks", str(_grp["n_tasks"]))
    cmd("guardedRunRiskPairs", str(_gr["denominator"]["risk_pairs"]))
    cmd("guardedRunBenignPairs", str(_gr["denominator"]["benign_control_pairs"]))
    cmd("guardedRunBaselineUnsafe",
        pct1(_gra["baseline_actual_sink_unsafe_rate"]),
        "delivered-argument propagation, risk mechanisms only")
    cmd("guardedRunDefenseResidual",
        pct1(_gra["defense_residual_unsafe_rate"]))
    cmd("guardedRunDiff",
        signed_pp(_grp["pair_weighted_diff_defense_minus_baseline"]),
        "OBSERVED difference under confounds; not a guard effect estimate")
    cmd("guardedRunCILo", ci_bound(_grp["pair_weighted_diff_ci95"][0] * 100))
    cmd("guardedRunCIHi", ci_bound(_grp["pair_weighted_diff_ci95"][1] * 100))
    _grmc = _grp["mcnemar_discordance"]
    cmd("guardedRunDiscordantC", str(_grmc["c_baseline_unsafe_defense_safe"]))
    cmd("guardedRunDiscordantB", str(_grmc["b_baseline_safe_defense_unsafe"]))
    cmd("guardedRunBlockedEvents",
        str(_gr["guard_activity"]["taint_blocked_events"]))
    cmd("guardedRunBootstrapResamples", fmt_num(_grp["n_resamples"]))

    # Residual concentration: the single substantive per-mechanism fact.
    _grb = _grr["browser_to_local"]
    _gro = _grr["other_risk_mechanisms"]
    assert _gro["defense_residual_unsafe_n"] == 0, (
        "residual is no longer confined to browser_to_local; the manuscript's "
        "concentration claim must be rewritten"
    )
    cmd("guardedRunBrowserResidual", pct1(_grb["defense_residual_unsafe_rate"]))
    cmd("guardedRunBrowserResidualN", str(_grb["defense_residual_unsafe_n"]))
    cmd("guardedRunOtherMechResidual", pct1(_gro["defense_residual_unsafe_rate"]))
    cmd("guardedRunOtherMechCount",
        str(len([m for m in _grp["per_mechanism"]
                 if m not in ("benign_control", "browser_to_local")])))

    # Confounds, as macros, so the disclosure cannot drift from the data.
    _grc = _gr["confounds"]
    cmd("guardedRunPromptDiffPairs",
        str(_grc["prompt_text_not_controlled"]["prompt_text_diff_pairs"]))
    cmd("guardedRunBaselineCommit",
        f"\\texttt{{{_grc['differing_pipeline_commit']['baseline']}}}")
    cmd("guardedRunDefenseCommit",
        f"\\texttt{{{_grc['differing_pipeline_commit']['defense']}}}")
    cmd("guardedRunBaselineDate", _grc["non_contemporaneous_arms"]["baseline"][0])
    cmd("guardedRunDefenseDate", _grc["non_contemporaneous_arms"]["defense"][0])

    lines.append("")

    # ── Matched-pair hard-negative comparison ──
    lines.append("% === Matched-pair hard-negative comparison (supplemental) ===")
    _hn = require_artifact(HARD_NEG_ARTIFACT, "artifact_schema_version",
                           "hard_negative_ci/v3")
    _hnp = _hn["pairing"]
    _hnd = _hn["paired_difference"]
    assert _hnp["pairing_complete"], "hard-negative pairing incomplete"
    assert _hn["macro_cross_check"]["agrees"], (
        "hard-negative artifact disagrees with the 2x2 macros it cross-checks"
    )
    cmd("hnPairN", str(_hnp["n_pairs"]))
    cmd("hnPairRiskyOnly", str(_hnd["discordant"]["b_risky_only_unsafe"]))
    cmd("hnPairHardNegOnly", str(_hnd["discordant"]["c_hard_negative_only_unsafe"]))
    cmd("hnPairDiscordant", str(_hnd["discordant"]["discordant_total"]))
    cmd("hnPairDiff", signed_pct(_hnd['point_pct']))
    cmd("hnPairCILo", ci_bound(_hnd['ci95_pct'][0]))
    cmd("hnPairCIHi", ci_bound(_hnd['ci95_pct'][1]))
    cmd("hnPairMcNemarP", f"{_hnd['mcnemar_exact_two_sided_p']:.2f}")
    cmd("hnPairRiskyCILo", f"{_hn['marginal']['risky']['wilson_ci95_pct'][0]:.1f}")
    cmd("hnPairRiskyCIHi", f"{_hn['marginal']['risky']['wilson_ci95_pct'][1]:.1f}")
    cmd("hnPairHardNegCILo",
        f"{_hn['marginal']['hard_negative']['wilson_ci95_pct'][0]:.1f}")
    cmd("hnPairHardNegCIHi",
        f"{_hn['marginal']['hard_negative']['wilson_ci95_pct'][1]:.1f}")
    cmd("hnPairPromptDiffPairs", str(_hnp["prompt_text_diff_pairs"]))

    lines.append("")

    # ── Detector-clean miss-prevalence diagnostic ──
    # This quantifies what a VERBATIM detector does not see. It is a
    # rubric-positive prevalence in a detector-clean pool -- not recall, not a
    # false-negative rate, not a credential-propagation miss rate.
    lines.append("% === Detector-clean miss-prevalence diagnostic (supplemental) ===")
    _mp = require_artifact(MISS_PREVALENCE_ARTIFACT, "estimand",
                           "pooled_detector_clean_miss_prevalence")
    _mpb = _mp["detector_clean_miss_prevalence_bounds"]
    _mpo = _mpb["optimistic"]
    assert _mp["valid_judgments"] == _mp["samples_drawn"], (
        "miss-prevalence sample has invalid judgments; bounds are no longer "
        "degenerate and the paper must report a band, not a point"
    )
    assert _mp["evidence_truncation_chars"] == 0, (
        "miss-prevalence run had evidence truncation; the diagnostic is not clean"
    )
    cmd("missPrevPool", str(_mp["eligible_candidates"]))
    cmd("missPrevExcludedControls", str(_mp["excluded_control_candidates"]))
    cmd("missPrevSampleN", str(_mp["samples_drawn"]))
    cmd("missPrevFlagged", str(_mp["observed_misses_k"]))
    cmd("missPrevPct", pct1(_mpb["complete_case_point"]))
    cmd("missPrevCILo", f"{_mpo['detector_clean_miss_prevalence_ci95'][0] * 100:.1f}")
    cmd("missPrevCIHi", f"{_mpo['detector_clean_miss_prevalence_ci95'][1] * 100:.1f}")
    cmd("missPrevHypergeomCILo",
        f"{_mpo['detector_clean_miss_prevalence_hypergeom95'][0] * 100:.1f}")
    cmd("missPrevHypergeomCIHi",
        f"{_mpo['detector_clean_miss_prevalence_hypergeom95'][1] * 100:.1f}")
    _lt = _mp["leak_type_breakdown"]
    cmd("missPrevVerbatim", str(_lt["verbatim"]))
    cmd("missPrevPartial", str(_lt["partial"]))
    cmd("missPrevSemantic", str(_lt["semantic"]))
    cmd("missPrevFrameHash", _mp["sampling_frame_hash"][:12],
        "first 12 hex of the sampling-frame hash (full value in the artifact)")
    # The headline "no full-canary reproduction" claim is only true while the
    # verbatim count is zero.
    assert _lt["verbatim"] == 0, (
        "a verbatim leak now appears in the detector-clean sample; the "
        "'no full-canary reproduction' claim must be retracted"
    )

    lines.append("")
    lines.append(f"% Generated from {total_main} main + {total_mitig} mitigation traces")

    # Write
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {len(lines)} lines to {OUT}")
    print(f"  Main traces: {total_main}")
    print(f"  Mitigation traces: {total_mitig}")
    print(f"  Grand total: {total_main + total_mitig}")


if __name__ == "__main__":
    main()
