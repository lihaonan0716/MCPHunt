#!/usr/bin/env python3
r"""
Generate paper/results_tables.tex: the data rows of every result table.

Motivation (invariant #1). ``generate_results_macros.py`` covers scalars that
appear in prose and in the small main-text tables, but roughly 290 result cells
across ten larger tables were still typed by hand. Hand-typed cells are
unauditable: a reader cannot tell which numbers were recomputed and which were
transcribed, and a transcription slip survives every test we have. This script
closes that gap by emitting the rows themselves.

Division of labour follows ``generate_grounding_tables.py``: this script emits
ROW MACROS ONLY. Column specifications, headers, rules, captions, and float
placement stay in the ``.tex`` files, because those are typesetting decisions,
not data. The paper writes

    \begin{tabular}{@{}lrrcrrc@{}}
    ... header ...
    \CrsMechanismRows
    \end{tabular}

Macros emitted (one per table; see TABLES below for the authoritative list):

* ``\MitigationCrossRows``      -- Table 7  (cross-model mitigation, risky_v1)
* ``\CrsMechanismRows``         -- Table 13 (per-mechanism CRS stratification)
* ``\CrsMechanismTotalRow``     -- Table 13 total line
* ``\MechanismHeterogeneityRows`` -- Table 14 (risky vs control + Fisher)
* ``\QuadrantRows``             -- Table 16 (outcome quadrants)
* ``\QuadrantTotalRow``         -- Table 16 total line
* ``\MultiModelAggregateRows``  -- Table 17 (per-model aggregate + CRS)
* ``\MultiModelMechanismRows``  -- Table 18 (mechanism x model)
* ``\MultiModelSignalRows``     -- Table 19 (signal counts x model)
* ``\OddsRatioMechanismRows``   -- Table 20 (GEE mechanism ORs)
* ``\OddsRatioModelRows``       -- Table 20 (GEE model ORs)
* ``\MitigationAggregateRows``  -- Table 21 (mitigation levels)
* ``\MitigationMechanismRows``  -- Table 22 (mechanism x mitigation level)

Run after any data or labeling change:

    PYTHONPATH=src python3 scripts/generate_results_tables.py

The output is an auto-generated build product (gitignored, like
``results_macros.tex``) -- never hand-edit it.
"""
from __future__ import annotations

import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Callable, Dict, List, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcphunt.labeling import (
    STRICT_LEAKAGE_SIGNALS,
    TAINTED_BOUNDARY_SIGNALS,
    NETWORK_RISK_SIGNALS,
)
from mcphunt.taxonomy import (
    RISK_TASKS, HN_TASKS, CRS_TASKS, TASK_REGISTRY,
)

REPO = Path(__file__).resolve().parents[1]
TRACES_DIR = REPO / "results" / "agent_traces"
MITIG_DIR = REPO / "results" / "mitigation_traces"
OUT = REPO / "paper" / "results_tables.tex"

PRIMARY_SLUG = "gpt_5_4"

# Display order and labels are shared with generate_results_macros.py and
# reproduce_paper_tables.py. Kept as literals rather than imported so a future
# reordering in one script cannot silently reshuffle the paper's table rows.
MODEL_SLUGS = {
    "gpt_5_4": "GPT-5.4",
    "gpt_5_2": "GPT-5.2",
    "deepseek_v4_flash": "DeepSeek-V4-Flash",
    "gemini_3_1_pro_preview": "Gemini-3.1-Pro",
    "MiniMax_M2_7": "MiniMax-M2.7",
}

# Canonical mechanism display order: descending primary-model risky propagation
# rate, matching Table 5's "Mechanisms are ordered by rate" caption. Shared by
# every mechanism-indexed table so a reader can scan across tables on one axis.
#
# The submitted Tables 18 and 22 deviated from this: config_to_script sat
# between file_to_doc and indirect_exposure, i.e. an 8th-place row carrying a
# 4th/5th-place rate. No caption stated an alternative rule and the order is not
# the registry order either, so it was a transcription slip, not a convention.
# Regenerating puts those two tables back on the stated rule.
MECH_ORDER = [
    "browser_to_local", "forced_multi_hop", "file_to_file", "db_to_artifact",
    "config_to_script", "git_history_leak", "sensitive_to_shell", "file_to_doc",
    "indirect_exposure",
]

MECH_IDS = RISK_TASKS | HN_TASKS
ALL_SIGNALS = sorted(
    STRICT_LEAKAGE_SIGNALS | TAINTED_BOUNDARY_SIGNALS | NETWORK_RISK_SIGNALS
)

MITIG_LEVELS_PRIMARY = {
    "None (baseline)": "gpt54_m0",
    "Level~1 (generic)": "gpt54_m1",
    "Level~2 (specific)": "gpt54_m2",
    "Level~3 (boundary)": "gpt54_m3",
}

# Cross-model mitigation (Table 7). GPT-5.4 uses the pooled-sweep directories;
# the other two models were run on risky_v1 only.
MITIG_CROSS = {
    "gpt_5_4": {"M0": "gpt54_m0", "M1": "gpt54_m1",
                "M2": "gpt54_m2", "M3": "gpt54_m3"},
    "deepseek_v4_flash": {"M0": "deepseek_m0_rv1", "M1": "deepseek_m1_rv1",
                          "M2": "deepseek_m2_rv1", "M3": "deepseek_m3_rv1"},
    "MiniMax_M2_7": {"M0": "minimax_m0_rv1", "M1": "minimax_m1_rv1",
                     "M2": "minimax_m2_rv1", "M3": "minimax_m3_rv1"},
}

CONTROL_ENVS = ("benign", "hard_neg_v1", "hard_neg_v2", "hard_neg_v3")


# ── Trace predicates (identical semantics to reproduce_paper_tables.py) ──

def leaked(t: Dict) -> bool:
    return t.get("outcome", "").startswith("unsafe")


def util(t: Dict) -> bool:
    return t.get("outcome", "") in ("safe_success", "unsafe_success")


def load_traces(slug: str) -> List[Dict]:
    return json.loads(
        (TRACES_DIR / slug / "agent_traces.json").read_text(encoding="utf-8")
    )["traces"]


def load_mitig(dirname: str) -> List[Dict]:
    d = MITIG_DIR / dirname
    files = [c for c in sorted(d.glob("agent_traces*.json"))
             if "collection_summary" not in c.name]
    if not files:
        raise SystemExit(f"ERROR: no trace file in {d.relative_to(REPO)}")
    return json.loads(files[0].read_text(encoding="utf-8"))["traces"]


def risky(traces: Sequence[Dict]) -> List[Dict]:
    return [t for t in traces if t["env_type"].startswith("risky")]


def mech_tagged(traces: Sequence[Dict]) -> List[Dict]:
    return [t for t in traces
            if TASK_REGISTRY.get(t["task_id"])
            and TASK_REGISTRY[t["task_id"]].mechanism not in ("benign_control", None)]


def by_mechanism(traces: Sequence[Dict]) -> Dict[str, List[Dict]]:
    out: Dict[str, List[Dict]] = defaultdict(list)
    for t in traces:
        td = TASK_REGISTRY.get(t["task_id"])
        if td and td.mechanism not in ("benign_control", None):
            out[td.mechanism].append(t)
    return out


# ── Formatting ──────────────────────────────────────────────────────
#
# The submitted tables used \phantom{0} to right-align ragged numbers inside
# left-aligned columns. Reproducing that by hand per cell is what made the
# tables unauditable, so padding is computed here from the actual column
# contents instead of being typed.

def tex_tt(name: str) -> str:
    """Typeset an identifier as \\texttt with escaped underscores."""
    return "\\texttt{" + name.replace("_", "\\_") + "}"


def pct(num: int, den: int) -> str:
    return "0.0" if den == 0 else f"{num / den * 100:.1f}"


def _unescape(cell: str) -> str:
    """Reduce LaTeX markup to the glyphs it renders."""
    c = re.sub(r"\\textbf\{(.*?)\}", r"\1", cell)
    c = re.sub(r"\\texttt\{(.*?)\}", r"\1", c)
    c = c.replace("\\%", "%").replace("\\_", "_")
    c = c.replace("$-$", "-").replace("$+$", "+").replace("$\\pm$", "±")
    c = c.replace("$<$", "<").replace("$>$", ">")
    c = c.replace("\\,", " ").replace("~", " ").replace("{,}", ",")
    return c


def visible_width(cell: str) -> int:
    """Width of a cell's own content, ignoring any padding already present.

    ``len()`` would score ``100.0\\%`` as 7 and ``n/a`` as 3, over-padding the
    latter, because the two-character escape ``\\%`` renders as one glyph.
    Math-mode signs have the same problem. ``\\phantom`` is excluded so that
    padding an already-padded cell is a no-op rather than compounding.
    """
    return len(_unescape(re.sub(r"\\phantom\{[^}]*\}", "", cell)))


def box_width(cell: str) -> int:
    """Width of the rendered box, counting padding.

    ``\\phantom{000}`` reserves exactly three digit widths, so it contributes to
    the box even though nothing is drawn. This is the measure that must be equal
    across a centred column for the cells to line up.
    """
    phantom = sum(len(m) for m in re.findall(r"\\phantom\{([^}]*)\}", cell))
    return phantom + visible_width(cell)


def pad(cells: Sequence[str], align: str = "c") -> List[str]:
    """Left-pad each cell with \\phantom{0} so a centred column aligns.

    Padding is only correct in CENTRED (``c``) columns, where ragged cell widths
    shift each entry independently: making every cell the same box width lets
    centring line them up. This is why the submitted tables carried hand-written
    phantoms; here the width is derived from the data instead of typed.

    In ``r`` columns the digits already align on the right edge, so padding is
    redundant, and in ``l`` columns it would indent the cell away from the
    column edge -- actively wrong. Callers pass the real column type and get the
    cells back untouched in those cases.
    """
    if not cells or align != "c":
        return list(cells)
    # Compare BOX widths so padding an already-padded column is a no-op: using
    # content width would re-pad every cell on a second pass and compound the
    # indent.
    width = max(box_width(c) for c in cells)
    out = []
    for c in cells:
        deficit = width - box_width(c)
        out.append("\\phantom{" + "0" * deficit + "}" + c if deficit else c)
    return out


def emit(lines: List[str], name: str, rows: Sequence[str],
         comment: str = "") -> None:
    """Emit a row-macro definition holding ``rows`` as tabular lines."""
    if comment:
        lines.append(f"% {comment}")
    lines.append("\\newcommand{\\" + name + "}{%")
    lines.extend(rows)
    lines.append("}")
    lines.append("")


def emit_scalar(lines: List[str], name: str, value: str,
                comment: str = "") -> None:
    """Emit a single-value macro on one line.

    Scalars must NOT go through emit(): a multi-line body leaves a newline before
    the closing brace, which LaTeX turns into a trailing space -- visible as
    ``1,440 traces`` gaining a double space mid-sentence.
    """
    c = f"  % {comment}" if comment else ""
    lines.append("\\newcommand{\\" + name + "}{" + value + "}" + c)
    lines.append("")


# ── Table builders ──────────────────────────────────────────────────

def table_mitigation_cross(lines: List[str]) -> None:
    """Table 7: cross-model mitigation on risky_v1, risk tasks only.

    Relative reduction is computed against each model's OWN M0 baseline, as the
    caption states, and from UNROUNDED rates. That choice is load-bearing: for
    MiniMax M1 the exact ratio is -5.4545% (rounds to -5%, matching the submitted
    table) while recomputing from the displayed 1-decimal rates gives -5.5010%
    (rounds to -6%). Deriving from displayed values would change a published
    digit, so rates are rounded only for display, never before arithmetic.
    """
    rows = []
    for slug, levels in MITIG_CROSS.items():
        rates = {}
        for lname, dirname in levels.items():
            tr = [t for t in load_mitig(dirname)
                  if t.get("env_type") == "risky_v1" and t.get("task_id") in RISK_TASKS]
            k = sum(1 for t in tr if leaked(t))
            rates[lname] = (k, len(tr))
        base_k, base_n = rates["M0"]
        base_rate = base_k / base_n * 100 if base_n else 0.0
        cells = [f"{base_rate:.1f}\\%"]
        for lname in ("M1", "M2", "M3"):
            k, n = rates[lname]
            r = k / n * 100 if n else 0.0
            if base_rate == 0:
                rel = "n/a"
            else:
                d = round((r - base_rate) / base_rate * 100)
                rel = ("$\\pm$0\\%" if d == 0
                       else f"$-${abs(d)}\\%" if d < 0 else f"$+${d}\\%")
            cells.append(f"{r:.1f}\\% ({rel})")
        rows.append(f"\\model{model_letter(slug)}{{}} & " + " & ".join(cells) + " \\\\")
    emit(lines, "MitigationCrossRows", rows,
         "Table 7: cross-model mitigation, risky_v1 risk tasks; "
         "relative reduction vs each model's own M0")


def model_letter(slug: str) -> str:
    """Map a model slug to the \\modelX macro suffix used in the paper."""
    if slug == PRIMARY_SLUG:
        return "Primary"
    order = [s for s in MODEL_SLUGS if s != PRIMARY_SLUG]
    return chr(ord("B") + order.index(slug))


def table_crs_mechanism(lines: List[str], primary: List[Dict]) -> None:
    """Table 13: per-mechanism CRS / non-CRS stratification (primary model).

    Sorted by policy-violating rate, as the caption states. "n/a" marks
    mechanisms with zero CRS tasks -- a design fact, not a missing measurement.
    """
    mechs = by_mechanism(risky(primary))
    recs = []
    for m in MECH_ORDER:
        sub = mechs.get(m, [])
        crs = [t for t in sub if t["task_id"] in CRS_TASKS]
        non = [t for t in sub if t["task_id"] not in CRS_TASKS]
        recs.append({
            "m": m,
            "crs_n": len(crs),
            "crs_pct": pct(sum(1 for t in crs if leaked(t)), len(crs)) if crs else None,
            "non_n": len(non),
            "non_pct": pct(sum(1 for t in non if leaked(t)), len(non)),
            "all_pct": pct(sum(1 for t in sub if leaked(t)), len(sub)),
        })
    recs.sort(key=lambda r: float(r["non_pct"]), reverse=True)

    # Bold the two mechanisms the appendix prose contrasts: the highest
    # policy-violating rate, and the lowest rate among mechanisms that HAVE CRS
    # tasks (the file_to_file vs its own CRS rate comparison). Bolding every row
    # tied at 0.0% would mark indirect_exposure too, which has no CRS tasks and
    # is therefore not part of that contrast.
    emph = {max(recs, key=lambda r: float(r["non_pct"]))["m"]}
    with_crs = [r for r in recs if r["crs_n"] > 0]
    if with_crs:
        emph.add(min(with_crs, key=lambda r: float(r["non_pct"]))["m"])

    # Column spec is lrrcrrc: the two rate columns are r-aligned (no padding
    # needed), the Overall column is centred (padding needed).
    non_cells = pad([f"{r['non_pct']}\\%" for r in recs], align="r")
    all_cells = pad([f"{r['all_pct']}\\%" for r in recs], align="c")
    crs_cells = pad([(f"{r['crs_pct']}\\%" if r["crs_pct"] is not None else "n/a")
                     for r in recs], align="r")
    rows = []
    for r, crs_c, non_c, all_c in zip(recs, crs_cells, non_cells, all_cells):
        non_disp = f"\\textbf{{{non_c}}}" if r["m"] in emph else non_c
        rows.append(f"{tex_tt(r['m'])} & {r['crs_n']} & {crs_c} & & "
                    f"{r['non_n']} & {non_disp} & {all_c} \\\\")
    emit(lines, "CrsMechanismRows", rows,
         "Table 13: per-mechanism CRS stratification, sorted by policy-violating rate")

    mr = mech_tagged(risky(primary))
    crs = [t for t in mr if t["task_id"] in CRS_TASKS]
    non = [t for t in mr if t["task_id"] not in CRS_TASKS]
    emit(lines, "CrsMechanismTotalRow", [
        f"\\textbf{{All mechanisms}} & {len(crs)} & "
        f"{pct(sum(1 for t in crs if leaked(t)), len(crs))}\\% & & {len(non)} & "
        f"{pct(sum(1 for t in non if leaked(t)), len(non))}\\% & "
        f"{pct(sum(1 for t in mr if leaked(t)), len(mr))}\\% \\\\"
    ], "Table 13 total line")


def table_mechanism_heterogeneity(lines: List[str], primary: List[Dict],
                                  fisher: Callable[[int, int, int, int], float]) -> None:
    """Table 14: risky vs control propagation per mechanism, with Fisher's exact p."""
    r_mechs = by_mechanism(risky(primary))
    c_mechs = by_mechanism([t for t in primary if t["env_type"] in CONTROL_ENVS])

    recs = []
    for m in MECH_ORDER:
        rs, cs = r_mechs.get(m, []), c_mechs.get(m, [])
        rk, ck = sum(1 for t in rs if leaked(t)), sum(1 for t in cs if leaked(t))
        rr = rk / len(rs) * 100 if rs else 0.0
        cr = ck / len(cs) * 100 if cs else 0.0
        p = fisher(rk, len(rs) - rk, ck, len(cs) - ck)
        recs.append({"m": m, "rr": rr, "cr": cr, "d": rr - cr, "p": p})
    recs.sort(key=lambda r: r["rr"], reverse=True)

    r_cells = pad([f"{r['rr']:.1f}\\%" for r in recs])
    c_cells = pad([f"{r['cr']:.1f}\\%" for r in recs])
    d_cells = pad([f"$+${r['d']:.1f} pp" if r["d"] >= 0 else f"$-${abs(r['d']):.1f} pp"
                   for r in recs])
    p_cells = pad([("$<$0.001" if r["p"] < 0.001 else f"{r['p']:.3f}") for r in recs])
    rows = []
    for r, rc, cc, dc, pc in zip(recs, r_cells, c_cells, d_cells, p_cells):
        sig = ("***" if r["p"] < 0.001 else "**" if r["p"] < 0.01
               else "*" if r["p"] < 0.05 else "")
        rows.append(f"{tex_tt(r['m'])} & {rc} & {cc} & {dc} & {pc} & {sig} \\\\")
    emit(lines, "MechanismHeterogeneityRows", rows,
         "Table 14: risky vs control per mechanism, two-sided Fisher's exact")


def table_quadrants(lines: List[str], primary: List[Dict]) -> None:
    """Table 16: outcome quadrant distribution by environment class."""
    groups = [
        ("Risky", risky(primary)),
        ("Benign", [t for t in primary if t["env_type"] == "benign"]),
        ("Hard-neg", [t for t in primary if t["env_type"].startswith("hard_neg")]),
    ]

    def quad(sub: Sequence[Dict]) -> Dict[str, int]:
        return {k: sum(1 for t in sub if t.get("outcome") == k)
                for k in ("safe_success", "unsafe_success",
                          "safe_failure", "unsafe_failure")}

    recs = [(label, len(sub), quad(sub)) for label, sub in groups]
    cols = {k: pad([f"{q[k]} ({pct(q[k], n)}\\%)" for _, n, q in recs])
            for k in ("safe_success", "unsafe_success",
                      "safe_failure", "unsafe_failure")}
    util_cells = pad([
        f"{pct(q['safe_success'] + q['unsafe_success'], n)}\\%" for _, n, q in recs
    ])
    rows = []
    for i, (label, n, _q) in enumerate(recs):
        cells = [cols[k][i] for k in ("safe_success", "unsafe_success",
                                      "safe_failure", "unsafe_failure")]
        rows.append(f"{label} & {n} & " + " & ".join(cells)
                    + f" & {util_cells[i]} \\\\")
    emit(lines, "QuadrantRows", rows, "Table 16: outcome quadrants by environment")

    n = len(primary)
    q = quad(primary)
    cells = [f"{q[k]} ({pct(q[k], n)}\\%)" for k in ("safe_success", "unsafe_success",
                                                     "safe_failure", "unsafe_failure")]
    emit(lines, "QuadrantTotalRow", [
        f"\\textbf{{All}} & {n} & " + " & ".join(cells)
        + f" & {pct(q['safe_success'] + q['unsafe_success'], n)}\\% \\\\"
    ], "Table 16 total line")


def table_multi_model_aggregate(lines: List[str], all_data: Dict[str, List[Dict]],
                                wilson: Callable[[int, int], tuple]) -> None:
    """Table 17: per-model aggregate with separate policy-violating and CRS columns."""
    rows = []
    for slug in MODEL_SLUGS:
        r = risky(all_data[slug])
        mr = mech_tagged(r)
        crs = [t for t in mr if t["task_id"] in CRS_TASKS]
        non = [t for t in mr if t["task_id"] not in CRS_TASKS]
        k = sum(1 for t in r if leaked(t))
        lo, hi = wilson(k, len(r))
        rows.append(
            f"\\model{model_letter(slug)}{{}} & {len(r)} & {pct(k, len(r))}\\% & "
            f"[{lo:.1f}, {hi:.1f}] & {pct(sum(1 for t in r if util(t)), len(r))}\\% & "
            f"{pct(sum(1 for t in non if leaked(t)), len(non))}\\% & "
            f"{pct(sum(1 for t in crs if leaked(t)), len(crs))}\\% \\\\"
        )
    emit(lines, "MultiModelAggregateRows", rows,
         "Table 17: per-model aggregate, policy-violating and CRS columns")


def table_multi_model_mechanism(lines: List[str],
                                all_data: Dict[str, List[Dict]]) -> None:
    """Table 18: propagation per mechanism x model, as propagated/total + rate."""
    grid = {}
    for slug in MODEL_SLUGS:
        mechs = by_mechanism(risky(all_data[slug]))
        for m in MECH_ORDER:
            sub = [t for t in mechs.get(m, []) if t.get("task_id") in MECH_IDS]
            k = sum(1 for t in sub if leaked(t))
            grid[(m, slug)] = (k, len(sub))

    # Pad per column so every model column aligns independently.
    cols = {}
    for slug in MODEL_SLUGS:
        cols[slug] = pad([f"{grid[(m, slug)][0]}/{grid[(m, slug)][1]} "
                          f"{pct(*grid[(m, slug)])}\\%" for m in MECH_ORDER])
    rows = []
    for i, m in enumerate(MECH_ORDER):
        rows.append(f"{tex_tt(m)} & "
                    + " & ".join(cols[s][i] for s in MODEL_SLUGS) + " \\\\")
    emit(lines, "MultiModelMechanismRows", rows,
         "Table 18: propagated/total and rate per mechanism x model")


def table_signals_primary(lines: List[str], primary: List[Dict]) -> None:
    """Table 15: per-signal counts with tier, primary model, risky environments.

    Also emits the caption's list of zero-count signals, so the caption cannot
    claim a signal was silent after the data says otherwise.
    """
    r = risky(primary)
    counts = {s: sum(1 for t in r if t["labeling"]["risk_signals"].get(s))
              for s in ALL_SIGNALS}
    # Descending count, then name: the name tiebreak is what keeps this table's
    # order reproducible and consistent with Table 19.
    shown = sorted((s for s in ALL_SIGNALS if counts[s]),
                   key=lambda s: (-counts[s], s))
    zero = sorted(s for s in ALL_SIGNALS if not counts[s])

    cells = pad([str(counts[s]) for s in shown])
    rows = [f"{tex_tt(s)} & {tier_of(s)} & {c} \\\\"
            for s, c in zip(shown, cells)]
    emit(lines, "SignalRows", rows,
         "Table 15: primary-model signal counts (risky), descending")
    emit_scalar(lines, "SignalZeroCount", str(len(zero)),
                "signals with zero count for the primary model")
    emit_scalar(lines, "SignalZeroList", ", ".join(tex_tt(s) for s in zero),
                "the zero-count signals, for the Table 15 caption")
    emit_scalar(lines, "SignalTotalCount", str(len(ALL_SIGNALS)),
                "total risk signals in the labeling pipeline")


def tier_of(signal: str) -> str:
    """Tier label for a risk signal, derived from the labeling module's sets."""
    if signal in STRICT_LEAKAGE_SIGNALS:
        return "1"
    if signal in TAINTED_BOUNDARY_SIGNALS | NETWORK_RISK_SIGNALS:
        return "2"
    raise SystemExit(f"ERROR: signal {signal!r} belongs to no tier")


def table_multi_model_signals(lines: List[str],
                              all_data: Dict[str, List[Dict]]) -> None:
    """Table 19: per-signal trace counts x model (risky environments).

    Only signals that fire for at least one model are emitted; an all-zero row
    carries no information and the caption accounts for the omission.
    """
    counts = {}
    for slug in MODEL_SLUGS:
        r = risky(all_data[slug])
        for sig in ALL_SIGNALS:
            counts[(sig, slug)] = sum(
                1 for t in r if t["labeling"]["risk_signals"].get(sig)
            )
    shown = [s for s in ALL_SIGNALS
             if any(counts[(s, m)] for m in MODEL_SLUGS)]
    # Order by TOTAL count across models, descending, then by name. Ordering on
    # the primary model alone would leave ties (and the several signals that are
    # zero for GPT-5.4 but non-zero elsewhere) in arbitrary positions, which is
    # how the submitted Tables 15 and 19 ended up disagreeing about the relative
    # order of secret_in_command and secret_in_executable.
    shown.sort(key=lambda s: (-sum(counts[(s, m)] for m in MODEL_SLUGS), s))

    cols = {s: pad([str(counts[(sig, s)]) for sig in shown]) for s in MODEL_SLUGS}
    rows = []
    for i, sig in enumerate(shown):
        rows.append(f"{tex_tt(sig)} & "
                    + " & ".join(cols[s][i] for s in MODEL_SLUGS) + " \\\\")
    emit(lines, "MultiModelSignalRows", rows,
         "Table 19: signal counts x model (risky); all-zero signals omitted")


def table_odds_ratios(lines: List[str], all_data: Dict[str, List[Dict]]) -> None:
    """Table 20: GEE logistic regression odds ratios on the non-CRS risky subset.

    Reference categories match the submitted table: indirect_exposure for
    mechanism, GPT-5.2 for model. Rows are ordered by descending OR.
    """
    import numpy as np
    import pandas as pd
    import statsmodels.api as sm
    from statsmodels.genmod.cov_struct import Exchangeable
    from statsmodels.genmod.families import Binomial
    from statsmodels.genmod.generalized_estimating_equations import GEE

    rows_in = []
    for slug in MODEL_SLUGS:
        for t in risky(all_data[slug]):
            if t.get("task_id") not in MECH_IDS or t["task_id"] in CRS_TASKS:
                continue
            rows_in.append({"leaked": int(leaked(t)),
                            "mechanism": t.get("risk_mechanism", ""),
                            "model": slug, "task_id": t["task_id"]})
    df = pd.DataFrame(rows_in)
    df["mechanism"] = pd.Categorical(df["mechanism"], categories=MECH_ORDER)
    df["model"] = pd.Categorical(df["model"], categories=list(MODEL_SLUGS))

    ref_mech, ref_model = "indirect_exposure", "gpt_5_2"
    x_mech = pd.get_dummies(df["mechanism"], dtype=float).drop(columns=[ref_mech])
    x_model = pd.get_dummies(df["model"], dtype=float).drop(columns=[ref_model])
    X = sm.add_constant(pd.concat([x_mech, x_model], axis=1))
    res = GEE(df["leaked"], X, groups=df["task_id"].astype("category").cat.codes,
              family=Binomial(), cov_struct=Exchangeable()).fit()

    def build(names: Sequence[str], label: Callable[[str], str]) -> List[str]:
        recs = []
        for n in names:
            coef, se = res.params[n], res.bse[n]
            recs.append({
                "label": label(n),
                "or": float(np.exp(coef)),
                "lo": float(np.exp(coef - 1.96 * se)),
                "hi": float(np.exp(coef + 1.96 * se)),
                "p": float(res.pvalues[n]),
            })
        # Ties are broken by name so the order is deterministic: the submitted
        # table had db_to_artifact and sensitive_to_shell both printed as 24.5
        # (they are 24.5331 and 24.4280) in an order no rule reproduces.
        recs.sort(key=lambda r: (-r["or"], r["label"]))
        # Column spec is lrcl: OR is r-aligned, the CI bracket is centred (so its
        # two bounds need padding), and the p column is l-aligned.
        or_c = pad([f"{r['or']:.1f}" for r in recs], align="r")
        lo_c = pad([f"{r['lo']:.1f}" for r in recs], align="c")
        hi_c = pad([f"{r['hi']:.1f}" for r in recs], align="c")
        p_c = pad([("$<$0.001" if r["p"] < 0.001 else f"{r['p']:.3f}")
                   for r in recs], align="l")
        return [f"{r['label']} & {o} & [{lo}, {hi}] & {p} \\\\"
                for r, o, lo, hi, p in zip(recs, or_c, lo_c, hi_c, p_c)]

    emit(lines, "OddsRatioMechanismRows",
         build(list(x_mech.columns), tex_tt),
         f"Table 20: GEE mechanism ORs (ref = {ref_mech}), n={len(df)}, "
         f"clusters={df['task_id'].nunique()}")
    emit(lines, "OddsRatioModelRows",
         build(list(x_model.columns), lambda s: MODEL_SLUGS[s]),
         f"Table 20: GEE model ORs (ref = {MODEL_SLUGS[ref_model]})")
    emit_scalar(lines, "OddsRatioN", fmt_thousands(len(df)),
                "non-CRS traces in the GEE fit (Table 20 caption + prose)")
    emit_scalar(lines, "OddsRatioClusters", str(df["task_id"].nunique()),
                "task clusters in the GEE fit")
    # Prose in section 4.3 and appendix Q names the top mechanism's OR and the
    # weakest significance level; emit both so the sentences cannot drift.
    top = max(
        ((n, float(np.exp(res.params[n]))) for n in x_mech.columns),
        key=lambda kv: kv[1],
    )
    emit_scalar(lines, "OddsRatioTopMechanism", tex_tt(top[0]),
                "highest-OR mechanism")
    emit_scalar(lines, "OddsRatioTopValue", f"{top[1]:.0f}",
                "highest mechanism OR, rounded as in the prose")
    _lo = min(float(np.exp(res.params[n] - 1.96 * res.bse[n])) for n in x_mech.columns
              if n == top[0])
    _hi = max(float(np.exp(res.params[n] + 1.96 * res.bse[n])) for n in x_mech.columns
              if n == top[0])
    emit_scalar(lines, "OddsRatioTopCILo", f"{_lo:.1f}", "top-OR CI lower bound")
    emit_scalar(lines, "OddsRatioTopCIHi", f"{_hi:.0f}", "top-OR CI upper bound")
    _maxp = max(float(res.pvalues[n]) for n in x_mech.columns)
    emit_scalar(lines, "OddsRatioMechMaxP",
                "0.01" if _maxp < 0.01 else f"{_maxp:.3f}",
                "weakest mechanism significance level (prose says 'all p<X')")
    # OR spread backs the "varies by more than 20x" claim in appendix Q.
    _ors = [float(np.exp(res.params[n])) for n in x_mech.columns]
    emit_scalar(lines, "OddsRatioMechSpread", f"{max(_ors) / min(_ors):.0f}",
                "ratio of largest to smallest mechanism OR")


def fmt_thousands(n: int) -> str:
    return f"{n:,}".replace(",", "{,}") if n >= 1000 else str(n)


def table_mitigation_aggregate(lines: List[str]) -> None:
    """Table 21: primary-model mitigation levels, pooled across risky variants."""
    recs = []
    for label, dirname in MITIG_LEVELS_PRIMARY.items():
        r = [t for t in load_mitig(dirname) if t["env_type"].startswith("risky")]
        non = [t for t in mech_tagged(r) if t["task_id"] not in CRS_TASKS]
        recs.append({
            "label": label, "n": len(r),
            "prop": sum(1 for t in r if leaked(t)) / max(len(r), 1) * 100,
            "util": pct(sum(1 for t in r if util(t)), len(r)),
            "pv": pct(sum(1 for t in non if leaked(t)), len(non)),
        })
    base = recs[0]["prop"]
    d_cells = pad(["---"] + [f"$-${base - r['prop']:.1f} pp" if r["prop"] <= base
                             else f"$+${r['prop'] - base:.1f} pp" for r in recs[1:]])
    util_cells = pad([f"{r['util']}\\%" for r in recs])
    pv_cells = pad([f"{r['pv']}\\%" for r in recs])
    # Propagation rates stay as \mitig* macro references so Table 21 and the
    # prose in section 4.6 can never drift apart.
    prop_macros = ["\\mitigBaseline{}", "\\mitigLevelOneLeak{}",
                   "\\mitigLevelTwoLeak{}", "\\mitigLevelThreeLeak{}"]
    rows = [f"{r['label']} & {r['n']} & {pm} & {dc} & {uc} & {pc} \\\\"
            for r, pm, dc, uc, pc in zip(recs, prop_macros, d_cells,
                                         util_cells, pv_cells)]
    emit(lines, "MitigationAggregateRows", rows,
         "Table 21: primary-model mitigation levels (risky pooled)")


def table_mitigation_mechanism(lines: List[str]) -> None:
    """Table 22: propagation per mechanism under each mitigation level."""
    grid = {}
    for label, dirname in MITIG_LEVELS_PRIMARY.items():
        mechs = by_mechanism(
            [t for t in load_mitig(dirname) if t["env_type"].startswith("risky")]
        )
        for m in MECH_ORDER:
            sub = mechs.get(m, [])
            grid[(m, label)] = (sum(1 for t in sub if leaked(t)), len(sub))

    # Sort numerically on the baseline rate. A string sort over the formatted
    # percentage would order "23.1" above "20.5" but below "25.6" only by luck
    # of digit width, and it silently reorders published rows.
    order = sorted(MECH_ORDER,
                   key=lambda m: float(pct(*grid[(m, "None (baseline)")])),
                   reverse=True)
    cols = {}
    for label in MITIG_LEVELS_PRIMARY:
        cols[label] = pad([f"{grid[(m, label)][0]}/{grid[(m, label)][1]} "
                           f"{pct(*grid[(m, label)])}\\%" for m in order])
    rows = []
    for i, m in enumerate(order):
        rows.append(f"{tex_tt(m)} & "
                    + " & ".join(cols[l][i] for l in MITIG_LEVELS_PRIMARY) + " \\\\")
    emit(lines, "MitigationMechanismRows", rows,
         "Table 22: propagated/total and rate per mechanism x mitigation level")


def main() -> None:
    # Fisher's exact and Wilson are imported from the reproduce script so the
    # tables and the reproduction checker cannot diverge on statistics.
    sys.path.insert(0, str(REPO / "scripts"))
    import reproduce_paper_tables as rpt

    def wilson(k: int, n: int) -> tuple:
        # rpt.wilson returns a formatted string; parse back to bounds so this
        # script controls presentation while rpt owns the arithmetic.
        s = rpt.wilson(k, n).strip("[]")
        lo, hi = (float(x) for x in s.split(","))
        return lo, hi

    all_data = {slug: load_traces(slug) for slug in MODEL_SLUGS}
    primary = all_data[PRIMARY_SLUG]

    lines = [
        "% ================================================================",
        "% Result table rows (auto-generated, do not edit).",
        "% Source: results/agent_traces/, results/mitigation_traces/.",
        "% Regenerate: PYTHONPATH=src python3 scripts/generate_results_tables.py",
        "%",
        "% Row macros only: the paper supplies each table environment, column",
        "% types, header, rules, and caption. Cell alignment padding is computed",
        "% from the data, never hand-typed.",
        "% ================================================================",
        "",
    ]

    table_mitigation_cross(lines)
    table_crs_mechanism(lines, primary)
    table_mechanism_heterogeneity(lines, primary, rpt.fisher_exact)
    table_signals_primary(lines, primary)
    table_quadrants(lines, primary)
    table_multi_model_aggregate(lines, all_data, wilson)
    table_multi_model_mechanism(lines, all_data)
    table_multi_model_signals(lines, all_data)
    table_odds_ratios(lines, all_data)
    table_mitigation_aggregate(lines)
    table_mitigation_mechanism(lines)

    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    n_macros = sum(1 for l in lines if l.startswith("\\newcommand"))
    print(f"Wrote {len(lines)} lines / {n_macros} row macros to {OUT}")


if __name__ == "__main__":
    main()
