#!/usr/bin/env python3
r"""
Generate paper/grounding_tables.tex from the task registry + grounding maps.

Emits ROW-LEVEL LaTeX macros only -- reproducible registry-derived content,
no table shell.  Column types, widths, and the surrounding table environment
are typesetting decisions that belong to the paper, not to this generator.
The paper wraps these macros in its own table environment (3 columns:
name & referent & task count).

Macros emitted:

* ``\GroundingMechanismRows``       -- 9 risk-mechanism rows (name & incident-
                                       class referent & risk-task count)
* ``\GroundingMechanismControlRow`` -- one display-only ``benign_control`` row,
                                       dagger-marked; NOT one of the 9
* ``\GroundingMechanismControlNote``-- footnote text for the dagger marker
* ``\GroundingFamilyRows``          -- 43 family rows (name & workflow referent
                                       & registered-task count)

Run after any registry/grounding change:

    PYTHONPATH=src python3 scripts/generate_grounding_tables.py

Like results_macros.tex the output is an auto-generated build product
(gitignored) -- never hand-edit it.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcphunt.taxonomy import (
    TASK_REGISTRY,
    RISK_MECHANISMS,
    MECHANISM_FAMILIES,
    MECHANISM_INCIDENT_GROUNDING,
    FAMILY_WORKFLOW_GROUNDING,
    validate_grounding_completeness,
)

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "paper" / "grounding_tables.tex"

# Fixed display order for the risk mechanisms == their definition order in
# MECHANISM_FAMILIES (an ordered dict), which is the registry's authoritative
# ordering. RISK_MECHANISMS is a frozenset (unordered), so we must NOT iterate
# it directly for rendered rows -- that would make row order non-reproducible.
MECH_ORDER: List[str] = [m for m in MECHANISM_FAMILIES if m in RISK_MECHANISMS]

CONTROL_NOTE = (
    "Negative control; excluded from the nine risk-mechanism count "
    "and not an incident class."
)

_LATEX_ESCAPES = {
    "\\": r"\textbackslash{}",
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "~": r"\textasciitilde{}",
    "^": r"\textasciicircum{}",
}


def tex_escape(s: str) -> str:
    """Escape a plain string for safe insertion into a LaTeX cell."""
    out = []
    for ch in s:
        out.append(_LATEX_ESCAPES.get(ch, ch))
    return "".join(out)


def _family_task_count(family: str) -> int:
    return sum(1 for td in TASK_REGISTRY.values() if td.family == family)


def _mechanism_task_count(mech: str) -> int:
    return sum(
        1 for td in TASK_REGISTRY.values()
        if td.mechanism == mech and td.task_type == "risk"
    )


def render_mechanism_rows() -> str:
    """Render the 9 risk-mechanism data rows (no shell, no header)."""
    rows: List[str] = []
    for mech in MECH_ORDER:
        referent = MECHANISM_INCIDENT_GROUNDING[mech]
        n = _mechanism_task_count(mech)
        rows.append(
            f"\\texttt{{{tex_escape(mech)}}} & {tex_escape(referent)} & {n} \\\\"
        )
    return "\n".join(rows)


def render_mechanism_control_row() -> str:
    """Render the display-only benign_control row (dagger-marked, NOT of the 9)."""
    control_desc = MECHANISM_FAMILIES["benign_control"].description
    n_benign = sum(1 for td in TASK_REGISTRY.values() if td.task_type == "benign")
    return (
        f"\\texttt{{benign\\_control}}\\textsuperscript{{$\\dagger$}} "
        f"& {tex_escape(control_desc)} & {n_benign} \\\\"
    )


def render_family_rows() -> str:
    """Render the family data rows, sorted by family key (no shell, no header)."""
    rows: List[str] = []
    for family in sorted(FAMILY_WORKFLOW_GROUNDING):
        referent = FAMILY_WORKFLOW_GROUNDING[family]
        n = _family_task_count(family)
        rows.append(
            f"\\texttt{{{tex_escape(family)}}} & {tex_escape(referent)} & {n} \\\\"
        )
    return "\n".join(rows)


def build() -> str:
    validate_grounding_completeness()
    parts: List[str] = []
    parts.append("% ================================================================")
    parts.append("% Grounding correspondence rows (auto-generated, do not edit).")
    parts.append("% Source: src/mcphunt/taxonomy.py (registry + grounding maps).")
    parts.append("% Row macros only: the paper supplies the table environment,")
    parts.append("% column types, header, and rules.")
    parts.append("% Row shape: name & referent & task count \\\\")
    parts.append("% ================================================================")
    parts.append("")
    parts.append(r"\newcommand{\GroundingMechanismRows}{%")
    parts.append(render_mechanism_rows())
    parts.append("}")
    parts.append("")
    parts.append(r"\newcommand{\GroundingMechanismControlRow}{%")
    parts.append(render_mechanism_control_row())
    parts.append("}")
    parts.append("")
    parts.append(r"\newcommand{\GroundingMechanismControlNote}{%")
    parts.append(tex_escape(CONTROL_NOTE))
    parts.append("}")
    parts.append("")
    parts.append(r"\newcommand{\GroundingFamilyRows}{%")
    parts.append(render_family_rows())
    parts.append("}")
    parts.append("")
    return "\n".join(parts)


def main() -> int:
    content = build()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", encoding="utf-8", newline="\n") as f:
        f.write(content)
    n_mech = len(MECHANISM_INCIDENT_GROUNDING)
    n_fam = len(FAMILY_WORKFLOW_GROUNDING)
    print(f"Wrote {OUT}")
    print(f"  Mechanism rows: {n_mech} risk + 1 control (separate macro)")
    print(f"  Family rows: {n_fam}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
