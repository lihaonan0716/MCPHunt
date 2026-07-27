"""Structural tests for the grounding referent maps.

These maps are static domain metadata (no trace-derived numbers). The tests
enforce that they stay in exact correspondence with the mechanism/family
constructs they ground, that the negative control is excluded, and that
external weakness identifiers do not appear in the released referent strings.
Such mappings are decided at the paper/citation gate, not welded into the
taxonomy artifact.
"""
from __future__ import annotations

import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = REPO_ROOT / "src"
SCRIPTS_ROOT = REPO_ROOT / "scripts"
for _p in (SRC_ROOT, SCRIPTS_ROOT):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from mcphunt.taxonomy import (  # noqa: E402
    FAMILY_WORKFLOW_GROUNDING,
    MECHANISM_INCIDENT_GROUNDING,
    RISK_MECHANISMS,
    TASK_REGISTRY,
    validate_grounding_completeness,
)

import generate_grounding_tables as ggt  # noqa: E402
import generate_results_macros as grm  # noqa: E402


class TestMechanismGrounding(unittest.TestCase):
    def test_keys_equal_risk_mechanisms(self):
        self.assertEqual(
            set(MECHANISM_INCIDENT_GROUNDING),
            set(RISK_MECHANISMS),
            "mechanism grounding must key on exactly the risk mechanisms",
        )

    def test_exactly_nine_mechanisms(self):
        self.assertEqual(len(MECHANISM_INCIDENT_GROUNDING), 9)

    def test_benign_control_excluded(self):
        self.assertNotIn("benign_control", MECHANISM_INCIDENT_GROUNDING)


class TestFamilyGrounding(unittest.TestCase):
    def test_keys_equal_registry_families(self):
        expected = {td.family for td in TASK_REGISTRY.values()}
        self.assertEqual(
            set(FAMILY_WORKFLOW_GROUNDING),
            expected,
            "family grounding must key on exactly the registry's distinct families",
        )

    def test_family_count_matches_registry(self):
        expected = {td.family for td in TASK_REGISTRY.values()}
        self.assertEqual(len(FAMILY_WORKFLOW_GROUNDING), len(expected))


class TestReferentHygiene(unittest.TestCase):
    def test_all_referents_nonempty(self):
        for key, text in {
            **MECHANISM_INCIDENT_GROUNDING,
            **FAMILY_WORKFLOW_GROUNDING,
        }.items():
            self.assertTrue(text and text.strip(), f"empty referent for {key!r}")

    def test_no_external_weakness_identifiers(self):
        # External weakness identifiers must never appear in released referent
        # strings; those citations belong at the paper/citation gate.
        pat = re.compile(r"\b(CWE-\d+|OWASP|A\d{2}:20\d{2})\b", re.IGNORECASE)
        for key, text in {
            **MECHANISM_INCIDENT_GROUNDING,
            **FAMILY_WORKFLOW_GROUNDING,
        }.items():
            self.assertIsNone(
                pat.search(text),
                f"referent for {key!r} must not embed a CWE/OWASP identifier",
            )


class TestValidator(unittest.TestCase):
    def test_validator_passes_on_shipped_maps(self):
        # Should not raise given the maps as shipped.
        validate_grounding_completeness()


class TestGroundingTablesGenerator(unittest.TestCase):
    """The rendered LaTeX tables must reproduce the registry faithfully."""

    def test_mechanism_order_is_deterministic(self):
        # MECH_ORDER is derived from MECHANISM_FAMILIES' definition order (an
        # ordered dict) filtered to risk mechanisms -- NOT the frozenset -- so
        # it must equal that independently-derived expected order exactly.
        from mcphunt.taxonomy import MECHANISM_FAMILIES
        expected = [m for m in MECHANISM_FAMILIES if m in RISK_MECHANISMS]
        self.assertEqual(ggt.MECH_ORDER, expected)
        self.assertEqual(len(ggt.MECH_ORDER), 9)
        self.assertEqual(set(ggt.MECH_ORDER), set(RISK_MECHANISMS))

    def test_mechanism_rows_cover_nine_risk_mechanisms(self):
        body = ggt.render_mechanism_rows()
        for mech in RISK_MECHANISMS:
            self.assertIn(mech.replace("_", r"\_"), body, f"missing risk row for {mech}")
        # Exactly nine data rows (each ends with a LaTeX row terminator).
        self.assertEqual(body.count(r"\\"), 9)
        # The control mechanism must NOT appear among the nine data rows.
        self.assertNotIn(r"benign\_control", body)

    def test_control_row_is_separate_and_dagger_marked(self):
        row = ggt.render_mechanism_control_row()
        self.assertIn(r"benign\_control", row)
        self.assertIn(r"\textsuperscript", row)
        self.assertIn(r"\dagger", row)
        # It is a single display-only row.
        self.assertEqual(row.count(r"\\"), 1)

    def test_control_note_marks_exclusion(self):
        note = ggt.render_mechanism_control_row  # sanity: callable exists
        self.assertTrue(callable(note))
        self.assertIn("excluded from the nine risk-mechanism count", ggt.CONTROL_NOTE)

    def test_control_row_not_in_mechanism_grounding_map(self):
        # The control row is display-only; it must never enter the 9-map.
        self.assertNotIn("benign_control", MECHANISM_INCIDENT_GROUNDING)

    def test_family_rows_cover_all_families(self):
        body = ggt.render_family_rows()
        for fam in FAMILY_WORKFLOW_GROUNDING:
            self.assertIn(fam.replace("_", r"\_"), body, f"missing family row for {fam}")
        self.assertEqual(body.count(r"\\"), len(FAMILY_WORKFLOW_GROUNDING))

    def test_no_table_shell_emitted(self):
        # Row-level output only: the paper owns the table environment.
        full = ggt.build()
        for shell in (r"\begin{tabular}", r"\begin{tabularx}", r"\toprule",
                      r"\bottomrule", r"\midrule"):
            self.assertNotIn(shell, full, f"generator must not emit {shell}")

    def test_family_task_counts_sum_to_registry_total(self):
        total = sum(ggt._family_task_count(f) for f in FAMILY_WORKFLOW_GROUNDING)
        self.assertEqual(total, len(TASK_REGISTRY))

    def test_mechanism_risk_task_counts_sum_to_risk_total(self):
        n_risk = sum(1 for td in TASK_REGISTRY.values() if td.task_type == "risk")
        total = sum(ggt._mechanism_task_count(m) for m in RISK_MECHANISMS)
        self.assertEqual(total, n_risk)

    def test_build_is_idempotent(self):
        self.assertEqual(ggt.build(), ggt.build())

    def test_tex_escape_handles_specials(self):
        self.assertEqual(ggt.tex_escape("a_b"), r"a\_b")
        self.assertEqual(ggt.tex_escape("x&y"), r"x\&y")
        # Every underscore must be backslash-escaped (no bare '_').
        self.assertEqual(ggt.tex_escape("data_migration"), r"data\_migration")
        self.assertNotIn("_", ggt.tex_escape("data_migration").replace(r"\_", ""))


class TestResultsMacroContract(unittest.TestCase):
    """Smoke-test the rebuttal-facing grounding macros in results_macros.tex."""

    @classmethod
    def setUpClass(cls):
        old_out = grm.OUT
        try:
            with tempfile.TemporaryDirectory() as tmp:
                grm.OUT = Path(tmp) / "results_macros.tex"
                grm.main()
                cls.content = grm.OUT.read_text(encoding="utf-8")
        finally:
            grm.OUT = old_out

    def assertMacro(self, name: str, value: int) -> None:
        needle = f"\\newcommand{{\\{name}}}{{{value}}}"
        self.assertIn(needle, self.content, f"missing or changed macro {name}")

    def test_global_grounding_macros(self):
        risk_tasks = [td for td in TASK_REGISTRY.values() if td.task_type == "risk"]
        hn_tasks = [td for td in TASK_REGISTRY.values() if td.task_type == "hard_negative"]
        benign_tasks = [td for td in TASK_REGISTRY.values() if td.task_type == "benign"]
        risk_mechs = sorted({td.mechanism for td in risk_tasks})

        risk_per_mech = {
            mech: sum(1 for td in risk_tasks if td.mechanism == mech)
            for mech in risk_mechs
        }
        hn_per_mech = {
            mech: sum(1 for td in hn_tasks if td.mechanism == mech)
            for mech in risk_mechs
        }

        expected = {
            "groundingMechanismCount": len(MECHANISM_INCIDENT_GROUNDING),
            "groundingFamilyCount": len(FAMILY_WORKFLOW_GROUNDING),
            "groundingRiskTasksPerMechanism": next(iter(set(risk_per_mech.values()))),
            "groundingHNTasksPerMechanism": next(iter(set(hn_per_mech.values()))),
            "groundingRiskTaskTotal": len(risk_tasks),
            "groundingHNTaskTotal": len(hn_tasks),
            "groundingBenignTaskTotal": len(benign_tasks),
            "groundingTaskTotal": len(TASK_REGISTRY),
        }
        self.assertEqual(set(risk_per_mech.values()), {12})
        self.assertEqual(set(hn_per_mech.values()), {3})
        for name, value in expected.items():
            self.assertMacro(name, value)

    def test_per_family_grounding_macros(self):
        self.assertEqual(len(FAMILY_WORKFLOW_GROUNDING), 43)
        for family in FAMILY_WORKFLOW_GROUNDING:
            tag = family.title().replace("_", "")
            count = sum(1 for td in TASK_REGISTRY.values() if td.family == family)
            self.assertMacro(f"groundingFamily{tag}Tasks", count)


if __name__ == "__main__":
    unittest.main()
