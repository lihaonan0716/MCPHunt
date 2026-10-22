"""Manuscript consistency gates that are not about numbers.

Number provenance is covered by test_manuscript_number_provenance.py. These
tests cover the other defect classes that full-text reviews kept finding:
signal/mechanism names that drift from the code, wording that claims more than
the evidence supports, and build defects in the compiled PDF.

The manuscript lives in the private paper repo, so every test skips when it is
absent (e.g. in a public clone).
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(REPO_ROOT / "src"))

from mcphunt.labeling import (  # noqa: E402
    NETWORK_RISK_SIGNALS,
    STRICT_LEAKAGE_SIGNALS,
    TAINTED_BOUNDARY_SIGNALS,
)
from mcphunt.taxonomy import MECHANISM_FAMILIES  # noqa: E402

PAPER_DIR = REPO_ROOT / "paper"
HAVE_PAPER = (PAPER_DIR / "paper.tex").exists()
TEX_FILES = ("paper.tex", "appendix.tex", "checklist.tex")
FIGURE_SOURCE = PAPER_DIR / "figures" / "Figure1.drawio"

ALL_SIGNALS = STRICT_LEAKAGE_SIGNALS | TAINTED_BOUNDARY_SIGNALS | NETWORK_RISK_SIGNALS
KNOWN_NAMES = ALL_SIGNALS | set(MECHANISM_FAMILIES)
# Figure 1 arrow labels that name trace events, not signals.
FIGURE_EVENT_LABELS = {"tool_call"}


def _read(name: str) -> str:
    return (PAPER_DIR / name).read_text(encoding="utf-8")


def _body_lines(name: str):
    for lineno, line in enumerate(_read(name).splitlines(), 1):
        if line.lstrip().startswith("%"):
            continue
        yield lineno, line


@unittest.skipUnless(HAVE_PAPER, "manuscript not present (private paper repo)")
class TestNamesMatchCode(unittest.TestCase):
    """Signal names in the paper and Figure 1 must exist in labeling.py."""

    def test_bold_signal_names_in_tex_exist(self):
        bold = re.compile(r"\\textbf\{([a-z]+(?:\\_[a-z]+)+)\}")
        unknown = set()
        for name in TEX_FILES:
            for _, line in _body_lines(name):
                for m in bold.findall(line):
                    ident = m.replace("\\_", "_")
                    if ident not in KNOWN_NAMES:
                        unknown.add((name, ident))
        self.assertFalse(unknown, f"bold identifiers not in code: {sorted(unknown)}")

    def test_figure_signal_names_are_code_names_or_prefixes(self):
        # Figure 1 abbreviates long names (e.g. sensitive_schema); each
        # snake_case token must be a code name or a prefix of exactly one.
        text = FIGURE_SOURCE.read_text(encoding="utf-8")
        tokens = set(re.findall(r"\b[a-z]+(?:_[a-z]+)+\b", text))
        bad = []
        for tok in sorted(tokens):
            if tok in KNOWN_NAMES or tok in FIGURE_EVENT_LABELS:
                continue
            hits = [n for n in ALL_SIGNALS if n.startswith(tok)]
            if len(hits) != 1:
                bad.append(tok)
        self.assertFalse(bad, f"Figure 1 tokens matching no single code name: {bad}")


# Phrases that assert more than a benchmark with these sample sizes can show.
# Each entry maps a regex to the number of occurrences currently judged
# legitimate (negated or scoped uses, e.g. "not a causal decomposition").
# The count may only go down; a new hit needs a reviewer's judgment, not a
# baseline bump.
OVERCLAIM_BASELINE = {
    r"\bconfirm(?:s|ing)\b": 0,
    r"\bnot tied to specific\b": 0,
    r"\bno observed utility cost\b": 0,
    r"\brather than baseline risk\b": 0,
    r"\bcausal (?:canary )?tracking\b": 0,
    r"\brequires \\emph\{data-flow-aware\}": 0,
    r"\bprimary driver\b": 0,
    r"\bconsistently fails\b": 0,
}


@unittest.skipUnless(HAVE_PAPER, "manuscript not present (private paper repo)")
class TestNoOverclaimWording(unittest.TestCase):

    def test_overclaim_ratchet(self):
        failures = []
        for pattern, budget in OVERCLAIM_BASELINE.items():
            rx = re.compile(pattern, re.IGNORECASE)
            hits = [(name, ln, line.strip()[:120])
                    for name in ("paper.tex", "appendix.tex")
                    for ln, line in _body_lines(name) if rx.search(line)]
            if len(hits) > budget:
                failures.append(f"{pattern}: {len(hits)} > {budget}\n" +
                                "\n".join(f"  {n}:{ln} {t}" for n, ln, t in hits))
        self.assertFalse(failures, "\n".join(failures))


@unittest.skipUnless(HAVE_PAPER and (PAPER_DIR / "paper.log").exists()
                     and (PAPER_DIR / "paper.pdf").exists(),
                     "compiled paper not present")
class TestCompiledPdf(unittest.TestCase):
    """Build gates on the last compile; recompile before relying on these."""

    def setUp(self):
        log = PAPER_DIR / "paper.log"
        pdf = PAPER_DIR / "paper.pdf"
        newest_src = max((PAPER_DIR / n).stat().st_mtime for n in TEX_FILES)
        if pdf.stat().st_mtime < newest_src:
            self.skipTest("paper.pdf is older than the sources; recompile first")
        self.log = log.read_text(encoding="utf-8", errors="replace")

    def test_no_undefined_references_or_duplicate_destinations(self):
        self.assertNotIn("undefined", self.log.lower().replace("undefined control", ""))
        self.assertNotIn("destination with the same identifier", self.log)

    def test_no_type3_fonts_and_metadata_set(self):
        if not (shutil.which("pdffonts") and shutil.which("pdfinfo")):
            self.skipTest("poppler tools not installed")
        pdf = str(PAPER_DIR / "paper.pdf")
        fonts = subprocess.run(["pdffonts", pdf], capture_output=True, text=True).stdout
        self.assertNotIn("Type 3", fonts)
        info = subprocess.run(["pdfinfo", pdf], capture_output=True, text=True,
                              errors="replace").stdout
        title = re.search(r"^Title:\s*(.*)$", info, re.M)
        author = re.search(r"^Author:\s*(.*)$", info, re.M)
        self.assertTrue(title and title.group(1).strip(), "PDF Title metadata empty")
        self.assertTrue(author and author.group(1).strip(), "PDF Author metadata empty")


if __name__ == "__main__":
    unittest.main()
