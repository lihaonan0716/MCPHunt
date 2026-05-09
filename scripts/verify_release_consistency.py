#!/usr/bin/env python3
"""
End-to-end consistency verification for the MCPHunt release bundle.

Aligned to the current paper mainline: canary-based compositional data-leakage
evaluation with 147 tasks, 9 mechanism families, and agent trace collection
across multiple models.

Run before submission to confirm:
  1. All required source / config / paper files exist.
  2. Agent trace files exist for the expected models.
  3. Unit tests pass.
  4. relabel_traces.py runs successfully on a trace file.
  5. Croissant metadata validates.
  6. paper.tex cite keys resolve in references.bib.
  7. HuggingFace staging bundle present.
  8. No stale project-name references remain.

Exits 0 on full success, non-zero on any failure.

Usage:
    python3 scripts/verify_release_consistency.py
    python3 scripts/verify_release_consistency.py --strict
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import List

REPO_ROOT = Path(__file__).resolve().parents[1]

# Constructed dynamically to avoid self-match during stale-name scanning
STALE_NAME = "MCPHunt" + "-" + "RIFT"

EXPECTED_MODELS = [
    "gpt_5_2",
    "gpt_5_4",
    "deepseek_v4_flash",
    "gemini_3_1_pro_preview",
    "MiniMax_M2_7",
]


class CheckResult:
    def __init__(self) -> None:
        self.errors: List[str] = []
        self.warnings: List[str] = []
        self.passes: List[str] = []

    def passed(self, msg: str) -> None:
        self.passes.append(msg)

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


# ── Check 1: Required files ──────────────────────────────────────

def check_required_files(result: CheckResult) -> None:
    required = [
        "README.md",
        "LICENSE",
        "Makefile",
        "manifest.json",
        "pyproject.toml",
        "src/mcphunt/__init__.py",
        "src/mcphunt/labeling.py",
        "src/mcphunt/taxonomy.py",
        "src/mcphunt/canary_registry.py",
        "src/mcphunt/agent_loop.py",
        "src/mcphunt/mcp_driver.py",
        "src/mcphunt/environments.py",
        "src/mcphunt/workspace.py",
        "src/mcphunt/runtime_guard.py",
        "src/mcphunt/datasets/agent_traces.py",
        "src/mcphunt/datasets/loader.py",
        "scripts/collect_agent_traces.py",
        "scripts/relabel_traces.py",
        "scripts/generate_croissant_metadata.py",
        "scripts/prepare_huggingface_release.py",
        "scripts/verify_release_consistency.py",
        "tests/test_project_smoke.py",
        "tests/test_labeling_integrity.py",
    ]
    for rel in required:
        if (REPO_ROOT / rel).exists():
            result.passed(f"file exists: {rel}")
        else:
            result.error(f"MISSING required file: {rel}")


# ── Check 2: Agent trace files ───────────────────────────────────

def check_agent_traces(result: CheckResult) -> None:
    traces_dir = REPO_ROOT / "results" / "agent_traces"
    if not traces_dir.exists():
        result.error("results/agent_traces/ directory not found")
        return

    total_traces = 0
    for model in EXPECTED_MODELS:
        trace_file = traces_dir / model / "agent_traces.json"
        if not trace_file.exists():
            result.error(f"missing trace file for model: {model}")
            continue
        try:
            data = json.loads(trace_file.read_text(encoding="utf-8"))
            traces = data["traces"] if isinstance(data, dict) and "traces" in data else data
            n = len(traces) if isinstance(traces, list) else 0
            total_traces += n
            result.passed(f"traces present: {model} ({n} traces)")
        except Exception as exc:
            result.error(f"cannot parse traces for {model}: {exc}")

    extra_models = []
    if traces_dir.exists():
        for d in sorted(traces_dir.iterdir()):
            if d.is_dir() and d.name not in EXPECTED_MODELS and (d / "agent_traces.json").exists():
                extra_models.append(d.name)
    if extra_models:
        result.passed(f"extra model traces found: {', '.join(extra_models)}")

    result.passed(f"total traces across expected models: {total_traces}")


# ── Check 3: Test suites ─────────────────────────────────────────

def check_tests(result: CheckResult) -> None:
    cmd = [sys.executable, "-m", "pytest", "tests/", "-x", "--tb=line", "-q"]
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, env=env)
    if proc.returncode == 0:
        summary = proc.stdout.strip().splitlines()[-1] if proc.stdout.strip() else "OK"
        result.passed(f"test suites: {summary}")
    else:
        snippet = (proc.stdout + proc.stderr).strip().splitlines()[-5:]
        result.error("test suite FAILED:\n  " + "\n  ".join(snippet))


# ── Check 4: relabel_traces.py works ─────────────────────────────

def check_relabel(result: CheckResult) -> None:
    traces_dir = REPO_ROOT / "results" / "agent_traces"
    sample = None
    for model in EXPECTED_MODELS:
        candidate = traces_dir / model / "agent_traces.json"
        if candidate.exists():
            sample = candidate
            break
    if sample is None:
        result.warn("cannot test relabel — no trace files found")
        return

    cmd = [sys.executable, "scripts/relabel_traces.py", str(sample)]
    env = dict(os.environ)
    env["PYTHONPATH"] = "src"
    proc = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, env=env)
    if proc.returncode == 0:
        result.passed(f"relabel_traces.py runs OK on {sample.parent.name}")
    else:
        snippet = proc.stderr.strip().splitlines()[-3:]
        result.error(f"relabel_traces.py FAILED:\n  " + "\n  ".join(snippet))


# ── Check 5: Croissant metadata ──────────────────────────────────

def check_croissant(result: CheckResult) -> None:
    release_dir = REPO_ROOT / "artifacts" / "release"
    fname = "croissant.json"
    path = release_dir / fname
    if not path.exists():
        result.error(f"missing Croissant file: {fname}")
        return
    meta = json.loads(path.read_text(encoding="utf-8"))
    required_fields = [
        "@context", "@type", "name", "description",
        "license", "version",
    ]
    rai_fields = [
        "rai:dataCollection", "rai:dataCollectionType",
        "rai:dataAnnotationProtocol", "rai:dataLimitation",
        "rai:personalSensitiveInformation",
    ]
    missing = [f for f in required_fields if f not in meta]
    if missing:
        result.error(f"{fname} missing required core fields: {missing}")
    else:
        result.passed(f"Croissant core fields valid: {fname}")
    missing_rai = [f for f in rai_fields if f not in meta]
    if missing_rai:
        result.error(f"{fname} missing RAI fields: {missing_rai}")
    else:
        result.passed(f"Croissant RAI fields valid: {fname}")
    if STALE_NAME in json.dumps(meta):
        result.error(f"{fname} still contains stale name reference")


# ── Check 6: Paper citations ─────────────────────────────────────

def check_paper_citations(result: CheckResult) -> None:
    paper = (REPO_ROOT / "paper" / "paper.tex").read_text(encoding="utf-8")
    appendix = ""
    appendix_path = REPO_ROOT / "paper" / "appendix.tex"
    if appendix_path.exists():
        appendix = appendix_path.read_text(encoding="utf-8")
    bib = (REPO_ROOT / "paper" / "references.bib").read_text(encoding="utf-8")

    cite_keys = set()
    for text in (paper, appendix):
        for match in re.finditer(r"\\cite[a-zA-Z]*\{([^}]+)\}", text):
            for key in match.group(1).split(","):
                cite_keys.add(key.strip())
    bib_keys = set(re.findall(r"@\w+\{([^,]+),", bib))
    missing = sorted(cite_keys - bib_keys)
    if missing:
        result.error(f"paper cites {len(missing)} missing key(s): {missing[:5]}")
    else:
        result.passed(f"all {len(cite_keys)} cite keys resolve in references.bib")


# ── Check 7: HuggingFace staging ─────────────────────────────────

def check_huggingface_staging(result: CheckResult) -> None:
    staging = REPO_ROOT / "artifacts" / "huggingface-staging" / "mcphunt-agent-traces"
    if not staging.exists():
        result.warn("artifacts/huggingface-staging/mcphunt-agent-traces not present (run `make hf-stage`)")
        return
    for sub_file in ("README.md", "croissant.json"):
        path = staging / sub_file
        if not path.exists():
            result.warn(f"HF staging missing: {sub_file}")
        else:
            result.passed(f"HF staging present: {sub_file}")
            text = path.read_text(encoding="utf-8")
            if STALE_NAME in text:
                result.error(f"stale name reference in {sub_file}")
    for subdir in ("main", "mitigation", "meta"):
        path = staging / subdir
        if path.is_dir() and any(path.iterdir()):
            result.passed(f"HF staging directory: {subdir}/ ({sum(1 for _ in path.glob('*'))} files)")
        else:
            result.warn(f"HF staging directory empty or missing: {subdir}/")


# ── Check 8: No stale naming ─────────────────────────────────────

def check_no_stale_naming(result: CheckResult) -> None:
    stale = "MCPHunt" + "-" + "RIFT"
    checked = 0
    hits = []
    for ext in ("*.md", "*.py", "*.json", "*.tex"):
        for path in REPO_ROOT.rglob(ext):
            rel = path.relative_to(REPO_ROOT)
            parts = rel.parts
            if any(skip in parts for skip in ("archive", ".git", ".omc", "node_modules", ".drawio")):
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            checked += 1
            if stale in text:
                hits.append(str(rel))
    if hits:
        result.error(f"stale '{stale}' found in {len(hits)} file(s): {hits[:5]}")
    else:
        result.passed(f"no '{stale}' references across {checked} files")


# ── Main ──────────────────────────────────────────────────────────

def main(strict: bool) -> int:
    print("=" * 70)
    print("MCPHunt Release Consistency Verification")
    print("=" * 70)
    result = CheckResult()

    checks = [
        ("[1/8] Required files...", check_required_files),
        ("[2/8] Agent trace files...", check_agent_traces),
        ("[3/8] Test suites...", check_tests),
        ("[4/8] Relabel pipeline...", check_relabel),
        ("[5/8] Croissant metadata...", check_croissant),
        ("[6/8] Paper citations...", check_paper_citations),
        ("[7/8] HuggingFace staging...", check_huggingface_staging),
        ("[8/8] No stale naming...", check_no_stale_naming),
    ]
    for label, fn in checks:
        print(label)
        fn(result)

    print()
    print("=" * 70)
    print(f"PASSES:   {len(result.passes)}")
    for p in result.passes:
        print(f"  [PASS] {p}")
    print()
    if result.warnings:
        print(f"WARNINGS: {len(result.warnings)}")
        for w in result.warnings:
            print(f"  [WARN] {w}")
        print()
    print(f"ERRORS:   {len(result.errors)}")
    for e in result.errors:
        print(f"  [FAIL] {e}")
    print("=" * 70)

    if result.errors:
        return 2
    if strict and result.warnings:
        return 1
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--strict", action="store_true",
                        help="Treat warnings as errors")
    args = parser.parse_args()
    sys.exit(main(strict=args.strict))
