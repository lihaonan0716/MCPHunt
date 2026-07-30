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
  5. Croissant metadata validates (named + anonymous identities).
  6. paper.tex cite keys resolve in references.bib.
  7. Both HuggingFace staging bundles present, complete, and leak-free.
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
        result.warn("cannot test relabel - no trace files found")
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
    required_fields = [
        "@context", "@type", "name", "description",
        "license", "version",
    ]
    rai_fields = [
        "rai:dataCollection", "rai:dataCollectionType",
        "rai:dataAnnotationProtocol", "rai:dataLimitation",
        "rai:personalSensitiveInformation",
    ]
    # Every release identity is validated, not just the named one: the anonymous
    # copy is the file reviewers actually see, so it must satisfy the same core
    # and RAI requirements.
    for variant, config in _staging_variants().items():
        fname = config["croissant"]
        path = release_dir / fname
        if not path.exists():
            result.error(f"missing Croissant file for '{variant}': {fname}")
            continue
        meta = json.loads(path.read_text(encoding="utf-8"))
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

def _staging_variants() -> dict:
    """Load the staging-variant table from the release preparation script.

    Read rather than duplicated: a bundle added there must be verified here, and
    a hardcoded copy is exactly how the anonymous bundle previously escaped
    every check.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_prep_hf_release", REPO_ROOT / "scripts" / "prepare_huggingface_release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.STAGING_VARIANTS


# Files that must never sit inside a bundle: the documented upload command
# copies the staging directory recursively, so a pre-sanitization backup would
# publish exactly the PII sanitization removed.
_UPLOAD_FORBIDDEN_SUFFIXES = (".presan.bak",)


def check_huggingface_staging(result: CheckResult) -> None:
    for variant, config in _staging_variants().items():
        staging = config["dir"] / "mcphunt-agent-traces"
        label = f"HF staging [{variant}]"
        if not staging.exists():
            result.warn(f"{label} not present at "
                        f"{staging.relative_to(REPO_ROOT)} (run `make release`)")
            continue
        for sub_file in ("README.md", "croissant.json"):
            path = staging / sub_file
            if not path.exists():
                result.warn(f"{label} missing: {sub_file}")
            else:
                result.passed(f"{label} present: {sub_file}")
                if STALE_NAME in path.read_text(encoding="utf-8"):
                    result.error(f"stale name reference in {variant}/{sub_file}")
        for subdir in ("main", "mitigation", "live_guard_defense",
                       "browser_replication", "meta", "recall_evaluation"):
            path = staging / subdir
            if path.is_dir() and any(path.iterdir()):
                result.passed(f"{label} directory: {subdir}/ "
                              f"({sum(1 for _ in path.glob('*'))} files)")
            else:
                result.error(f"{label} directory empty or missing: {subdir}/")

        stray = [p for p in staging.rglob("*")
                 if p.is_file() and p.name.endswith(_UPLOAD_FORBIDDEN_SUFFIXES)]
        if stray:
            result.error(
                f"{label} contains {len(stray)} upload-forbidden file(s) "
                f"(e.g. {stray[0].relative_to(staging)}); these carry "
                "pre-sanitization content and the upload is recursive")
        else:
            result.passed(f"{label} free of pre-sanitization backups")

        # Every file the Croissant distribution declares must actually ship,
        # or the bundle promises a download that 404s.
        _check_declared_files_present(result, staging, label)

        # Cross-consistency: staging croissant must match its release
        # source-of-truth on descriptive/provenance fields. Only fields that are
        # intentionally varied per identity are exempt.
        _check_staging_matches_release(result, staging, config, label)


# Fields intentionally allowed to differ between the release source-of-truth and
# a staged bundle. Empty by design: each identity now has its OWN generated
# croissant (croissant.json / croissant.anon.json), so the staged copy must be a
# byte-for-byte match of its source rather than an approved-divergence copy.
_STAGING_EXEMPT_KEYS: frozenset = frozenset()


def _check_declared_files_present(result: CheckResult, staging: Path,
                                  label: str) -> None:
    path = staging / "croissant.json"
    if not path.exists():
        return  # presence already reported above
    try:
        meta = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - report, don't crash the suite
        result.error(f"{label} croissant not parseable: {exc}")
        return
    missing = [obj.get("contentUrl") for obj in meta.get("distribution", [])
               if obj.get("contentUrl")
               and not (staging / obj["contentUrl"]).exists()]
    if missing:
        result.error(f"{label} croissant declares {len(missing)} file(s) that "
                     f"are not in the bundle: {missing[:5]}")
    else:
        n = len(meta.get("distribution", []))
        result.passed(f"{label} ships every one of {n} declared file(s)")


def _staging_sync_keys(rel: dict, stg: dict) -> list:
    """Fields that MUST stay in sync: descriptive text plus every top-level
    RAI provenance field present in either croissant, minus any exempt keys.
    Built dynamically so a newly added rai:* field is covered automatically
    instead of silently escaping a hardcoded list."""
    keys = {"description"} | {
        key for key in (rel.keys() | stg.keys()) if key.startswith("rai:")
    }
    return sorted(keys - _STAGING_EXEMPT_KEYS)


def _check_staging_matches_release(result: CheckResult, staging: Path,
                                   config: dict, label: str) -> None:
    release_path = REPO_ROOT / "artifacts" / "release" / config["croissant"]
    staging_path = staging / "croissant.json"
    if not (release_path.exists() and staging_path.exists()):
        return  # presence already reported above
    try:
        rel = json.loads(release_path.read_text(encoding="utf-8"))
        stg = json.loads(staging_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001 - report, don't crash the suite
        result.error(f"{label} croissant staging/release not parseable: {exc}")
        return
    sync_keys = _staging_sync_keys(rel, stg)
    rai_count = sum(1 for key in sync_keys if key.startswith("rai:"))
    drift = [key for key in sync_keys
             if not (rel.get(key) is None and stg.get(key) is None)
             and rel.get(key) != stg.get(key)]
    # The staged copy is a plain copy of its identity's generated file, so the
    # whole document -- distribution and recordSet included -- must agree.
    for key in ("distribution", "recordSet", "citeAs", "url",
                "creator", "publisher"):
        if rel.get(key) != stg.get(key) and key not in drift:
            drift.append(key)
    if drift:
        result.error(
            f"{label} croissant drifted from "
            f"artifacts/release/{config['croissant']} on {sorted(drift)}; "
            "re-run scripts/generate_croissant_metadata.py then "
            "scripts/prepare_huggingface_release.py"
        )
    else:
        result.passed(
            f"{label} croissant matches artifacts/release/"
            f"{config['croissant']} (checked {len(sync_keys)} descriptive/RAI "
            f"fields including {rai_count} RAI fields, plus distribution, "
            "recordSet and identity fields)"
        )


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
