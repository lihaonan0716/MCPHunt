#!/usr/bin/env python3
"""
Prepare a HuggingFace Datasets release bundle for MCPHunt agent traces.

Stages sanitized trace files, Croissant metadata, and a dataset card into
artifacts/huggingface-staging/ for manual upload.

Usage:
    python3 scripts/prepare_huggingface_release.py                # full pipeline
    python3 scripts/prepare_huggingface_release.py --skip-sanitize # skip sanitization
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "results"
RELEASE_DIR = REPO_ROOT / "artifacts" / "release"

# Two staging bundles are built from the SAME staged files and differ only in
# the identity fields (author/creator/publisher/repo URL). Keeping them
# parameterised here — rather than syncing one by hand — is what stops the
# anonymous bundle from silently missing a newly added artifact.
STAGING_VARIANTS = {
    "named": {
        "dir": REPO_ROOT / "artifacts" / "huggingface-staging",
        "hf_repo": "lihaonan0716/mcphunt-agent-traces",
        "authors": "Li, Haonan and Sun, Tianjun and Wang, Yongqing and Zhang, Qisheng",
        "citation": (
            "@article{mcphunt2026,\n"
            "  title={MCPHunt: An Evaluation Framework for Cross-Boundary Data Propagation\n"
            "         in Multi-Server MCP Agents},\n"
            "  author={Li, Haonan and Sun, Tianjun and Wang, Yongqing and Zhang, Qisheng},\n"
            "  year={2026},\n"
            "  eprint={2604.27819},\n"
            "  archivePrefix={arXiv},\n"
            "  primaryClass={cs.CR},\n"
            "  url={https://arxiv.org/abs/2604.27819}\n"
            "}"
        ),
        # Matching RELEASE_IDENTITIES entry in generate_croissant_metadata.py;
        # both files declare identical content and differ only in identity.
        "croissant": "croissant.json",
    },
    "anon": {
        "dir": REPO_ROOT / "artifacts" / "huggingface-staging-anon",
        "hf_repo": "mcphunt-benchmark/mcphunt-agent-traces",
        "authors": "Anonymous",
        "citation": (
            "@misc{mcphunt2026anonymous,\n"
            "  title={MCPHunt: An Evaluation Framework for Cross-Boundary Data Propagation\n"
            "         in Multi-Server MCP Agents},\n"
            "  author={Anonymous},\n"
            "  year={2026}\n"
            "}"
        ),
        "croissant": "croissant.anon.json",
    },
}
# Back-compat alias: the default (named) bundle path other scripts check.
HF_STAGING = STAGING_VARIANTS["named"]["dir"] / "mcphunt-agent-traces"

MAIN_MODELS = [
    "gpt_5_4",
    "gpt_5_2",
    "deepseek_v4_flash",
    "gemini_3_1_pro_preview",
    "MiniMax_M2_7",
]

# Post-submission additive arms shipped alongside the main + mitigation split.
# All are DeepSeek-only replications collected to answer rebuttal reviewers on
# runtime taint-guard efficacy and cross-arm reproducibility.
LIVE_GUARD_DEFENSE = {
    "src": "results/agent_traces/deepseek_v4_flash/agent_traces_deft.json",
    "dst_subdir": "live_guard_defense",
    "dst_name": "deepseek_v4_flash.json",
}
BROWSER_REPLICATION = [
    {
        "src": "results/agent_traces_b3_replication/deepseek_v4_flash/agent_traces_browser.json",
        "dst_subdir": "browser_replication",
        "dst_name": "deepseek_v4_flash_baseline.json",
    },
    {
        "src": "results/agent_traces_b3_replication/deepseek_v4_flash/agent_traces_browser_deft.json",
        "dst_subdir": "browser_replication",
        "dst_name": "deepseek_v4_flash_defense.json",
    },
]
# Paired-analysis artifacts. REQUIRED, not best-effort: the dataset card names
# each of them unconditionally and the reviewer-facing paired numbers are quoted
# externally, so a missing file must abort the build rather than produce a bundle
# whose README promises something the bundle does not contain.
PAIRED_META = [
    "results/live_guard_replication/paired_live_guard_analysis.json",
    "results/mitigation_analysis/live_guard_deepseek_v4_flash_paired.json",
    # Hard-negative matched-pair table. Staged because the reviewer-facing
    # paired difference and its interval are quoted externally; without the
    # artifact in the bundle, "reproduces from the released traces and scripts"
    # would depend on a file that only exists in the (gitignored) working tree.
    "results/hard_negative_analysis/hard_negative_ci.json",
]

# Judge-based recall diagnostic. Released as its own split (not under meta/)
# because it is a single-record estimate over a seeded sample rather than an
# aggregate of the trace splits, and AC-2 quotes its headline externally.
# The source filename carries the run tag; the released name is stable.
RECALL_EVALUATION = {
    "src": ("results/recall_evaluation/"
            "recall_estimation_claude-opus-4-8_seed20260729_n150.json"),
    "dst_subdir": "recall_evaluation",
    "dst_name": "recall_estimation.json",
}

# Artifacts that record the SHA-256 of the trace file they were computed from,
# paired with the staged copy that must carry that same hash. Sanitization
# rewrites trace bytes, so an artifact computed before `--apply` would cite a
# hash no released file has -- making "recomputes from the released traces"
# unverifiable. Checked after staging; see _verify_source_hashes.
SOURCE_HASH_CHECKS = [
    {
        "artifact": "results/hard_negative_analysis/hard_negative_ci.json",
        "hash_key": "source_sha256",
        "staged": "main/gpt_5_4.json",
    },
    {
        "artifact": "results/live_guard_replication/paired_live_guard_analysis.json",
        "hash_key": "provenance.inputs.baseline.sha256",
        "staged": "browser_replication/deepseek_v4_flash_baseline.json",
    },
    {
        "artifact": "results/live_guard_replication/paired_live_guard_analysis.json",
        "hash_key": "provenance.inputs.defense.sha256",
        "staged": "browser_replication/deepseek_v4_flash_defense.json",
    },
]

# Files that must never reach a released bundle. `.presan.bak` are pre-sanitized
# backups: they sit beside the cleaned files and still carry the raw local paths
# and env dumps, and the documented upload command copies the directory
# RECURSIVELY -- so leaving one in staging uploads the very PII that
# sanitization removed.
STAGING_EXCLUDE_SUFFIXES = (".presan.bak",)

DATASET_CARD = """\
---
license: cc-by-4.0
language:
- en
pretty_name: MCPHunt Agent Traces
size_categories:
- 1K<n<10K
task_categories:
- other
tags:
- agent-safety
- mcp
- model-context-protocol
- data-propagation
- benchmark
- canary-tracking
---

# MCPHunt Agent Traces

Agent execution traces from the MCPHunt evaluation framework, measuring
cross-boundary data propagation in multi-server MCP agents.

## Contents

- **`main/`** — 3,615 traces from 5 models across 147 tasks and 7 environment
  variants (risky_v1/v2/v3, benign, hard_neg_v1/v2/v3). One JSON file per model.
- **`mitigation/`** — 2,706 traces from the prompt-mitigation study (M0--M3
  levels) across 3 models.
- **`live_guard_defense/`** — 387 DeepSeek-V4-Flash traces from the runtime
  taint-guard defense arm (same task/env schedule as the main split for that
  model), paired with the corresponding baseline traces in `main/` so the
  defense-vs-baseline comparison is reproducible per-trace.
- **`browser_replication/`** — 78 DeepSeek-V4-Flash traces (39 baseline + 39
  defense) collected as a same-arm-schedule replication of the
  browser-to-local mechanism, released to support cross-arm reproducibility
  checks for the runtime-guard analysis.
- **`meta/`** — Aggregated results, regression data, and paired-analysis
  summaries for statistical analysis. Includes
  `paired_live_guard_analysis.json`,
  `live_guard_deepseek_v4_flash_paired.json`, and
  `hard_negative_ci.json` (the risky-vs-hard-negative matched 2x2, its Tango
  score interval, and the exact McNemar p-value).
- **`recall_evaluation/`** — `recall_estimation.json`, a single-record
  LLM-judge recall estimate over a seeded SRS sample (n=150, seed=20260729) of
  detector-clean no-defense traces. It estimates the prevalence of secret
  propagation missed by the exact-substring detector within the detector-clean
  pool. Point estimates are judge-estimated (Claude Opus judge), not human
  ground truth; confidence intervals are Wilson score 95%. This quantifies the
  non-verbatim undercount of the conservative, verbatim-only substring detector
  and is diagnostic only — it does not modify any per-trace label in the other
  splits.

## Reproduction

```bash
git clone <repo-url> && cd mcphunt
pip install -e .
make download    # downloads this dataset to results/
make reproduce   # reproduces every number in the paper
make paired      # recomputes the matched-pair analyses from the traces
```

`make download` restores the supplemental arms to the paths the analyses read
(`live_guard_defense/` and `browser_replication/` become
`results/agent_traces/deepseek_v4_flash/agent_traces_deft.json` and
`results/agent_traces_b3_replication/deepseek_v4_flash/`), and fetches the
released `meta/` artifacts as reference copies. `make paired` then recomputes
them from the traces, writing to `results/hard_negative_analysis/` and
`results/live_guard_replication/`; the release build is what copies those
outputs into `meta/`. Each recomputed artifact records the SHA-256 of the trace
file it read, which matches the corresponding file in this bundle.

## Models

| Model | Provider | Traces |
|-------|----------|--------|
| GPT-5.4 | OpenAI | 723 |
| GPT-5.2 | OpenAI | 723 |
| DeepSeek-V4-Flash | DeepSeek | 723 |
| Gemini-3.1-Pro | Google | 723 |
| MiniMax-M2.7 | MiniMax | 723 |

## Schema

Each trace JSON file contains a top-level `traces` array. Per-trace fields:
`task_id`, `env_type`, `risk_mechanism`, `outcome`, `labeling` (with 11 tiered
risk signals plus 1 diagnostic signal), `events` (tool-call log),
`task_completed`, `duration_s`, etc.

## Citation

```bibtex
{{citation}}
```

## License

CC-BY-4.0
"""


def _dataset_card(config: dict) -> str:
    """Render the dataset card for one staging variant.

    The content claims are shared; only the identity-sensitive fields vary by
    bundle so the anonymous review copy cannot leak the named citation.
    """
    card = DATASET_CARD.replace("{{citation}}", config["citation"])
    return card.replace("{{authors}}", config["authors"])


def _run(cmd: list[str], description: str) -> None:
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"FAILED: {description}")


def _require(src: Path, what: str) -> Path:
    """Abort unless a required release input exists.

    Required inputs are named unconditionally by the dataset card, so a WARNING
    here would ship a bundle whose README promises a file it does not contain.
    """
    if not src.exists():
        raise SystemExit(
            f"FAILED: required {what} missing: "
            f"{src.relative_to(REPO_ROOT) if src.is_relative_to(REPO_ROOT) else src}\n"
            "  The dataset card names this file unconditionally. Run "
            "`make paired` (matched-pair artifacts) or `make download` "
            "(supplemental arms) and retry.")
    return src


def _verify_source_hashes(staging: Path) -> None:
    """Assert each paired artifact cites the hash of the file actually shipped.

    Sanitization rewrites trace bytes, so an artifact computed before
    ``--apply`` records a hash that no released file has. This is the check that
    makes "recomputes from the released traces" verifiable rather than asserted.
    """
    print("\n==> Verifying artifact source hashes against staged traces...")
    for check in SOURCE_HASH_CHECKS:
        artifact = _require(REPO_ROOT / check["artifact"], "paired artifact")
        staged = _require(staging / check["staged"], "staged trace")
        # hash_key is a dotted path so nested provenance blocks can be cited.
        recorded = json.loads(artifact.read_text(encoding="utf-8"))
        for part in check["hash_key"].split("."):
            recorded = (recorded or {}).get(part) if isinstance(recorded, dict) else None
        actual = hashlib.sha256(staged.read_bytes()).hexdigest()
        name = Path(check["artifact"]).name
        if recorded != actual:
            raise SystemExit(
                f"FAILED: {name}.{check['hash_key']} does not match the staged "
                f"{check['staged']}.\n"
                f"  artifact records: {recorded}\n"
                f"  staged file is:   {actual}\n"
                "  The artifact was computed from pre-sanitization bytes. "
                "Re-run `make paired` AFTER sanitization, then rebuild.")
        print(f"  {name} -> {check['staged']}: {actual[:16]}... OK")


def _assert_no_excluded_files(staging: Path) -> None:
    """Refuse to leave upload-forbidden files in a bundle.

    The documented upload command copies the staging directory recursively, so a
    stray pre-sanitization backup would publish exactly the PII that
    sanitization removed.
    """
    stray = sorted(p for p in staging.rglob("*")
                   if p.is_file() and p.name.endswith(STAGING_EXCLUDE_SUFFIXES))
    if stray:
        names = ", ".join(str(p.relative_to(staging)) for p in stray[:5])
        raise SystemExit(
            f"FAILED: {len(stray)} upload-forbidden file(s) in "
            f"{staging.relative_to(REPO_ROOT)}: {names}"
            f"{' ...' if len(stray) > 5 else ''}\n"
            "  These carry pre-sanitization content and the upload command is "
            "recursive. Remove them before uploading.")


def _stage_variant(variant: str, config: dict) -> Path:
    """Build one staging bundle. Both variants stage identical file content."""
    staging = config["dir"] / "mcphunt-agent-traces"
    print(f"\n{'=' * 60}\n==> Staging '{variant}' bundle -> "
          f"{staging.relative_to(REPO_ROOT)}\n{'=' * 60}")

    if staging.exists():
        shutil.rmtree(staging)
    for sub in ("main", "mitigation", "live_guard_defense",
                "browser_replication", "meta",
                RECALL_EVALUATION["dst_subdir"]):
        (staging / sub).mkdir(parents=True)

    # Main traces
    print("==> Staging main traces...")
    for model in MAIN_MODELS:
        src = _require(RESULTS_DIR / "agent_traces" / model / "agent_traces.json",
                       f"main trace file for {model}")
        dst = staging / "main" / f"{model}.json"
        shutil.copy2(src, dst)
        print(f"  {model}: {dst.stat().st_size / (1024 * 1024):.1f} MB")

    # Mitigation traces
    print("\n==> Staging mitigation traces...")
    mitig_dir = RESULTS_DIR / "mitigation_traces"
    if mitig_dir.exists():
        for subdir in sorted(mitig_dir.iterdir()):
            if not subdir.is_dir():
                continue
            jsons = list(subdir.glob("*.json"))
            if not jsons:
                continue
            dst = staging / "mitigation" / f"{subdir.name}.json"
            shutil.copy2(jsons[0], dst)
            print(f"  {subdir.name}: {dst.stat().st_size / (1024 * 1024):.1f} MB")

    # Aggregate meta files
    print("\n==> Staging meta files...")
    for name in ["regression_data.csv",
                 "mitigation_analysis/mitigation_results.json"]:
        src = _require(RESULTS_DIR / name, "meta file")
        shutil.copy2(src, staging / "meta" / src.name)
        print(f"  {src.name}")

    # Live-guard defense arm (DeepSeek-only, paired with main/)
    print("\n==> Staging live-guard defense-arm traces...")
    lg_src = _require(REPO_ROOT / LIVE_GUARD_DEFENSE["src"],
                      "live-guard defense arm")
    lg_dst = (staging / LIVE_GUARD_DEFENSE["dst_subdir"]
              / LIVE_GUARD_DEFENSE["dst_name"])
    shutil.copy2(lg_src, lg_dst)
    print(f"  {LIVE_GUARD_DEFENSE['dst_name']}: "
          f"{lg_dst.stat().st_size / (1024 * 1024):.1f} MB")

    # Browser-mechanism cross-arm replication (baseline + defense)
    print("\n==> Staging browser-replication traces...")
    for entry in BROWSER_REPLICATION:
        src = _require(REPO_ROOT / entry["src"], "browser-replication arm")
        dst = staging / entry["dst_subdir"] / entry["dst_name"]
        shutil.copy2(src, dst)
        print(f"  {entry['dst_name']}: "
              f"{dst.stat().st_size / (1024 * 1024):.1f} MB")

    # Paired-analysis summaries (required: quoted externally)
    print("\n==> Staging paired-analysis meta files...")
    for rel in PAIRED_META:
        src = _require(REPO_ROOT / rel, "paired-analysis artifact")
        shutil.copy2(src, staging / "meta" / src.name)
        print(f"  {src.name}")

    # Judge-based recall diagnostic
    print("\n==> Staging recall-evaluation artifact...")
    rc_src = _require(REPO_ROOT / RECALL_EVALUATION["src"],
                      "recall-evaluation artifact")
    shutil.copy2(rc_src, staging / RECALL_EVALUATION["dst_subdir"]
                 / RECALL_EVALUATION["dst_name"])
    print(f"  {RECALL_EVALUATION['dst_name']}")

    # Croissant metadata + dataset card
    croissant_src = _require(RELEASE_DIR / config["croissant"],
                             f"Croissant metadata for '{variant}'")
    shutil.copy2(croissant_src, staging / "croissant.json")
    (staging / "README.md").write_text(_dataset_card(config),
                                       encoding="utf-8")

    _verify_source_hashes(staging)
    _assert_no_excluded_files(staging)

    total_files = sum(1 for p in staging.rglob("*") if p.is_file())
    total_size = sum(p.stat().st_size for p in staging.rglob("*") if p.is_file())
    print(f"\n==> Staged {total_files} files "
          f"({total_size / (1024**2):.0f} MB) in '{variant}'")
    return staging


def main(skip_sanitize: bool = False,
         variants: list[str] | None = None) -> None:
    print("Preparing HuggingFace release for MCPHunt Agent Traces\n")

    selected = variants or list(STAGING_VARIANTS)
    unknown = [v for v in selected if v not in STAGING_VARIANTS]
    if unknown:
        raise SystemExit(f"unknown staging variant(s): {unknown}; "
                         f"choose from {list(STAGING_VARIANTS)}")

    # 1. Sanitize traces FIRST, so the paired artifacts recomputed in step 2
    #    hash the same bytes that get staged in step 3.
    if not skip_sanitize:
        print("==> Sanitizing traces...")
        _run([sys.executable,
              str(REPO_ROOT / "scripts" / "sanitize_traces.py"), "--apply"],
             "Sanitize traces")
        print()

        # 2. Recompute the matched-pair artifacts from the sanitized traces.
        #    Order matters: doing this before sanitization would record a
        #    source hash no released file carries.
        print("==> Recomputing matched-pair analyses from sanitized traces...")
        for script in ("compute_hard_negative_ci.py",
                       "analyze_paired_live_guard.py"):
            _run([sys.executable, str(REPO_ROOT / "scripts" / script)],
                 f"Recompute {script}")
        print()

    # 3. Stage every requested bundle from the same inputs.
    staged = {v: _stage_variant(v, STAGING_VARIANTS[v]) for v in selected}

    print("\n" + "=" * 60)
    print("UPLOAD INSTRUCTIONS:")
    print("=" * 60)
    print("\n1. pip install huggingface_hub\n2. huggingface-cli login")
    for variant, staging in staged.items():
        print(f"\n[{variant}]\n3. huggingface-cli upload "
              f"{STAGING_VARIANTS[variant]['hf_repo']} \\\n"
              f"     {staging} . --repo-type dataset")
    print("\n4. Verify downloads with `make download && make paired`. "
          "Use --repo-id or MCPHUNT_HF_REPO_ID to override the branch default.\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--skip-sanitize", action="store_true",
                        help="skip sanitization AND the paired-artifact "
                             "recompute (assumes results/ is already clean)")
    parser.add_argument("--variant", action="append", dest="variants",
                        choices=sorted(STAGING_VARIANTS),
                        help="stage only this bundle (repeatable); "
                             "default: all")
    args = parser.parse_args()
    main(skip_sanitize=args.skip_sanitize, variants=args.variants)
