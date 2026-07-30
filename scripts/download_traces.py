#!/usr/bin/env python3
"""
Download MCPHunt agent traces from HuggingFace to results/.

Restores the directory layout expected by reproduce_paper_tables.py and
other evaluation scripts, including the supplemental arms that the
matched-pair analyses (`make paired`) read from their default paths.

Usage:
    python3 scripts/download_traces.py              # download all
    python3 scripts/download_traces.py --main-only   # main benchmark only
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "results"

# ── HuggingFace dataset coordinates ──────────────────────────────────
# Default branch-local release dataset. Override precedence is:
#   1. --repo-id
#   2. MCPHUNT_HF_REPO_ID
#   3. this branch default
DEFAULT_HF_REPO_ID = "mcphunt-benchmark/mcphunt-agent-traces"
HF_REPO_ENV_VAR = "MCPHUNT_HF_REPO_ID"

MAIN_MODELS = [
    "gpt_5_4",
    "gpt_5_2",
    "deepseek_v4_flash",
    "gemini_3_1_pro_preview",
    "MiniMax_M2_7",
]

MITIGATION_DIRS = [
    "gpt54_m0", "gpt54_m1", "gpt54_m2", "gpt54_m3",
    "deepseek_m0_rv1", "deepseek_m1_rv1", "deepseek_m2_rv1", "deepseek_m3_rv1",
    "minimax_m0_rv1", "minimax_m1_rv1", "minimax_m2_rv1", "minimax_m3_rv1",
]

# Supplemental arms restored to the exact paths their analysis scripts default
# to, so `make download && make paired` works in a fresh clone. Each entry maps
# one released file to the working-tree path a script reads:
#
#   live_guard_defense/  -> generate_results_macros.py (defense-arm trace count)
#   browser_replication/ -> analyze_paired_live_guard.py (DEFAULT_BASELINE /
#                           DEFAULT_DEFENSE); without these the paired
#                           live-guard target aborts on a missing input.
SUPPLEMENTAL_FILES = [
    ("live_guard_defense/deepseek_v4_flash.json",
     "agent_traces/deepseek_v4_flash/agent_traces_deft.json"),
    ("browser_replication/deepseek_v4_flash_baseline.json",
     "agent_traces_b3_replication/deepseek_v4_flash/agent_traces_browser.json"),
    ("browser_replication/deepseek_v4_flash_defense.json",
     "agent_traces_b3_replication/deepseek_v4_flash/agent_traces_browser_deft.json"),
]

# Released paired-analysis artifacts. Downloaded as a REFERENCE copy so a
# reviewer can diff a locally recomputed artifact against the published one;
# `make paired` overwrites them from the traces.
PAIRED_META_FILES = [
    ("meta/paired_live_guard_analysis.json",
     "live_guard_replication/paired_live_guard_analysis.json"),
    ("meta/live_guard_deepseek_v4_flash_paired.json",
     "mitigation_analysis/live_guard_deepseek_v4_flash_paired.json"),
    ("meta/hard_negative_ci.json",
     "hard_negative_analysis/hard_negative_ci.json"),
]


def _ensure_huggingface_hub():
    try:
        from huggingface_hub import hf_hub_download, snapshot_download  # noqa: F401
        return True
    except ImportError:
        print("ERROR: huggingface_hub is required.")
        print("  Install with: pip install huggingface_hub")
        return False


def resolve_repo_id(cli_repo_id: str | None) -> tuple[str, str]:
    """Resolve the dataset repo id with explicit, testable precedence."""
    if cli_repo_id:
        return (cli_repo_id, "CLI")
    env_repo_id = os.environ.get(HF_REPO_ENV_VAR, "").strip()
    if env_repo_id:
        return (env_repo_id, HF_REPO_ENV_VAR)
    return (DEFAULT_HF_REPO_ID, "default")


def _fetch(hf_hub_download, repo_id: str, hf_path: str, local_path: Path) -> None:
    """Download one released file to an exact working-tree path."""
    local_path.parent.mkdir(parents=True, exist_ok=True)
    label = f"{local_path.parent.name}/{local_path.name}"
    if local_path.exists():
        print(f"  {label}: already exists, skipping")
        return
    print(f"  {label}: downloading...", end=" ", flush=True)
    downloaded = hf_hub_download(
        repo_id=repo_id,
        filename=hf_path,
        repo_type="dataset",
        local_dir=RESULTS_DIR / "_hf_cache",
    )
    shutil.copy2(downloaded, local_path)
    size_mb = local_path.stat().st_size / (1024 * 1024)
    print(f"{size_mb:.1f} MB" if size_mb >= 0.1 else "OK")


def download_all(repo_id: str, main_only: bool = False) -> None:
    from huggingface_hub import hf_hub_download

    print(f"Downloading MCPHunt traces from {repo_id}")
    print(f"Target directory: {RESULTS_DIR}\n")

    # Download main traces
    print("==> Main benchmark traces (5 models, 3615 traces)")
    main_dir = RESULTS_DIR / "agent_traces"
    for model in MAIN_MODELS:
        target_dir = main_dir / model
        target_dir.mkdir(parents=True, exist_ok=True)
        target_file = target_dir / "agent_traces.json"

        if target_file.exists():
            print(f"  {model}: already exists, skipping")
            continue

        print(f"  {model}: downloading...", end=" ", flush=True)
        downloaded = hf_hub_download(
            repo_id=repo_id,
            filename=f"main/{model}.json",
            repo_type="dataset",
            local_dir=RESULTS_DIR / "_hf_cache",
        )
        shutil.copy2(downloaded, target_file)
        size_mb = target_file.stat().st_size / (1024 * 1024)
        print(f"{size_mb:.1f} MB")

    if main_only:
        print("\n--main-only: skipping mitigation traces")
        _cleanup_cache()
        return

    # Download mitigation traces
    print("\n==> Mitigation traces (3 models x 4 levels, 2706 traces)")
    mitig_dir = RESULTS_DIR / "mitigation_traces"
    for dirname in MITIGATION_DIRS:
        target_dir = mitig_dir / dirname
        target_dir.mkdir(parents=True, exist_ok=True)

        existing = list(target_dir.glob("*.json"))
        if existing:
            print(f"  {dirname}: already exists, skipping")
            continue

        print(f"  {dirname}: downloading...", end=" ", flush=True)
        downloaded = hf_hub_download(
            repo_id=repo_id,
            filename=f"mitigation/{dirname}.json",
            repo_type="dataset",
            local_dir=RESULTS_DIR / "_hf_cache",
        )
        target_file = target_dir / "agent_traces.json"
        shutil.copy2(downloaded, target_file)
        size_mb = target_file.stat().st_size / (1024 * 1024)
        print(f"{size_mb:.1f} MB")

    # Download supplemental arms (live-guard defense + browser replication).
    # These restore the DEFAULT input paths of analyze_paired_live_guard.py and
    # the defense-arm count in generate_results_macros.py, so `make paired`
    # is runnable straight after `make download`.
    print("\n==> Supplemental arms (live-guard defense + browser replication)")
    for hf_path, rel_target in SUPPLEMENTAL_FILES:
        _fetch(hf_hub_download, repo_id, hf_path, RESULTS_DIR / rel_target)

    # Download meta files
    print("\n==> Meta files")
    meta_targets = [
        ("meta/regression_data.csv", "regression_data.csv"),
        ("meta/mitigation_results.json",
         "mitigation_analysis/mitigation_results.json"),
    ]
    for hf_path, rel_target in meta_targets + PAIRED_META_FILES:
        _fetch(hf_hub_download, repo_id, hf_path, RESULTS_DIR / rel_target)

    _cleanup_cache()

    # Summary
    n_main = sum(1 for m in MAIN_MODELS if (main_dir / m / "agent_traces.json").exists())
    n_mitig = sum(1 for d in MITIGATION_DIRS if (mitig_dir / d).exists())
    n_supp = sum(1 for _, rel in SUPPLEMENTAL_FILES
                 if (RESULTS_DIR / rel).exists())
    print(f"\nDone: {n_main} main + {n_mitig} mitigation trace files "
          f"+ {n_supp}/{len(SUPPLEMENTAL_FILES)} supplemental arms "
          f"in {RESULTS_DIR}")
    print("Run `make reproduce` to reproduce paper tables, "
          "`make paired` to recompute the matched-pair analyses.")


def _cleanup_cache():
    cache_dir = RESULTS_DIR / "_hf_cache"
    if cache_dir.exists():
        shutil.rmtree(cache_dir)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--main-only", action="store_true",
                        help="Download only main benchmark traces (skip mitigation)")
    parser.add_argument("--repo-id",
                        help=("HuggingFace dataset repo id override. "
                              f"Precedence: --repo-id > {HF_REPO_ENV_VAR} > "
                              f"{DEFAULT_HF_REPO_ID}"))
    args = parser.parse_args()

    if not _ensure_huggingface_hub():
        sys.exit(1)

    repo_id, source = resolve_repo_id(args.repo_id)
    print(f"Resolved dataset repo: {repo_id} ({source})")
    download_all(repo_id=repo_id, main_only=args.main_only)


if __name__ == "__main__":
    main()
