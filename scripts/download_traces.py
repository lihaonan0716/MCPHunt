#!/usr/bin/env python3
"""
Download MCPHunt agent traces from HuggingFace to results/.

Restores the directory layout expected by reproduce_paper_tables.py and
other evaluation scripts.

Usage:
    python3 scripts/download_traces.py              # download all
    python3 scripts/download_traces.py --main-only   # main benchmark only
"""
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "results"

# ── HuggingFace dataset coordinates ──────────────────────────────────
# TODO: Update this after uploading to HuggingFace
HF_REPO_ID = "lihaonan0716/mcphunt-agent-traces"

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


def _ensure_huggingface_hub():
    try:
        from huggingface_hub import hf_hub_download, snapshot_download  # noqa: F401
        return True
    except ImportError:
        print("ERROR: huggingface_hub is required.")
        print("  Install with: pip install huggingface_hub")
        return False


def download_all(main_only: bool = False) -> None:
    from huggingface_hub import hf_hub_download

    print(f"Downloading MCPHunt traces from {HF_REPO_ID}")
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
            repo_id=HF_REPO_ID,
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
    print("\n==> Mitigation traces (3 models x 4 levels, 2885 traces)")
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
            repo_id=HF_REPO_ID,
            filename=f"mitigation/{dirname}.json",
            repo_type="dataset",
            local_dir=RESULTS_DIR / "_hf_cache",
        )
        target_file = target_dir / "agent_traces.json"
        shutil.copy2(downloaded, target_file)
        size_mb = target_file.stat().st_size / (1024 * 1024)
        print(f"{size_mb:.1f} MB")

    # Download meta files
    print("\n==> Meta files")
    meta_targets = {
        "meta/regression_data.csv": RESULTS_DIR / "regression_data.csv",
        "meta/mitigation_results.json": RESULTS_DIR / "mitigation_analysis" / "mitigation_results.json",
    }
    for hf_path, local_path in meta_targets.items():
        local_path.parent.mkdir(parents=True, exist_ok=True)
        if local_path.exists():
            print(f"  {local_path.name}: already exists, skipping")
            continue
        print(f"  {local_path.name}: downloading...", end=" ", flush=True)
        downloaded = hf_hub_download(
            repo_id=HF_REPO_ID,
            filename=hf_path,
            repo_type="dataset",
            local_dir=RESULTS_DIR / "_hf_cache",
        )
        shutil.copy2(downloaded, local_path)
        print("OK")

    _cleanup_cache()

    # Summary
    n_main = sum(1 for m in MAIN_MODELS if (main_dir / m / "agent_traces.json").exists())
    n_mitig = sum(1 for d in MITIGATION_DIRS if (mitig_dir / d).exists())
    print(f"\nDone: {n_main} main + {n_mitig} mitigation trace files in {RESULTS_DIR}")
    print("Run `make reproduce` to reproduce paper tables.")


def _cleanup_cache():
    cache_dir = RESULTS_DIR / "_hf_cache"
    if cache_dir.exists():
        shutil.rmtree(cache_dir)


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--main-only", action="store_true",
                        help="Download only main benchmark traces (skip mitigation)")
    args = parser.parse_args()

    if not _ensure_huggingface_hub():
        sys.exit(1)

    download_all(main_only=args.main_only)


if __name__ == "__main__":
    main()
