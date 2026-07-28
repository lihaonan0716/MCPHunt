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
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_DIR = REPO_ROOT / "results"
RELEASE_DIR = REPO_ROOT / "artifacts" / "release"
HF_STAGING = REPO_ROOT / "artifacts" / "huggingface-staging" / "mcphunt-agent-traces"

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
PAIRED_META = [
    "results/live_guard_replication/paired_live_guard_analysis.json",
    "results/mitigation_analysis/live_guard_deepseek_v4_flash_paired.json",
]

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
  `paired_live_guard_analysis.json` and
  `live_guard_deepseek_v4_flash_paired.json`.

## Reproduction

```bash
git clone <repo-url> && cd mcphunt
pip install -e .
make download    # downloads this dataset to results/
make reproduce   # reproduces every number in the paper
```

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
@misc{mcphunt2026,
  title={MCPHunt: An Evaluation Framework for Cross-Boundary Data Propagation
         in Multi-Server MCP Agents},
  author={Anonymous},
  year={2026}
}
```

## License

CC-BY-4.0
"""


def _run(cmd: list[str], description: str) -> None:
    print(f"  $ {' '.join(cmd)}")
    result = subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"FAILED: {description}")


def main(skip_sanitize: bool = False) -> None:
    print("Preparing HuggingFace release for MCPHunt Agent Traces\n")

    # 1. Sanitize traces
    if not skip_sanitize:
        print("==> Sanitizing traces...")
        _run(
            [sys.executable, str(REPO_ROOT / "scripts" / "sanitize_traces.py"), "--apply"],
            "Sanitize traces",
        )
        print()

    # 2. Set up staging directory
    if HF_STAGING.exists():
        shutil.rmtree(HF_STAGING)
    (HF_STAGING / "main").mkdir(parents=True)
    (HF_STAGING / "mitigation").mkdir(parents=True)
    (HF_STAGING / "live_guard_defense").mkdir(parents=True)
    (HF_STAGING / "browser_replication").mkdir(parents=True)
    (HF_STAGING / "meta").mkdir(parents=True)

    # 3. Copy main traces
    print("==> Staging main traces...")
    for model in MAIN_MODELS:
        src = RESULTS_DIR / "agent_traces" / model / "agent_traces.json"
        if not src.exists():
            print(f"  WARNING: {src} not found, skipping")
            continue
        dst = HF_STAGING / "main" / f"{model}.json"
        shutil.copy2(src, dst)
        size_mb = dst.stat().st_size / (1024 * 1024)
        print(f"  {model}: {size_mb:.1f} MB")

    # 4. Copy mitigation traces
    print("\n==> Staging mitigation traces...")
    mitig_dir = RESULTS_DIR / "mitigation_traces"
    if mitig_dir.exists():
        for subdir in sorted(mitig_dir.iterdir()):
            if not subdir.is_dir():
                continue
            jsons = list(subdir.glob("*.json"))
            if not jsons:
                continue
            src = jsons[0]
            dst = HF_STAGING / "mitigation" / f"{subdir.name}.json"
            shutil.copy2(src, dst)
            size_mb = dst.stat().st_size / (1024 * 1024)
            print(f"  {subdir.name}: {size_mb:.1f} MB")

    # 5. Copy meta files
    print("\n==> Staging meta files...")
    for name in ["regression_data.csv", "mitigation_analysis/mitigation_results.json"]:
        src = RESULTS_DIR / name
        if src.exists():
            dst = HF_STAGING / "meta" / src.name
            shutil.copy2(src, dst)
            print(f"  {src.name}")

    # 5a. Copy live-guard defense-arm traces (DeepSeek-only, paired with main/)
    print("\n==> Staging live-guard defense-arm traces...")
    lg_src = REPO_ROOT / LIVE_GUARD_DEFENSE["src"]
    if lg_src.exists():
        lg_dst = HF_STAGING / LIVE_GUARD_DEFENSE["dst_subdir"] / LIVE_GUARD_DEFENSE["dst_name"]
        shutil.copy2(lg_src, lg_dst)
        size_mb = lg_dst.stat().st_size / (1024 * 1024)
        print(f"  {LIVE_GUARD_DEFENSE['dst_name']}: {size_mb:.1f} MB")
    else:
        print(f"  WARNING: {lg_src} not found, skipping live-guard defense arm")

    # 5b. Copy browser-mechanism cross-arm replication (baseline + defense)
    print("\n==> Staging browser-replication traces...")
    for entry in BROWSER_REPLICATION:
        src = REPO_ROOT / entry["src"]
        if not src.exists():
            print(f"  WARNING: {src} not found, skipping")
            continue
        dst = HF_STAGING / entry["dst_subdir"] / entry["dst_name"]
        shutil.copy2(src, dst)
        size_mb = dst.stat().st_size / (1024 * 1024)
        print(f"  {entry['dst_name']}: {size_mb:.1f} MB")

    # 5c. Copy paired-analysis summaries
    print("\n==> Staging paired-analysis meta files...")
    for rel in PAIRED_META:
        src = REPO_ROOT / rel
        if src.exists():
            dst = HF_STAGING / "meta" / src.name
            shutil.copy2(src, dst)
            print(f"  {src.name}")
        else:
            print(f"  WARNING: {rel} not found, skipping paired-analysis file")

    # 6. Copy Croissant metadata
    croissant_src = RELEASE_DIR / "croissant.json"
    if croissant_src.exists():
        shutil.copy2(croissant_src, HF_STAGING / "croissant.json")

    # 7. Write dataset card
    (HF_STAGING / "README.md").write_text(DATASET_CARD, encoding="utf-8")

    # 8. Summary
    total_files = sum(1 for _ in HF_STAGING.rglob("*") if _.is_file())
    total_size = sum(f.stat().st_size for f in HF_STAGING.rglob("*") if f.is_file())
    print(f"\n==> Staged {total_files} files ({total_size / (1024**2):.0f} MB)")
    print(f"    Location: {HF_STAGING.relative_to(REPO_ROOT)}")

    print("\n" + "=" * 60)
    print("UPLOAD INSTRUCTIONS:")
    print("=" * 60)
    print(f"""
1. pip install huggingface_hub
2. huggingface-cli login
3. huggingface-cli upload mcphunt-benchmark/mcphunt-agent-traces \\
     {HF_STAGING} . --repo-type dataset
4. Update the dataset URL in scripts/download_traces.py
""")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--skip-sanitize", action="store_true")
    args = parser.parse_args()
    main(skip_sanitize=args.skip_sanitize)
