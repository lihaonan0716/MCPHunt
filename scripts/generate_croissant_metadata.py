#!/usr/bin/env python3
"""
Generate Croissant metadata for the MCPHunt agent traces dataset.

NeurIPS 2026 Evaluations & Datasets Track requires Croissant format with
core and Responsible AI (RAI) fields.

Outputs:
  - artifacts/release/croissant.json

Croissant spec: https://docs.mlcommons.org/croissant/docs/croissant-spec.html

Usage:
    python3 scripts/generate_croissant_metadata.py
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_DIR = REPO_ROOT / "artifacts" / "release"
DATASET_VERSION = "1.1.0"
PUBLICATION_DATE = "2026-05-06"

CRS_AUDIT_DIR = DEFAULT_OUT_DIR / "crs_audit"


def _crs_audit_stats() -> Dict[str, Any]:
    """Derive the CRS inter-annotator statistics from the committed raw labels.

    Reuses the verified helpers in ``scripts/score_annotation.py`` so the numbers
    written into the released metadata are computed from the raw labels, never
    hand-typed (project invariant #1). Item order = annotator-1 row order, the
    same canonical order the scorer and its pinning test use.
    """
    if str(REPO_ROOT / "scripts") not in sys.path:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import score_annotation as sa

    a = sa._load_sheet(CRS_AUDIT_DIR / "annotation_1.csv")
    b = sa._load_sheet(CRS_AUDIT_DIR / "annotation_2.csv")
    if set(a) != set(b):
        raise SystemExit("crs_audit: annotation sheets cover different task sets.")
    ids = list(a)  # annotator-1 canonical order
    va = [a[t] for t in ids]
    vb = [b[t] for t in ids]
    n = len(ids)
    agree = sum(1 for x, y in zip(va, vb) if x == y)
    kappa = sa._cohen_kappa(va, vb)
    lo, hi = sa._bootstrap_kappa_ci(va, vb, sa.BOOTSTRAP_RESAMPLES, sa.BOOTSTRAP_SEED)
    return {
        "n": n,
        "agree": agree,
        "agree_pct": 100.0 * agree / n,
        "kappa": kappa,
        "ci_lo": lo,
        "ci_hi": hi,
        "resamples": sa.BOOTSTRAP_RESAMPLES,
    }

# TODO: Update after uploading to HuggingFace
HF_DATASET_URL = "https://huggingface.co/datasets/lihaonan0716/mcphunt-agent-traces"

MAIN_MODELS = [
    "gpt_5_4", "gpt_5_2", "deepseek_v4_flash",
    "gemini_3_1_pro_preview", "MiniMax_M2_7",
]


def _croissant_context() -> Dict[str, Any]:
    return {
        "@language": "en",
        "@vocab": "https://schema.org/",
        "citeAs": "cr:citeAs",
        "column": "cr:column",
        "conformsTo": "dct:conformsTo",
        "cr": "http://mlcommons.org/croissant/",
        "rai": "http://mlcommons.org/croissant/RAI/",
        "data": {"@id": "cr:data", "@type": "@json"},
        "dataType": {"@id": "cr:dataType", "@type": "@vocab"},
        "dct": "http://purl.org/dc/terms/",
        "examples": {"@id": "cr:examples", "@type": "@json"},
        "extract": "cr:extract",
        "field": "cr:field",
        "fileProperty": "cr:fileProperty",
        "fileObject": "cr:fileObject",
        "fileSet": "cr:fileSet",
        "format": "cr:format",
        "includes": "cr:includes",
        "isLiveDataset": "cr:isLiveDataset",
        "jsonPath": "cr:jsonPath",
        "key": "cr:key",
        "md5": "cr:md5",
        "parentField": "cr:parentField",
        "path": "cr:path",
        "recordSet": "cr:recordSet",
        "references": "cr:references",
        "regex": "cr:regex",
        "repeated": "cr:repeated",
        "replace": "cr:replace",
        "sc": "https://schema.org/",
        "separator": "cr:separator",
        "source": "cr:source",
        "subField": "cr:subField",
        "transform": "cr:transform",
    }


def _field(field_id: str, description: str, dtype: str, json_path: str, parent: str) -> Dict[str, Any]:
    return {
        "@type": "cr:Field",
        "@id": field_id,
        "name": field_id,
        "description": description,
        "dataType": dtype,
        "source": {
            "fileObject": {"@id": parent},
            "extract": {"jsonPath": json_path},
        },
    }


def build_metadata() -> Dict[str, Any]:
    crs = _crs_audit_stats()
    crs_protocol = (
        "The CRS labels were not crowdsourced. A post-submission independent "
        "audit of the CRS labels was subsequently performed by two annotators "
        "who are not authors, each labeling all "
        f"{crs['n']} tasks blind to trace outcomes; the raw labels are "
        "released under artifacts/release/crs_audit/ so the reliability "
        "statistic is reproducible."
    )
    crs_analysis = (
        "For the CRS stratification, a post-submission independent human audit "
        "(two non-author annotators, blind to outcomes) yielded inter-annotator "
        f"agreement of {crs['agree']}/{crs['n']} = {crs['agree_pct']:.1f}% and "
        f"Cohen's kappa = {crs['kappa']:.2f} (percentile bootstrap 95% CI "
        f"[{crs['ci_lo']:.2f}, {crs['ci_hi']:.2f}], {crs['resamples']} "
        "resamples). This statistic reflects a post-submission audit, not a "
        "pre-submission or pre-registered study; the raw labels "
        "(artifacts/release/crs_audit/) and the scoring script "
        "(scripts/score_annotation.py) make it fully reproducible, and "
        "tests/test_crs_audit_reproducibility.py pins the reported values."
    )
    distribution = []
    for model in MAIN_MODELS:
        distribution.append({
            "@type": "cr:FileObject",
            "@id": f"main_{model}",
            "name": f"main/{model}.json",
            "contentUrl": f"main/{model}.json",
            "encodingFormat": "application/json",
        })

    # Live-guard defense arm (DeepSeek-only, paired with main/deepseek_v4_flash.json).
    distribution.append({
        "@type": "cr:FileObject",
        "@id": "live_guard_defense_deepseek_v4_flash",
        "name": "live_guard_defense/deepseek_v4_flash.json",
        "contentUrl": "live_guard_defense/deepseek_v4_flash.json",
        "encodingFormat": "application/json",
    })

    # Browser-mechanism cross-arm replication (DeepSeek-only, 39 baseline + 39 defense).
    distribution.append({
        "@type": "cr:FileObject",
        "@id": "browser_replication_deepseek_baseline",
        "name": "browser_replication/deepseek_v4_flash_baseline.json",
        "contentUrl": "browser_replication/deepseek_v4_flash_baseline.json",
        "encodingFormat": "application/json",
    })
    distribution.append({
        "@type": "cr:FileObject",
        "@id": "browser_replication_deepseek_defense",
        "name": "browser_replication/deepseek_v4_flash_defense.json",
        "contentUrl": "browser_replication/deepseek_v4_flash_defense.json",
        "encodingFormat": "application/json",
    })

    distribution.append({
        "@type": "cr:FileObject",
        "@id": "meta_regression",
        "name": "meta/regression_data.csv",
        "contentUrl": "meta/regression_data.csv",
        "encodingFormat": "text/csv",
    })

    # Paired-analysis summaries for the runtime taint-guard evaluation.
    distribution.append({
        "@type": "cr:FileObject",
        "@id": "meta_paired_live_guard_analysis",
        "name": "meta/paired_live_guard_analysis.json",
        "contentUrl": "meta/paired_live_guard_analysis.json",
        "encodingFormat": "application/json",
    })
    distribution.append({
        "@type": "cr:FileObject",
        "@id": "meta_live_guard_deepseek_v4_flash_paired",
        "name": "meta/live_guard_deepseek_v4_flash_paired.json",
        "contentUrl": "meta/live_guard_deepseek_v4_flash_paired.json",
        "encodingFormat": "application/json",
    })

    trace_fields = [
        _field("trace_id", "Unique trace identifier.", "sc:Text", "$.traces[*].trace_id", "main_gpt_5_4"),
        _field("task_id", "Task identifier from the 147-task registry.", "sc:Text", "$.traces[*].task_id", "main_gpt_5_4"),
        _field("model", "LLM model identifier.", "sc:Text", "$.traces[*].model", "main_gpt_5_4"),
        _field("env_type", "Environment variant: risky_v1/v2/v3, benign, hard_neg_v1/v2/v3.", "sc:Text", "$.traces[*].env_type", "main_gpt_5_4"),
        _field("risk_mechanism", "Mechanism family: file_to_file, browser_to_local, etc.", "sc:Text", "$.traces[*].risk_mechanism", "main_gpt_5_4"),
        _field("risk_type", "Control type: risk, benign, hard_negative.", "sc:Text", "$.traces[*].risk_type", "main_gpt_5_4"),
        _field("outcome", "Outcome classification: safe_success, unsafe_success, safe_failure, unsafe_failure.", "sc:Text", "$.traces[*].outcome", "main_gpt_5_4"),
        _field("task_completed", "Whether the agent completed the requested task.", "sc:Boolean", "$.traces[*].task_completed", "main_gpt_5_4"),
        _field("num_events", "Number of tool-call events in the trace.", "sc:Integer", "$.traces[*].num_events", "main_gpt_5_4"),
        _field("num_turns", "Number of LLM turns.", "sc:Integer", "$.traces[*].num_turns", "main_gpt_5_4"),
        _field("duration_s", "Wall-clock duration in seconds.", "sc:Float", "$.traces[*].duration_s", "main_gpt_5_4"),
        _field("mitigation_level", "Prompt mitigation level: none, generic, moderate, detailed.", "sc:Text", "$.traces[*].mitigation_level", "main_gpt_5_4"),
    ]

    meta = {
        "@context": _croissant_context(),
        "@type": "sc:Dataset",
        "conformsTo": "http://mlcommons.org/croissant/1.0",
        "version": DATASET_VERSION,
        "license": "https://creativecommons.org/licenses/by/4.0/",
        "creator": {"@type": "sc:Organization", "name": "Haonan Li"},
        "publisher": {"@type": "sc:Organization", "name": "Haonan Li"},
        "datePublished": PUBLICATION_DATE,
        "name": "MCPHunt Agent Traces",
        "description": (
            "Agent execution traces measuring cross-boundary data propagation "
            "in multi-server MCP agents. Contains 3,615 main-benchmark traces "
            "from 5 models across 147 tasks and 9 mechanism families, plus "
            "2,706 mitigation-study traces. A DeepSeek-V4-Flash runtime "
            "taint-guard defense arm ships 387 additional paired traces "
            "(live_guard_defense/) and a browser-mechanism cross-arm "
            "replication ships 78 additional traces "
            "(browser_replication/: 39 baseline + 39 defense) for a total of "
            "6,786 released traces. Each trace includes the full tool-call "
            "event log, 11 tiered binary risk signals plus one diagnostic "
            "signal computed by canary-based taint tracking, CRS "
            "stratification labels, and outcome classification."
        ),
        "keywords": [
            "MCP", "Model Context Protocol", "agent safety",
            "data propagation", "cross-boundary", "canary tracking",
            "tool-use", "benchmark", "evaluation",
        ],
        "url": HF_DATASET_URL,
        "citeAs": (
            "@article{mcphunt2026,\n"
            "  title = {MCPHunt: An Evaluation Framework for Cross-Boundary "
            "Data Propagation in Multi-Server MCP Agents},\n"
            "  author = {Li, Haonan and Sun, Tianjun and Wang, Yongqing and "
            "Zhang, Qisheng},\n"
            "  year = {2026},\n"
            "  eprint = {2604.27819},\n"
            "  archivePrefix = {arXiv},\n"
            "  primaryClass = {cs.CR},\n"
            "  url = {https://arxiv.org/abs/2604.27819}\n"
            "}"
        ),
        "distribution": distribution,
        "recordSet": [
            {
                "@type": "cr:RecordSet",
                "@id": "agent_traces",
                "name": "agent_traces",
                "description": (
                    "Per-trace records from multi-server MCP agent execution. "
                    "Each record represents one complete task execution with "
                    "canary-based propagation labels."
                ),
                "field": trace_fields,
            }
        ],
        # Responsible AI fields
        "rai:dataCollection": (
            "All traces are collected by running LLM agents (via OpenAI-compatible "
            "APIs) against 8 MCP servers in controlled sandbox environments. "
            "Workspaces contain synthetic canary credentials; no real user data "
            "or production systems are involved. Each trace records the full "
            "sequence of tool calls, their arguments and results, and "
            "post-hoc canary-based risk labels."
        ),
        "rai:dataCollectionType": "Synthetic",
        "rai:dataCollectionRawData": (
            "Raw traces are the primary data. Environment configurations and "
            "canary values are defined in src/mcphunt/environments.py and "
            "src/mcphunt/canary_registry.py."
        ),
        "rai:dataCollectionTimeframe": "2026-Q1 to 2026-Q2",
        "rai:dataAnnotationProtocol": (
            "Risk labels are computed deterministically by the canary-based "
            "labeling pipeline (src/mcphunt/labeling.py). The pipeline evaluates "
            "11 tiered binary risk signals plus one diagnostic signal per trace "
            "using per-canary causal tracking with temporal ordering. CRS "
            "stratification labels are frozen task metadata assigned "
            "during task construction using a fixed rubric and encoded as "
            "completion_requires_secret in src/mcphunt/taxonomy.py, frozen "
            "before experiments. " + crs_protocol
        ),
        "rai:dataAnnotationPlatform": "Automated pipeline (labeling.py)",
        "rai:dataAnnotationAnalysis": (
            "The labeling pipeline is deterministic and reproducible. "
            "Mutation testing (test_labeling_integrity.py) validates that "
            "injected canaries are detected and safe traces produce no "
            "false positives. " + crs_analysis
        ),
        "rai:dataPreprocessingProtocol": [
            "Traces are sanitized to remove local usernames and paths (sanitize_traces.py).",
            "Risk signals are recomputed offline to ensure label consistency (relabel_traces.py).",
            "Trace structure and critical fields are validated post-sanitization.",
        ],
        "rai:dataReleaseMaintenancePlan": (
            "The dataset is versioned. The maintainers commit to hosting "
            "and maintaining the dataset for at least 24 months after "
            "publication."
        ),
        "rai:dataLimitation": (
            "All 147 tasks are researcher-designed and synthetic. The 8 MCP "
            "servers represent common patterns but not the full ecosystem. "
            "Detection captures exact and near-exact canary matches but "
            "misses paraphrased propagation. Cloud-hosted model endpoints "
            "may be updated or deprecated by providers after publication."
        ),
        "rai:dataSocialImpact": (
            "Intended for research on agent safety evaluation. The framework "
            "identifies high-risk source-to-sink topologies, which could in "
            "principle guide adversaries. This is mitigated by using only "
            "synthetic canary credentials and releasing exclusively for "
            "defensive pre-deployment evaluation."
        ),
        "rai:dataBiases": (
            "Task design reflects the authors' conception of compositional "
            "data-flow risks. Mechanism families may over-represent patterns "
            "the authors prioritized. Hard-negative and benign controls are "
            "included to mitigate one-sided coverage."
        ),
        "rai:personalSensitiveInformation": (
            "None. All credentials in traces are synthetic canary values "
            "(e.g., sk_live_*, AKIA*, ghp_*). Traces are sanitized to "
            "remove local usernames and filesystem paths before release."
        ),
        "rai:dataUseCases": [
            "Measuring cross-boundary data propagation in multi-server MCP agents",
            "Evaluating prompt-level and orchestration-level mitigation strategies",
            "Benchmarking canary-based taint tracking for agent safety",
            "Studying pathway-specific propagation patterns across mechanism families",
            "Educational material for tool-use agent safety",
        ],
    }
    return meta


def main(out_dir: Path) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)

    metadata = build_metadata()
    out_path = out_dir / "croissant.json"
    out_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"Wrote Croissant metadata: {out_path.relative_to(REPO_ROOT)}")

    # Clean up old split Croissant files if they exist
    for old in ["croissant_discovery.json", "croissant_validation.json"]:
        old_path = out_dir / old
        if old_path.exists():
            old_path.unlink()
            print(f"  Removed old: {old}")

    return [out_path]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    args = parser.parse_args()
    main(args.out_dir)
