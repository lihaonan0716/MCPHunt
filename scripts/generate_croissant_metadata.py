#!/usr/bin/env python3
"""
Generate Croissant metadata for the MCPHunt agent traces dataset.

NeurIPS 2026 Evaluations & Datasets Track requires Croissant format with
core and Responsible AI (RAI) fields.

Output: artifacts/release/croissant.json (named authors).
The anonymous review identity is retired. Metadata is generated only after
the release payload is assembled; use prepare_huggingface_release.py for a rebuild.

Croissant spec: https://docs.mlcommons.org/croissant/docs/croissant-spec.html

Usage:
    python3 scripts/generate_croissant_metadata.py
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT_DIR = REPO_ROOT / "artifacts" / "release"
DEFAULT_PAYLOAD_DIR = REPO_ROOT / "artifacts" / "huggingface-staging" / "mcphunt-agent-traces"
DATASET_VERSION = "1.1.0"
PUBLICATION_DATE = "2026-04-29"

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

# Release identity. The dict shape is kept even though only one identity
# remains: build_metadata() takes an identity and main() iterates the table, so
# retiring an identity is a data change rather than a code change. The anonymous
# review identity was dropped after acceptance (2026-09); the bundle already
# published under it stays untouched, because public rebuttal comments link into
# it by commit hash.
# Keys match STAGING_VARIANTS in scripts/prepare_huggingface_release.py, which
# copies the matching file into each staging bundle as croissant.json.
RELEASE_IDENTITIES = {
    "named": {
        "filename": "croissant.json",
        "owner": "Haonan Li",
        "creators": ["Haonan Li", "Tianjun Sun", "Yongqing Wang",
                     "Qisheng Zhang"],
        "authors": "Li, Haonan and Sun, Tianjun and Wang, Yongqing and "
                   "Zhang, Qisheng",
        "url": "https://huggingface.co/datasets/lihaonan0716/mcphunt-agent-traces",
        # Venue string and url are the OpenReview-issued BibTeX for the accepted
        # paper (forum 9mPzIg8uil), not guessed. The arXiv fields stay: the
        # preprint exists and has been cited, so dropping them would orphan
        # those citations.
        "citation": (
            "@inproceedings{mcphunt2026,\n"
            "  title = {{MCPH}unt: An Evaluation Framework for Cross-Boundary "
            "Data Propagation in Multi-Server {MCP} Agents},\n"
            "  author = {Li, Haonan and Sun, Tianjun and Wang, Yongqing and "
            "Zhang, Qisheng},\n"
            "  booktitle = {The Fortieth Annual Conference on Neural Information "
            "Processing Systems Evaluations and Datasets Track},\n"
            "  year = {2026},\n"
            "  eprint = {2604.27819},\n"
            "  archivePrefix = {arXiv},\n"
            "  primaryClass = {cs.AI},\n"
            "  url = {https://openreview.net/forum?id=9mPzIg8uil}\n"
            "}"
        ),
    },
}

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
        "sha256": "sc:sha256",
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


def build_metadata(identity: Dict[str, str]) -> Dict[str, Any]:
    crs = _crs_audit_stats()
    crs_protocol = (
        "The CRS labels were not crowdsourced. A post-submission independent "
        "audit of the CRS labels was subsequently performed by two annotators "
        "who are not authors, each labeling all "
        f"{crs['n']} tasks blind to trace outcomes; the raw labels are "
        "released under crs_audit/ in this bundle (mirrored at artifacts/release/crs_audit/ in the code repository) so the reliability "
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
        "(crs_audit/ in this bundle; artifacts/release/crs_audit/ in the code repository) and the scoring script "
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
    # Risky-vs-hard-negative matched 2x2 (paired on task_id over the frozen
    # registry's risk tasks), its Tango score interval, and the exact McNemar
    # p-value. Declared here so the dataset card, the shipped files, and the
    # Croissant distribution cannot disagree about what the bundle contains.
    distribution.append({
        "@type": "cr:FileObject",
        "@id": "meta_hard_negative_ci",
        "name": "meta/hard_negative_ci.json",
        "contentUrl": "meta/hard_negative_ci.json",
        "encodingFormat": "application/json",
    })

    # Judge-based recall diagnostic. Its own split rather than a meta/ file: it
    # is a single-record estimate over a seeded sample, not an aggregate of the
    # trace splits, and it gets its own RecordSet below.
    distribution.append({
        "@type": "cr:FileObject",
        "@id": "recall_evaluation_estimation",
        "name": "recall_evaluation/recall_estimation.json",
        "contentUrl": "recall_evaluation/recall_estimation.json",
        "encodingFormat": "application/json",
    })

    # Required publication inputs, using the same mitigation inventory that
    # downloads restore. A partially populated stratum must not become a smaller
    # apparently complete release just because the missing file was not listed.
    from download_traces import MITIGATION_DIRS
    required_payload = ([f"mitigation/{name}.json" for name in MITIGATION_DIRS]
                        + ["meta/mitigation_results.json",
                           "meta/guarded_run_provenance.json", "README.md"]
                        + [f"crs_audit/{n}" for n in
                           ("README.md", "annotation_1.csv", "annotation_2.csv")])
    for name in required_payload:
        distribution.append({
            "@type": "cr:FileObject", "@id": f"payload/{name}",
            "name": name, "contentUrl": name,
            "encodingFormat": {".md": "text/markdown", ".csv": "text/csv"}.get(
                Path(name).suffix, "application/json"),
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

    _RC = "recall_evaluation_estimation"
    recall_fields = [
        _field("recall_estimand", "Name of the quantity being estimated (pooled_detector_clean_miss_prevalence).", "sc:Text", "$.estimand", _RC),
        _field("recall_complete_case_point", "Complete-case point estimate of detector-clean miss prevalence (judge-estimated).", "sc:Float", "$.detector_clean_miss_prevalence_complete_case", _RC),
        _field("recall_ci_method", "Confidence-interval method (Wilson score 95% primary).", "sc:Text", "$.ci_method", _RC),
        _field("recall_seed", "Sampling seed for the seeded SRS draw.", "sc:Integer", "$.seed", _RC),
        _field("recall_judge_model", "LLM judge model that produced the per-trace judgments.", "sc:Text", "$.judge_model", _RC),
    ]
    # _field() names the field after its @id; the released schema uses the raw
    # JSON key as the field name, so restore those without duplicating @ids.
    for fld, key in zip(recall_fields, [
            "estimand", "detector_clean_miss_prevalence_complete_case",
            "ci_method", "seed", "judge_model"]):
        fld["name"] = key

    meta = {
        "@context": _croissant_context(),
        "@type": "sc:Dataset",
        "conformsTo": "http://mlcommons.org/croissant/1.0",
        "version": DATASET_VERSION,
        "license": "https://creativecommons.org/licenses/by/4.0/",
        "creator": [{"@type": "sc:Person", "name": name}
                    for name in identity["creators"]],
        "publisher": {"@type": "sc:Person", "name": identity["owner"]},
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
            "6,786 traces. Each trace includes the full tool-call "
            "event log, 11 tiered binary risk signals plus one diagnostic "
            "signal computed by canary-based taint tracking, CRS "
            "stratification labels, and outcome classification."
        ),
        "keywords": [
            "MCP", "Model Context Protocol", "agent safety",
            "data propagation", "cross-boundary", "canary tracking",
            "tool-use", "benchmark", "evaluation",
        ],
        "url": identity["url"],
        "citeAs": identity["citation"],
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
            },
            {
                "@type": "cr:RecordSet",
                "@id": "recall_evaluation",
                "name": "recall_evaluation",
                "description": (
                    "Single-record detector-clean miss-prevalence diagnostic "
                    "over a seeded simple random sample (n=150, seed=20260729) "
                    "of risky-environment, no-defense traces that read a canary "
                    "but were not flagged by the exact-substring detector. One "
                    "LLM judge (Claude Opus) flagged traces whose outbound "
                    "events contain a canary, a fragment, or a description of "
                    "one. A rubric-positive prevalence (Wilson 95%, sampling "
                    "error only), not a recall, false-negative rate, or "
                    "credential-propagation miss rate. The record-set name is "
                    "kept for compatibility with earlier releases."
                ),
                "field": recall_fields,
            },
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
        "rai:hasSyntheticData": True,
        "rai:dataCollectionRawData": (
            "Raw traces are the primary data. Environment configurations and "
            "canary values are defined in src/mcphunt/environments.py and "
            "src/mcphunt/canary_registry.py."
        ),
        "rai:dataCollectionTimeframe": "2026-Q2 to 2026-Q3",
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
        "rai:dataLimitations": (
            "All 147 tasks are researcher-designed and synthetic. The 8 MCP "
            "servers represent common patterns but not the full ecosystem. "
            "Main-benchmark detection captures verbatim canary matches but "
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


def payload_files(payload_dir: Path) -> Dict[str, Path]:
    """All shipped bytes except the metadata itself (no self-hash cycle)."""
    if not payload_dir.is_dir():
        raise ValueError(f"release payload missing: {payload_dir}; assemble it first")
    files = {}
    for path in sorted(payload_dir.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"symlinks are not release payload: {path}")
        if path.is_file() and path != payload_dir / "croissant.json":
            if path.name.endswith(".presan.bak"):
                raise ValueError(f"pre-sanitization backup in payload: {path}")
            files[path.relative_to(payload_dir).as_posix()] = path
    if not files:
        raise ValueError("release payload is empty")
    return files


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def finalize_metadata(meta: Dict[str, Any], payload_dir: Path) -> Dict[str, Any]:
    """Declare and hash the finalized payload, preserving existing reference IDs."""
    files = payload_files(payload_dir)
    declared = {obj["contentUrl"] for obj in meta["distribution"]}
    missing = declared - files.keys()
    if missing:
        raise ValueError(f"required release files missing: {sorted(missing)}")
    for name in sorted(files.keys() - declared):
        meta["distribution"].append({
            "@type": "cr:FileObject", "@id": f"payload/{name}",
            "name": name, "contentUrl": name,
            "encodingFormat": {".json": "application/json", ".csv": "text/csv",
                               ".md": "text/markdown"}.get(Path(name).suffix,
                                                           "application/octet-stream"),
        })
    for obj in meta["distribution"]:
        obj["sha256"] = file_sha256(files[obj["contentUrl"]])
    counts = payload_trace_counts(payload_dir)
    meta["description"] = (
        "Agent execution traces measuring cross-boundary data propagation in "
        "multi-server MCP agents: "
        f"{counts['main']:,} main-benchmark traces across 147 tasks and 9 "
        f"mechanism families, {counts['mitigation']:,} prompt-mitigation traces, "
        f"and {counts['live_guard_defense'] + counts['browser_replication']:,} "
        "supplemental traces in separate directories "
        f"({counts['live_guard_defense']:,} historical single-model guarded "
        "traces in live_guard_defense/; "
        f"{counts['browser_replication']:,} same-day baseline/defense browser "
        f"traces in browser_replication/). Total: {sum(counts.values()):,} "
        "traces. Each trace includes tool-call events, canary-based risk labels, "
        "CRS stratification, and outcome classification."
    )
    meta["creativeWorkStatus"] = "Published"
    meta["additionalProperty"] = [
        {"@type": "sc:PropertyValue", "name": f"{name}_trace_count", "value": n}
        for name, n in counts.items()
    ]
    validate_payload(meta, payload_dir)
    return meta


def payload_trace_counts(payload_dir: Path) -> Dict[str, int]:
    counts = {}
    for name in ("main", "mitigation", "live_guard_defense", "browser_replication"):
        paths = sorted((payload_dir / name).glob("*.json"))
        if not paths:
            raise ValueError(f"trace stratum missing or empty: {name}")
        counts[name] = 0
        for path in paths:
            traces = json.loads(path.read_text(encoding="utf-8"))["traces"]
            if not isinstance(traces, list) or not traces:
                raise ValueError(f"empty or invalid trace array: {path}")
            counts[name] += len(traces)
    return counts


def validate_payload(meta: Dict[str, Any], payload_dir: Path) -> None:
    """Fail on missing/extra files, duplicate declarations, unsafe paths or drift."""
    files = payload_files(payload_dir)
    entries = meta.get("distribution")
    if not isinstance(entries, list) or not entries:
        raise ValueError("distribution must be a nonempty list")
    declared = set()
    ids = set()
    for obj in entries:
        name = obj.get("contentUrl")
        if not isinstance(name, str) or name not in files:
            raise ValueError(f"declared file missing or outside payload: {name!r}")
        if name in declared or obj.get("@id") in ids:
            raise ValueError(f"duplicate distribution entry: {name}")
        declared.add(name)
        ids.add(obj.get("@id"))
        if obj.get("sha256") != file_sha256(files[name]):
            raise ValueError(f"missing or mismatched sha256: {name}")
    extra = files.keys() - declared
    if extra:
        raise ValueError(f"undeclared payload files: {sorted(extra)}")


def main(out_dir: Path, payload_dir: Path = DEFAULT_PAYLOAD_DIR) -> List[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)

    written = []
    for variant, identity in RELEASE_IDENTITIES.items():
        metadata = finalize_metadata(build_metadata(identity), payload_dir)
        out_path = out_dir / identity["filename"]
        out_path.write_text(json.dumps(metadata, indent=2, ensure_ascii=False) + "\n",
                            encoding="utf-8")
        print(f"Wrote Croissant metadata ({variant}): "
              f"{out_path}")
        written.append(out_path)

    # Clean up old split Croissant files if they exist
    for old in ["croissant_discovery.json", "croissant_validation.json"]:
        old_path = out_dir / old
        if old_path.exists():
            old_path.unlink()
            print(f"  Removed old: {old}")

    return written


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--out-dir", type=Path, default=DEFAULT_OUT_DIR)
    parser.add_argument("--payload-dir", type=Path, default=DEFAULT_PAYLOAD_DIR,
                        help="finalized payload to declare and hash")
    args = parser.parse_args()
    main(args.out_dir, args.payload_dir)
