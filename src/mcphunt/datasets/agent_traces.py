"""Agent trace loading, normalisation, and record construction.

Loads LLM agent traces collected by ``scripts/collect_agent_traces.py``,
converts them into pipeline-compatible records, and provides the
environment-ablation and quadrant analyses as first-class outputs.

Dataset name: ``compose_riskbench_agent_v1``
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd

from ..taxonomy import (
    RISK_SIGNAL_NAMES,
    WRITE_TOOLS as _WRITE_TOOLS,
    DANGEROUS_SINKS as _DANGEROUS_SINKS,
    env_class as _env_class,
    is_crs_task as _is_crs,
)

AGENT_TRACES_DIR = Path(__file__).resolve().parents[3] / "results" / "agent_traces"
AGENT_DATASET = "compose_riskbench_agent_v1"


def load_agent_traces(
    traces_dir: Optional[Path] = None,
    model: Optional[str] = None,
) -> List[Dict[str, Any]]:
    root = traces_dir or AGENT_TRACES_DIR
    if not root.exists():
        return []
    traces: List[Dict] = []
    seen_ids: set = set()
    for json_path in sorted(root.rglob("agent_traces*.json")):
        if ".checkpoint." in json_path.name:
            continue
        try:
            raw = json.loads(json_path.read_text(encoding="utf-8"))
            items = raw.get("traces", raw) if isinstance(raw, dict) else raw
            if isinstance(items, list):
                for t in items:
                    if model and t.get("model") != model:
                        continue
                    tid = t.get("trace_id", "")
                    mid = t.get("model", "")
                    key = f"{mid}::{tid}"
                    if key in seen_ids:
                        continue
                    seen_ids.add(key)
                    traces.append(t)
        except (json.JSONDecodeError, KeyError):
            continue
    return traces


def build_agent_record(trace: Dict[str, Any]) -> Dict[str, Any]:
    """Convert one agent trace into a pipeline record."""
    events = trace.get("events", [])
    labeling = trace.get("labeling", {})
    risk_signals = labeling.get("risk_signals", {})
    taint = labeling.get("taint_summary", {})
    checks = trace.get("completion_checks", {})
    measurement = trace.get("measurement", {})
    env_type = trace.get("env_type", "")

    servers_used = trace.get("servers_used", [])
    n_events = len(events)

    n_writes = sum(1 for e in events if e.get("tool") in _WRITE_TOOLS)
    n_dangerous = sum(1 for e in events if e.get("tool") in _DANGEROUS_SINKS)
    n_reads = checks.get("reads_attempted", 0)

    cross_transitions = 0
    for i in range(len(events) - 1):
        if events[i].get("server") != events[i + 1].get("server"):
            cross_transitions += 1

    return {
        "record_id": trace["trace_id"],
        "dataset": AGENT_DATASET,
        "stage": "agent",
        "trace_id": trace["trace_id"],
        "task_id": trace.get("task_id", ""),
        "task_category": trace.get("task_category", ""),
        "risk_mechanism": trace.get("risk_mechanism", trace.get("task_category", "")),
        "env_type": env_type,
        "env_class": _env_class(env_type),
        "model": trace.get("model", "unknown"),
        "ablation_profile": trace.get("ablation_profile", "full"),
        "group_id": f"{trace.get('task_id', '')}::{_env_class(env_type)}::{trace.get('model', '')}",

        # Structural features
        "n_events": n_events,
        "n_turns": trace.get("num_turns", 0),
        "n_servers": len(servers_used),
        "n_writes": n_writes,
        "n_reads": n_reads,
        "n_dangerous": n_dangerous,
        "cross_server_ratio": cross_transitions / max(n_events - 1, 1) if n_events > 1 else 0.0,
        "tool_error_rate": trace.get("tool_errors", 0) / max(n_events, 1),
        "duration_s": trace.get("duration_s", 0),

        # Risk signals (11 boolean signals → float)
        "data_flow": int(risk_signals.get("data_flow", False)),
        "authority_escalation": int(risk_signals.get("authority_escalation", False)),
        "secret_in_executable": int(risk_signals.get("secret_in_executable", False)),
        "cross_boundary_flow": int(risk_signals.get("cross_boundary_flow", False)),
        "external_after_sensitive": int(risk_signals.get("external_after_sensitive", False)),
        "browser_sensitive_input": int(risk_signals.get("browser_sensitive_input", False)),
        "partial_leak": int(risk_signals.get("partial_leak", False)),
        "sensitive_schema_flow": int(risk_signals.get("sensitive_schema_flow", False)),
        "semantic_leak": int(risk_signals.get("semantic_leak", False)),
        "secret_in_command": int(risk_signals.get("secret_in_command", False)),
        "opaque_transfer": int(risk_signals.get("opaque_transfer", False)),

        # Taint tracking
        "taints_read": taint.get("taints_read", 0),
        "taints_leaked": taint.get("taints_leaked", 0),
        "leak_verbatim": taint.get("by_method", {}).get("verbatim", 0),
        "leak_fragment": taint.get("by_method", {}).get("fragment_match", 0),

        # Labels
        "risky_label": int(labeling.get("any_risk", False)),
        "completion_requires_secret": int(labeling.get("completion_requires_secret",
                                                        _is_crs(trace.get("task_id", "")))),
        "intrinsic_risk": int(labeling.get("intrinsic_risk",
                                            labeling.get("any_risk", False) and not _is_crs(trace.get("task_id", "")))),
        "outcome": trace.get("outcome", "safe_failure"),
        "task_completed": int(trace.get("task_completed", False)),
        "artifact_verified": int(checks.get("artifact_verified", False)),

        # Provenance
        "danger_chain": json.dumps(labeling.get("danger_chain", [])),
        "servers_used_json": json.dumps(servers_used),

        # Measurement metadata
        "prompt_tokens": measurement.get("prompt_tokens", 0),
        "completion_tokens": measurement.get("completion_tokens", 0),
        "total_tokens": measurement.get("total_tokens", 0),
        "api_retries": measurement.get("api_retries", 0),
        "last_failure_code": measurement.get("last_failure_code", ""),
        "wire_api": measurement.get("wire_api", trace.get("wire_api", "")),
        "preset": measurement.get("preset", ""),
    }


def build_agent_rows(traces: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [build_agent_record(t) for t in traces]


def compute_summary(traces: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Derive a summary dict purely from trace data.

    This is the single source of truth for collection_summary.json.
    Both the collector and the relabeler call this function, so the
    summary can never drift from the traces.
    """
    from ..taxonomy import schema_header, RISK_SIGNAL_NAMES, RISK_MECHANISMS, CONTROL_MECHANISMS, TASK_REGISTRY

    n = len(traces)
    quadrants = {q: 0 for q in ("safe_success", "unsafe_success", "safe_failure", "unsafe_failure")}
    signal_counts: Dict[str, int] = {}
    risk_levels = {"high": 0, "medium": 0, "low": 0, "none": 0}
    truncated = 0
    api_errors = 0
    tool_errors = 0
    models = set()
    envs = set()
    categories = set()

    for t in traces:
        quadrants[t.get("outcome", "safe_failure")] += 1
        risk_levels[t.get("expected_risk", "none")] += 1
        if t.get("truncated"):
            truncated += 1
        api_errors += t.get("api_errors", 0)
        tool_errors += t.get("tool_errors", 0)
        models.add(t.get("model", "unknown"))
        envs.add(t.get("env_type", ""))
        categories.add(t.get("task_category", ""))
        for sig, val in t.get("labeling", {}).get("risk_signals", {}).items():
            if val:
                signal_counts[sig] = signal_counts.get(sig, 0) + 1

    artifact_ok = quadrants["safe_success"] + quadrants["unsafe_success"]
    utility_rate = artifact_ok / max(n, 1)
    safety_rate = (quadrants["safe_success"] + quadrants["safe_failure"]) / max(n, 1)

    crs_unsafe_total = 0
    non_crs_unsafe_total = 0
    crs_total = 0
    non_crs_total = 0
    for t in traces:
        tid = t.get("task_id", "")
        crs = t.get("labeling", {}).get("completion_requires_secret", _is_crs(tid))
        is_unsafe = t.get("labeling", {}).get("any_risk", False)
        if crs:
            crs_total += 1
            if is_unsafe:
                crs_unsafe_total += 1
        else:
            non_crs_total += 1
            if is_unsafe:
                non_crs_unsafe_total += 1

    per_env: Dict[str, Dict[str, Any]] = {}
    for env in sorted(envs):
        et = [t for t in traces if t.get("env_type") == env]
        en = len(et)
        eq = {q: sum(1 for t in et if t.get("outcome") == q) for q in quadrants}
        eu = sum(1 for t in et if t.get("labeling", {}).get("any_risk"))
        el = sum(1 for t in et if t.get("labeling", {}).get("strict_leakage"))

        crs_n = sum(1 for t in et if t.get("labeling", {}).get("completion_requires_secret", _is_crs(t.get("task_id", ""))))
        non_crs_n = en - crs_n
        crs_unsafe = sum(1 for t in et
                         if t.get("labeling", {}).get("any_risk")
                         and t.get("labeling", {}).get("completion_requires_secret", _is_crs(t.get("task_id", ""))))
        non_crs_unsafe = sum(1 for t in et
                             if t.get("labeling", {}).get("any_risk")
                             and not t.get("labeling", {}).get("completion_requires_secret", _is_crs(t.get("task_id", ""))))

        risk_only = [t for t in et if TASK_REGISTRY.get(t.get("task_id", ""), None) is not None
                     and TASK_REGISTRY[t.get("task_id")].task_type == "risk"]
        risk_only_n = len(risk_only)
        risk_only_unsafe = sum(1 for t in risk_only if t.get("labeling", {}).get("any_risk"))

        per_env[env] = {
            "n": en,
            "unsafe_rate": round(eu / max(en, 1), 4),
            "strict_leakage_rate": round(el / max(en, 1), 4),
            "risk_task_only_n": risk_only_n,
            "risk_task_only_unsafe_rate": round(risk_only_unsafe / max(risk_only_n, 1), 4) if risk_only_n else 0.0,
            "crs_unsafe_rate": round(crs_unsafe / max(crs_n, 1), 4) if crs_n else 0.0,
            "non_crs_unsafe_rate": round(non_crs_unsafe / max(non_crs_n, 1), 4) if non_crs_n else 0.0,
            "intrinsic_unsafe_rate": round(non_crs_unsafe / max(en, 1), 4),
            "crs_n": crs_n,
            "quadrants": eq,
        }

    def _mech_stats(subset: List[Dict]) -> Dict[str, Any]:
        sn = len(subset)
        sq = {q: sum(1 for t in subset if t.get("outcome") == q) for q in quadrants}
        su = sum(1 for t in subset if t.get("labeling", {}).get("any_risk"))
        sl = sum(1 for t in subset if t.get("labeling", {}).get("strict_leakage"))
        return {
            "n": sn,
            "unsafe_rate": round(su / max(sn, 1), 4),
            "strict_leakage_rate": round(sl / max(sn, 1), 4),
            "utility_rate": round((sq.get("safe_success", 0) + sq.get("unsafe_success", 0)) / max(sn, 1), 4),
            "quadrants": sq,
        }

    per_mechanism: Dict[str, Dict[str, Any]] = {}
    per_control: Dict[str, Dict[str, Any]] = {}
    all_mechs = sorted(set(t.get("risk_mechanism", "") for t in traces))
    for mech in all_mechs:
        mt = [t for t in traces if t.get("risk_mechanism") == mech]
        risky = [t for t in mt if _env_class(t.get("env_type", "")) == "risky"]
        ctrl = [t for t in mt if _env_class(t.get("env_type", "")) != "risky"]
        entry = {"risky": _mech_stats(risky), "control": _mech_stats(ctrl)}
        if mech in RISK_MECHANISMS:
            per_mechanism[mech] = entry
        elif mech in CONTROL_MECHANISMS:
            per_control[mech] = entry

    intrinsic_safe = (quadrants["safe_success"] + quadrants["safe_failure"] + crs_unsafe_total)
    intrinsic_safety_rate = intrinsic_safe / max(n, 1)

    return {
        **schema_header(),
        "total": n,
        "models": sorted(models),
        "environments": sorted(envs),
        "task_categories": sorted(categories),
        "risk_levels": risk_levels,
        "risk_signal_counts": signal_counts,
        "outcome_quadrants": quadrants,
        "utility_rate": round(utility_rate, 4),
        "safety_rate": round(safety_rate, 4),
        "intrinsic_safety_rate": round(intrinsic_safety_rate, 4),
        "crs_breakdown": {
            "crs_tasks": crs_total,
            "crs_unsafe": crs_unsafe_total,
            "non_crs_tasks": non_crs_total,
            "non_crs_unsafe": non_crs_unsafe_total,
            "crs_unsafe_rate": round(crs_unsafe_total / max(crs_total, 1), 4),
            "non_crs_unsafe_rate": round(non_crs_unsafe_total / max(non_crs_total, 1), 4),
        },
        "truncated": truncated,
        "artifact_verified": artifact_ok,
        "api_errors_total": api_errors,
        "tool_errors_total": tool_errors,
        "per_environment": per_env,
        "per_mechanism": per_mechanism,
        "per_control": per_control,
        "summary_generated": __import__("time").strftime("%Y-%m-%dT%H:%M:%SZ", __import__("time").gmtime()),
    }


def load_agent_records(
    traces_dir: Optional[Path] = None,
    model: Optional[str] = None,
) -> pd.DataFrame:
    traces = load_agent_traces(traces_dir, model)
    if not traces:
        return pd.DataFrame()
    rows = build_agent_rows(traces)
    return pd.DataFrame(rows)
