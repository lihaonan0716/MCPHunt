"""Lightweight trace viewer for quick debugging.

Usage:
    PYTHONPATH=src python3 -m mcphunt.trace_viewer migrate_project_risky_v1
    PYTHONPATH=src python3 -m mcphunt.trace_viewer --task migrate_project --env risky_v1
    PYTHONPATH=src python3 -m mcphunt.trace_viewer --list
    PYTHONPATH=src python3 -m mcphunt.trace_viewer --list --model gpt-5.4
    PYTHONPATH=src python3 -m mcphunt.trace_viewer migrate_project_risky_v1 --events-only
    PYTHONPATH=src python3 -m mcphunt.trace_viewer migrate_project_risky_v1 --json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
TRACES_DIR = REPO_ROOT / "results" / "agent_traces"

_RISK_COLORS = {
    "data_flow": "31",           # red
    "cross_boundary_flow": "31",
    "secret_in_executable": "31",
    "external_after_sensitive": "35",  # magenta
    "secret_in_command": "35",
    "browser_sensitive_input": "35",
    "partial_leak": "33",        # yellow
    "semantic_leak": "33",
    "opaque_transfer": "33",
    "sensitive_schema_flow": "36",  # cyan
    "authority_escalation": "36",
}


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m"


def _load_all_traces(model: Optional[str] = None) -> List[Dict]:
    from mcphunt.datasets.agent_traces import load_agent_traces
    return load_agent_traces(traces_dir=TRACES_DIR, model=model)


def _find_trace(traces: List[Dict], trace_id: str = "",
                task_id: str = "", env_type: str = "") -> Optional[Dict]:
    for t in traces:
        if trace_id and t.get("trace_id", "") == trace_id:
            return t
        if task_id and env_type:
            if t.get("task_id") == task_id and t.get("env_type") == env_type:
                return t
    if trace_id:
        for t in traces:
            if trace_id in t.get("trace_id", ""):
                return t
    return None


def list_traces(traces: List[Dict]) -> None:
    if not traces:
        print("No traces found.")
        return
    models = sorted(set(t.get("model", "?") for t in traces))
    print(f"  {len(traces)} traces across {len(models)} model(s): {', '.join(models)}\n")
    print(f"  {'trace_id':50s} {'outcome':18s} {'turns':>5s} {'events':>6s} {'signals'}")
    print(f"  {'-'*50} {'-'*18} {'-'*5} {'-'*6} {'-'*30}")
    for t in sorted(traces, key=lambda x: x.get("trace_id", "")):
        tid = t.get("trace_id", "?")[:50]
        outcome = t.get("outcome", "?")
        turns = t.get("num_turns", 0)
        events = t.get("num_events", len(t.get("events", [])))
        signals = t.get("labeling", {}).get("risk_signals", {})
        active = [s for s, v in signals.items() if v]
        sig_str = ", ".join(active) if active else "-"
        out_color = "31" if "unsafe" in outcome else "32"
        print(f"  {tid:50s} {_c(outcome, out_color):27s} {turns:5d} {events:6d} {sig_str}")


def print_trace(trace: Dict, events_only: bool = False) -> None:
    tid = trace.get("trace_id", "?")
    task_id = trace.get("task_id", "?")
    env_type = trace.get("env_type", "?")
    model = trace.get("model", "?")
    outcome = trace.get("outcome", "?")
    labeling = trace.get("labeling", {})
    signals = labeling.get("risk_signals", {})
    active_signals = [s for s, v in signals.items() if v]

    if not events_only:
        print(f"\n{'=' * 72}")
        print(f"  Trace: {_c(tid, '1')}")
        print(f"  Task:  {task_id}  |  Env: {env_type}  |  Model: {model}")
        print(f"  Outcome: {_c(outcome, '31' if 'unsafe' in outcome else '32')}")
        print(f"  Turns: {trace.get('num_turns', '?')}  |  "
              f"Duration: {trace.get('duration_s', '?')}s  |  "
              f"Tool errors: {trace.get('tool_errors', 0)}")

        if active_signals:
            print(f"\n  {_c('RISK SIGNALS:', '1;31')}")
            for sig in active_signals:
                color = _RISK_COLORS.get(sig, "33")
                print(f"    {_c('●', color)} {sig}")
        else:
            print(f"\n  {_c('No risk signals', '32')}")

        details = labeling.get("risk_details", [])
        if details:
            print(f"\n  Risk details:")
            for d in details:
                print(f"    {d}")

        chain = labeling.get("danger_chain", [])
        if chain:
            print(f"\n  Danger chain: {' → '.join(chain)}")

        taint = labeling.get("taint_summary", {})
        if taint.get("taints_leaked", 0) > 0:
            print(f"\n  Taint: {taint['taints_read']} read, "
                  f"{taint['taints_leaked']} leaked "
                  f"(verbatim={taint.get('by_method', {}).get('verbatim', 0)}, "
                  f"fragment={taint.get('by_method', {}).get('fragment_match', 0)})")

        checks = trace.get("completion_checks", {})
        print(f"\n  Completion: artifact_verified={checks.get('artifact_verified', '?')}  "
              f"reads={checks.get('reads_attempted', 0)}  "
              f"writes={checks.get('writes_succeeded', 0)}/{checks.get('writes_attempted', 0)}")
        if checks.get("expected_file"):
            exists = "✓" if checks.get("file_exists") else "✗"
            print(f"    Expected file: {checks['expected_file']} [{exists}]")

        df = labeling.get("data_flow_leaked_canaries", 0)
        df_vis = labeling.get("data_flow_visible_leaked_canaries", 0)
        if df > 0:
            vis_note = f" ({df_vis} visible to LLM)" if df_vis != df else ""
            print(f"    Canaries leaked: {df}{vis_note}")

    # Event timeline
    events = trace.get("events", [])
    if not events:
        print("\n  No events recorded.")
        return

    print(f"\n  {'─' * 68}")
    print(f"  EVENT TIMELINE ({len(events)} events)")
    print(f"  {'─' * 68}")

    for i, ev in enumerate(events):
        turn = ev.get("turn", "?")
        server = ev.get("server", "?")
        tool = ev.get("tool", "?")
        success = ev.get("success", True)
        latency = ev.get("latency_ms", 0)
        canary_r = ev.get("canary_in_result", False)
        canary_a = ev.get("canary_in_args", False)
        canary_vis = ev.get("canary_visible_to_llm", None)
        truncated = ev.get("result_truncated", False)

        status = _c("✓", "32") if success else _c("✗", "31")
        flags = []
        if canary_r:
            vis_tag = "visible" if canary_vis else ("invisible" if canary_vis is False else "?")
            flags.append(_c(f"CANARY_READ({vis_tag})", "33"))
        if canary_a:
            flags.append(_c("CANARY_WRITE", "31"))
        if truncated:
            flags.append(_c("TRUNCATED", "36"))
        if ev.get("taint_blocked"):
            flags.append(_c("TAINT_BLOCKED", "35"))
        if ev.get("error"):
            flags.append(_c(f"err:{ev['error'][:40]}", "31"))

        flag_str = f"  {'  '.join(flags)}" if flags else ""
        print(f"\n  [{i+1:3d}] turn {turn}  {status} {server}.{tool}  ({latency}ms){flag_str}")

        args = ev.get("args", {})
        args_short = json.dumps(args, ensure_ascii=False)
        if len(args_short) > 120:
            args_short = args_short[:120] + "..."
        print(f"        args: {args_short}")

        result_chars = ev.get("result_chars", 0)
        preview = ev.get("result_preview", "")[:200]
        if preview:
            preview_oneline = preview.replace("\n", "\\n")
            if len(preview_oneline) > 120:
                preview_oneline = preview_oneline[:120] + "..."
            print(f"        result ({result_chars} chars): {preview_oneline}")

    print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="View agent traces for debugging",
        usage="python3 -m mcphunt.trace_viewer [TRACE_ID] [options]",
    )
    parser.add_argument("trace_id", nargs="?", default="",
                        help="Trace ID (or substring) to view")
    parser.add_argument("--task", default="", help="Task ID to find")
    parser.add_argument("--env", default="", help="Environment type (with --task)")
    parser.add_argument("--model", default="", help="Filter by model")
    parser.add_argument("--list", action="store_true", help="List all traces")
    parser.add_argument("--events-only", action="store_true",
                        help="Show only event timeline")
    parser.add_argument("--json", action="store_true",
                        help="Output raw trace as JSON")
    args = parser.parse_args()

    traces = _load_all_traces(model=args.model or None)
    if not traces:
        print(f"No traces found in {TRACES_DIR}")
        sys.exit(1)

    if args.list:
        list_traces(traces)
        return

    if not args.trace_id and not args.task:
        print("Specify a trace_id, --task/--env, or --list")
        sys.exit(1)

    trace = _find_trace(traces, trace_id=args.trace_id,
                        task_id=args.task, env_type=args.env)
    if not trace:
        search = args.trace_id or f"{args.task}+{args.env}"
        print(f"Trace not found: '{search}'")
        print(f"Use --list to see available traces")
        sys.exit(1)

    if args.json:
        print(json.dumps(trace, indent=2, ensure_ascii=False))
    else:
        print_trace(trace, events_only=args.events_only)


if __name__ == "__main__":
    main()
