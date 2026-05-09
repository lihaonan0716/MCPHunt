#!/usr/bin/env python3
"""
Collect real LLM agent traces by letting an LLM autonomously interact with MCP servers.

The LLM receives natural language tasks and decides which MCP tools to use.
Each trace records the full decision chain: task -> LLM reasoning -> tool calls -> results.

Environment-controlled labeling:
  - Risky env: workspace contains sensitive data with realistic canary secrets
  - Benign env: identical structure, no sensitive data
  - Same task in both -> labels based on actual data flow (objective, non-circular)

Supported models:
  - OpenAI-compatible (GPT, Qwen, etc.) via --wire-api chat
  - Claude via Vertex AI (--wire-api vertex) using service account credentials

Usage:
    PYTHONPATH=src python3 scripts/collect_agent_traces.py --model gpt-5.4
    PYTHONPATH=src python3 scripts/collect_agent_traces.py --model claude-opus-4-6 --wire-api vertex
    PYTHONPATH=src python3 scripts/collect_agent_traces.py --tasks 5 --dry-run
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List

import openai

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "src"))

from mcphunt.log import get_logger, setup_logging
log = get_logger("collector")

from mcphunt.taxonomy import (
    RISK_TASKS as _RISK_TASKS,
    HN_TASKS as _HN_TASKS,
    BENIGN_TASKS as _BENIGN_TASKS,
    ABLATION_PROFILES,
    schema_header as _schema_header,
    is_valid_combo as _is_valid_combo,
    VALID_TASK_ENV_COMBOS as _VALID_COMBOS,
)

from mcphunt import workspace
from mcphunt.workspace import (
    _set_workspace, setup_workspace, setup_sqlite, setup_memory,
    cleanup_mcp_artifacts,
)
from mcphunt.environments import ENV_VARIANTS
from mcphunt.prompts import (
    _build_tasks, _build_browser_tasks,
    TASKS, BROWSER_TASKS,
    MITIGATION_LEVELS,
)
from mcphunt.mcp_driver import (
    TOOL_DEFS, BROWSER_TOOL_DEFS,
    _filter_tool_defs,
    start_servers, stop_servers, smoke_test_servers,
    _start_local_http_server, _stop_local_http_server,
)
from mcphunt.agent_loop import (
    run_agent_task, load_model_config,
    API_BASE_URL, API_MODEL,
)
from mcphunt.integrity import validate_early_traces, _post_collection_integrity_check
from mcphunt.runtime_guard import RuntimeGuard
from mcphunt.config import (
    MAX_CONSECUTIVE_API_FAILURES, CHECKPOINT_SAVE_INTERVAL,
    EARLY_VALIDATE_THRESHOLD, PERIODIC_VALIDATE_INTERVAL,
)

# Re-export TASKS/BROWSER_TASKS at module level (mutated by run())
import mcphunt.prompts as _prompts


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

async def run(args: argparse.Namespace) -> None:
    api_base = args.api_base if hasattr(args, "api_base") else API_BASE_URL
    api_model = args.model if hasattr(args, "model") else API_MODEL
    # model_label overrides what gets recorded in traces and used for output dir
    model_label = getattr(args, "model_label", None) or api_model

    model_slug = model_label.replace("/", "_").replace(".", "_").replace("-", "_")
    _set_workspace(model_slug)
    log.info("Workspace: %s", workspace.ws.workspace)

    _prompts.TASKS = _build_tasks()
    _prompts.BROWSER_TASKS = _build_browser_tasks()

    # Validate bidirectional coverage between registry and builder
    registry_ids = set(_RISK_TASKS | _HN_TASKS | _BENIGN_TASKS)
    builder_ids = {t["id"] for t in _prompts.TASKS + _prompts.BROWSER_TASKS}
    missing_prompts = registry_ids - builder_ids
    if missing_prompts:
        log.warning("%d registry tasks have no prompt: %s", len(missing_prompts), sorted(missing_prompts))

    out_dir = Path(args.out_dir) / model_slug
    out_dir.mkdir(parents=True, exist_ok=True)

    wire = getattr(args, "wire_api", "chat")
    model_cfg = load_model_config(api_model)

    if wire == "vertex":
        cred_path = workspace.REPO_ROOT / "configs" / "claude_credentials.json"
        if not cred_path.exists():
            log.error("Vertex credentials not found at %s", cred_path)
            return
        region = getattr(args, "vertex_region", "us-east5")
        from google.oauth2 import service_account
        from anthropic import AnthropicVertex
        credentials = service_account.Credentials.from_service_account_file(
            str(cred_path),
            scopes=["https://www.googleapis.com/auth/cloud-platform"],
        )
        cred_info = json.loads(cred_path.read_text(encoding="utf-8"))
        project_id = cred_info.get("project_id", "")
        client = AnthropicVertex(project_id=project_id, region=region, credentials=credentials)
        log.info("Vertex AI: project=%s, region=%s", project_id, region)
    else:
        api_key = (args.api_key if hasattr(args, "api_key") and args.api_key
                   else model_cfg.get("api_key", "")
                   or os.environ.get("OPENAI_API_KEY", ""))
        if model_cfg.get("base_url"):
            api_base = model_cfg["base_url"]
        if not api_key:
            log.error("No API key for model '%s'. Set in configs/api_keys.yaml, --api-key flag, or OPENAI_API_KEY env var.", api_model)
            return
        client = openai.OpenAI(api_key=api_key, base_url=api_base)

    suite = getattr(args, "suite", "base")
    include_browser = suite in ("browser", "all")

    # Build task pool from registry — all tasks run by default
    browser_ids = {t["id"] for t in _prompts.BROWSER_TASKS}
    combined = _prompts.TASKS + _prompts.BROWSER_TASKS
    registry_ids = set(_RISK_TASKS | _HN_TASKS | _BENIGN_TASKS)
    task_pool = [t for t in combined if t["id"] in registry_ids]
    include_browser = any(t["id"] in browser_ids for t in task_pool)
    selected_envs = None

    active_tool_defs = TOOL_DEFS + (BROWSER_TOOL_DEFS if include_browser else [])

    ablation = getattr(args, "ablation", "full")
    ablation_servers = ABLATION_PROFILES[ablation]

    if args.tasks > 0:
        task_pool = task_pool[:args.tasks]
    if getattr(args, "envs", None):
        selected_envs = [e.strip() for e in args.envs.split(",")]

    # Recompute include_browser AFTER --tasks truncation
    include_browser = any(t["id"] in browser_ids for t in task_pool)
    active_tool_defs = TOOL_DEFS + (BROWSER_TOOL_DEFS if include_browser else [])
    # Filter tool defs to only include tools from active servers
    active_tool_defs = _filter_tool_defs(active_tool_defs, ablation_servers | ({"browser"} if include_browser else set()))

    tasks = task_pool
    active_envs = selected_envs or list(ENV_VARIANTS.keys())
    for e in active_envs:
        if e not in ENV_VARIANTS:
            log.error("Unknown environment '%s'. Available: %s", e, list(ENV_VARIANTS.keys()))
            return

    suffix = f"_{suite}" if suite != "base" else ""
    abl_suffix = f"_{ablation}" if ablation != "full" else ""
    mit_level = getattr(args, "mitigation_level", "none")
    if mit_level == "none" and getattr(args, "mitigation", False):
        mit_level = "moderate"
    mit_suffix = f"_mit{mit_level[0]}" if mit_level != "none" else ""
    defense = getattr(args, "defense", "none")
    def_suffix = f"_def{defense[0]}" if defense != "none" else ""
    out_path = out_dir / f"agent_traces{suffix}{abl_suffix}{mit_suffix}{def_suffix}.json"

    # Count valid combinations only (skip scientifically meaningless pairs)
    all_combos = getattr(args, "all_combos", False)
    if all_combos:
        valid_count = len(tasks) * len(active_envs)
    else:
        valid_count = sum(1 for t in tasks for e in active_envs if _is_valid_combo(t["id"], e))
    log.info("Config: %d tasks x %d envs, %d valid traces%s",
             len(tasks), len(active_envs), valid_count,
             "" if not all_combos else " (--all-combos: running all cross-products)")

    if ablation != "full":
        log.info("Ablation profile: %s -> servers: %s", ablation, sorted(ablation_servers))
        log.info("Tools available: %d (filtered from %d)", len(active_tool_defs), len(TOOL_DEFS))

    # Checkpoint/resume: load existing traces if any.
    all_traces: List[Dict[str, Any]] = []
    completed_keys: set = set()
    jsonl_path = out_path.with_suffix(".checkpoint.jsonl")

    def _is_valid_trace(trace: Dict) -> bool:
        """A trace is valid only if the agent produced at least one tool call."""
        return len(trace.get("events", [])) > 0

    def _load_checkpoint() -> None:
        nonlocal all_traces, completed_keys
        # Primary: load from main JSON
        if out_path.exists():
            try:
                raw = json.loads(out_path.read_text(encoding="utf-8"))
                loaded = raw.get("traces", raw) if isinstance(raw, dict) else raw
                # Drop empty traces (API failures) so they get re-collected
                valid = [t for t in loaded if _is_valid_trace(t)]
                dropped = len(loaded) - len(valid)
                if dropped:
                    log.info("Dropping %d empty traces (API failures) for re-collection", dropped)
                all_traces = valid
                completed_keys = {t["trace_id"] for t in all_traces}
            except (json.JSONDecodeError, KeyError):
                all_traces = []
        # Recover any traces from checkpoint JSONL that aren't in the main file
        if jsonl_path.exists():
            recovered = 0
            for line in jsonl_path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    trace = json.loads(line)
                    tid = trace.get("trace_id", "")
                    if tid and tid not in completed_keys and _is_valid_trace(trace):
                        all_traces.append(trace)
                        completed_keys.add(tid)
                        recovered += 1
                except json.JSONDecodeError:
                    continue
            if recovered:
                log.info("Recovered %d traces from checkpoint JSONL", recovered)
                _save_main()

    def _save_main() -> None:
        """Atomic write: write to temp file, then rename."""
        envelope = {**_schema_header(), "traces": all_traces}
        tmp_path = out_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(envelope, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(out_path)

    def _append_checkpoint(trace: Dict) -> None:
        """Append single trace to JSONL checkpoint (fast, append-only, crash-safe)."""
        with open(jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(trace, ensure_ascii=False) + "\n")

    if not args.dry_run:
        _load_checkpoint()
        if completed_keys:
            log.info("Found %d existing traces, skipping completed tasks", len(completed_keys))

    total_tasks = valid_count
    task_num = 0
    consecutive_api_failures = 0
    early_validated = len(all_traces) >= EARLY_VALIDATE_THRESHOLD

    guard = RuntimeGuard(token_budget=getattr(args, "token_budget", 0))

    # -- Pre-flight smoke test (first run only) --
    if not args.dry_run and not completed_keys:
        setup_workspace(active_envs[0])
        setup_sqlite(active_envs[0])
        smoke_servers = await start_servers(include_browser=include_browser, allowed=ablation_servers)
        if smoke_servers:
            if not await smoke_test_servers(smoke_servers):
                await stop_servers(smoke_servers)
                return
            await stop_servers(smoke_servers)

    for env_type in active_envs:
        log.info("=" * 60)
        log.info("ENVIRONMENT: %s", env_type.upper())
        log.info("=" * 60)

        for task in tasks:
            task_num += 1
            _mit = f"_mit{mit_level[0]}" if mit_level != "none" else ""
            _def = f"_def{defense[0]}" if defense != "none" else ""
            trace_id = f"{task['id']}_{env_type}{_mit}{_def}" if ablation == "full" else f"{task['id']}_{env_type}_{ablation}{_mit}{_def}"

            if trace_id in completed_keys:
                continue

            if not all_combos and not _is_valid_combo(task["id"], env_type):
                continue

            if args.dry_run:
                log.info("[dry-run] Would run: %s in %s env (%s)", task['id'], env_type, ablation)
                continue

            # Quota exhaustion detection: stop early if too many consecutive failures
            if consecutive_api_failures >= MAX_CONSECUTIVE_API_FAILURES:
                log.error("STOP: %d consecutive API failures. Likely quota exhaustion. %d/%d traces saved. Re-run to resume.", consecutive_api_failures, len(completed_keys), total_tasks)
                _save_main()
                if include_browser:
                    _stop_local_http_server()
                return

            max_browser_attempts = 3 if task.get("mechanism") == "browser_to_local" else 1
            trace = None

            for _attempt in range(max_browser_attempts):
                # Reset workspace for EACH task (and each retry) to ensure independence
                setup_workspace(env_type)
                setup_sqlite(env_type)

                expected_ws = workspace.WORKSPACE_BASE / model_slug
                if workspace.ws.workspace != expected_ws:
                    raise RuntimeError(
                        f"WORKSPACE consistency violation: expected {expected_ws}, got {workspace.ws.workspace}. "
                        f"Possible concurrent mutation of global state."
                    )

                # Restart HTTP server per-task so web content matches the current env
                if include_browser:
                    _stop_local_http_server()
                    _start_local_http_server()

                servers = await start_servers(include_browser=include_browser, allowed=ablation_servers)
                if not servers:
                    log.warning("[%s] SKIP (no servers)", trace_id)
                    break

                if "memory" in servers:
                    await setup_memory(servers["memory"], env_type)

                try:
                    trace = await run_agent_task(task, servers, env_type, client, api_model, wire, active_tool_defs, ablation,
                                                mitigation=getattr(args, "mitigation", False),
                                                mitigation_level=mit_level,
                                                defense=getattr(args, "defense", "none"))
                except Exception as exc:
                    log.error("[%s] attempt %d/%d error: %s", trace_id, _attempt+1, max_browser_attempts, exc)
                    trace = None

                await stop_servers(servers)

                if trace is not None:
                    break
                if _attempt < max_browser_attempts - 1:
                    log.info("[%s] browser retry %d/%d", trace_id, _attempt+2, max_browser_attempts)

            if trace is None:
                completed_keys.add(trace_id)
                log.warning("[%s] SKIPPED after %d attempts", trace_id, max_browser_attempts)
                continue

            # Record workspace label separately; keep trace["model"] as the real API model
            if model_label != api_model:
                trace["model_label"] = model_label

            if not _is_valid_trace(trace):
                log.warning("[%s] SKIP saving (0 events — API failure, will retry next run)", trace_id)
                consecutive_api_failures += 1
            else:
                all_traces.append(trace)
                completed_keys.add(trace_id)
                _append_checkpoint(trace)

                # Runtime guard: check invariants after every trace
                guard_ok, guard_reason = guard.check(trace)
                if not guard_ok:
                    log.error("EXPERIMENT HALTED: %s", guard_reason)
                    log.error("Saved %d traces. Fix the issue and re-run to resume.", len(all_traces))
                    _save_main()
                    if include_browser:
                        _stop_local_http_server()
                    return

                # Reset failure counter on success
                if trace.get("api_errors", 0) == 0:
                    consecutive_api_failures = 0
                else:
                    consecutive_api_failures += 1

            if len(completed_keys) % CHECKPOINT_SAVE_INTERVAL == 0:
                _save_main()

            should_validate = (
                (not early_validated and len(all_traces) >= EARLY_VALIDATE_THRESHOLD)
                or (early_validated and len(all_traces) % PERIODIC_VALIDATE_INTERVAL == 0)
            )
            if should_validate:
                early_validated = True
                if not validate_early_traces(all_traces):
                    _save_main()
                    if include_browser:
                        _stop_local_http_server()
                    return

            cleanup_mcp_artifacts()

            # Progress
            done = len(completed_keys)
            remaining = total_tasks - done
            pct = done / total_tasks * 100
            log.info("[progress] %d/%d (%.0f%%) — %d remaining", done, total_tasks, pct, remaining)

    # Final save — atomic write of complete trace set
    if all_traces:
        _save_main()
        # Clean up JSONL checkpoint (all data is in the main file now)
        if jsonl_path.exists():
            jsonl_path.unlink()
            log.info("Cleaned up checkpoint %s", jsonl_path.name)

        _post_collection_integrity_check(all_traces, api_model)

        from mcphunt.datasets.agent_traces import compute_summary
        summary = compute_summary(all_traces)

        n = summary["total"]
        quadrants = summary["outcome_quadrants"]
        log.info("=" * 60)
        log.info("COLLECTION COMPLETE: %s", api_model)
        log.info("=" * 60)
        log.info("Total traces: %d", n)
        log.info("Risk levels: %s", summary['risk_levels'])
        log.info("Risk signals: %s", summary['risk_signal_counts'])
        log.info("Truncated: %d, API errors: %d, Tool errors: %d",
                 summary['truncated'], summary['api_errors_total'], summary['tool_errors_total'])
        log.info("Outcome quadrants:")
        for q in ("safe_success", "unsafe_success", "safe_failure", "unsafe_failure"):
            label = {"safe_success": "ideal", "unsafe_success": "completed but leaked",
                     "safe_failure": "safe but incomplete", "unsafe_failure": "worst case"}[q]
            log.info("  %17s: %4d  (%5.1f%%)  <- %s", q, quadrants[q], quadrants[q]/max(n,1)*100, label)
        log.info("  Utility rate: %.1f%%  |  Safety rate: %.1f%%",
                 summary['utility_rate']*100, summary['safety_rate']*100)
        log.info("Per-environment:")
        for env, info in summary.get("per_environment", {}).items():
            log.info("  %12s: unsafe=%.1f%% (n=%d)", env, info['unsafe_rate']*100, info['n'])
        log.info("Saved to: %s", out_path)

        (out_dir / "collection_summary.json").write_text(
            json.dumps(summary, indent=2), encoding="utf-8"
        )

    if include_browser:
        _stop_local_http_server()

    cleanup_mcp_artifacts()


def main() -> None:
    parser = argparse.ArgumentParser(description="Collect LLM agent traces via MCP servers")
    parser.add_argument("--out-dir", default=str(workspace.DEFAULT_OUT_DIR))  # immutable constant, safe
    parser.add_argument("--tasks", type=int, default=0, help="Limit number of tasks (0=all)")
    parser.add_argument("--envs", default=None,
                        help="Comma-separated environment list (e.g. risky_v1,benign,hard_neg_v1). "
                             "Default: all environments.")
    parser.add_argument("--dry-run", action="store_true", help="Print tasks without executing")
    parser.add_argument("--api-base", default=API_BASE_URL, help="LLM API base URL")
    parser.add_argument("--model", default=API_MODEL, help="LLM model name")
    parser.add_argument("--model-label", default=None,
                        help="Label to record in traces instead of --model. "
                             "Use when the API model name is generic (e.g. astron-code-latest) "
                             "but you want traces tagged with the actual backend model.")
    parser.add_argument("--api-key", default="", help="API key (overrides OPENAI_API_KEY env var)")
    parser.add_argument("--wire-api", default="chat", choices=["chat", "responses", "vertex"],
                        help="API format: 'chat' (OpenAI), 'responses' (OpenAI), 'vertex' (Claude via Vertex AI)")
    parser.add_argument("--vertex-region", default="us-east5", help="Vertex AI region")
    parser.add_argument("--suite", default="base", choices=["base", "browser", "all"],
                        help="Task suite: 'base' (70 tasks), 'browser' (12 browser tasks), 'all' (both)")
    parser.add_argument("--ablation", default="full", choices=list(ABLATION_PROFILES.keys()),
                        help="Server ablation profile (default: full). "
                             "Restricts which MCP servers are available to prove compositional necessity.")
    parser.add_argument("--mitigation", action="store_true",
                        help="Enable safety mitigation prompt (legacy flag, equivalent to --mitigation-level moderate).")
    parser.add_argument("--mitigation-level", default="none",
                        choices=list(MITIGATION_LEVELS.keys()),
                        help="Graduated mitigation level: none (M0 baseline), generic (M1 brief reminder), "
                             "moderate (M2 specific rules), detailed (M3 boundary-aware with examples). "
                             "Overrides --mitigation if both are specified.")
    parser.add_argument("--defense", default="none",
                        choices=["none", "taint_tracking"],
                        help="Runtime defense: 'taint_tracking' blocks writes containing previously-read canary values.")
    parser.add_argument("--all-combos", action="store_true",
                        help="Run ALL task×environment cross-products (default: only scientifically valid combinations, ~50%% fewer traces).")
    parser.add_argument("--token-budget", type=int, default=0,
                        help="Max total tokens before auto-halt (0=unlimited). Guards against runaway costs.")
    args = parser.parse_args()

    log_file = Path(args.out_dir) / "collection.log" if not args.dry_run else None
    setup_logging(log_file=log_file)

    asyncio.run(run(args))


if __name__ == "__main__":
    main()
