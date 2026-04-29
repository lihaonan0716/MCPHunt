"""Runtime invariant guard — fail-fast on anomalies to save tokens.

Checks invariants after every collected trace and halts the experiment
immediately when a violation is detected.  Three severity levels:

- **HALT**: single-trace violation that indicates a bug or contamination.
- **ALARM**: cumulative anomaly detected after a sliding window.
- **BUDGET**: cost limit reached.

Integrated into the collection loop via ``RuntimeGuard.check()``.
"""
from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, List, Tuple

from .config import (
    GUARD_MIN_CANARY_READ_RATE,
    GUARD_MAX_HN_RISK_RATE,
    GUARD_MAX_RISKY_RISK_RATE,
    GUARD_SOFT_STOP_WINDOW,
    GUARD_MAX_CONSECUTIVE_TRUNCATIONS,
    GUARD_MAX_CONSECUTIVE_ZERO_UTILITY,
    GUARD_MAX_TOOL_ERROR_RATE,
    GUARD_MAX_SINGLE_TRACE_TOKENS,
    GUARD_MAX_DUPLICATE_TOOL_RATIO,
)
from .log import get_logger

log = get_logger(__name__)


@dataclass
class _Counters:
    """Running counters per environment class."""
    total: int = 0
    canary_reads: int = 0
    canary_writes: int = 0
    any_risk: int = 0
    sensitive_read: int = 0
    risk_task_total: int = 0
    risk_task_sensitive_read: int = 0


class RuntimeGuard:
    """Fail-fast guard for the collection pipeline.

    Usage::

        guard = RuntimeGuard(token_budget=5_000_000)
        ...
        ok, reason = guard.check(trace)
        if not ok:
            save_and_exit(reason)
    """

    def __init__(
        self,
        token_budget: int = 0,
        min_canary_read_rate: float = GUARD_MIN_CANARY_READ_RATE,
        max_hn_risk_rate: float = GUARD_MAX_HN_RISK_RATE,
        max_risky_risk_rate: float = GUARD_MAX_RISKY_RISK_RATE,
        soft_stop_window: int = GUARD_SOFT_STOP_WINDOW,
        max_consecutive_truncations: int = GUARD_MAX_CONSECUTIVE_TRUNCATIONS,
        max_consecutive_zero_utility: int = GUARD_MAX_CONSECUTIVE_ZERO_UTILITY,
        max_tool_error_rate: float = GUARD_MAX_TOOL_ERROR_RATE,
        max_single_trace_tokens: int = GUARD_MAX_SINGLE_TRACE_TOKENS,
        max_duplicate_tool_ratio: float = GUARD_MAX_DUPLICATE_TOOL_RATIO,
    ) -> None:
        self._token_budget = token_budget
        self._min_canary_read_rate = min_canary_read_rate
        self._max_hn_risk_rate = max_hn_risk_rate
        self._max_risky_risk_rate = max_risky_risk_rate
        self._soft_stop_window = soft_stop_window
        self._max_consecutive_truncations = max_consecutive_truncations
        self._max_consecutive_zero_utility = max_consecutive_zero_utility
        self._max_tool_error_rate = max_tool_error_rate
        self._max_single_trace_tokens = max_single_trace_tokens
        self._max_duplicate_tool_ratio = max_duplicate_tool_ratio

        self._tokens_used: int = 0
        self._trace_count: int = 0
        self._counters: Dict[str, _Counters] = {}
        self._violations: List[str] = []

        # Sliding window trackers
        self._consecutive_truncations: int = 0
        self._consecutive_zero_utility: int = 0
        self._last_mechanism: str = ""
        self._token_spike_count: int = 0
        self._recent_token_costs: Deque[int] = deque(maxlen=20)
        self._total_tool_calls: int = 0
        self._total_tool_errors: int = 0

    def _env_class(self, env_type: str) -> str:
        if env_type.startswith("risky"):
            return "risky"
        if env_type.startswith("hard_neg"):
            return "hard_neg"
        return "benign"

    def _get_counter(self, env_class: str) -> _Counters:
        if env_class not in self._counters:
            self._counters[env_class] = _Counters()
        return self._counters[env_class]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, trace: Dict[str, Any]) -> Tuple[bool, str]:
        """Check one trace against all invariants.

        Returns ``(True, "")`` if OK, ``(False, reason)`` to halt.
        """
        env_type = trace.get("env_type", "")
        env_cls = self._env_class(env_type)
        ctr = self._get_counter(env_cls)
        labeling = trace.get("labeling", {})
        events = trace.get("events", [])
        measurement = trace.get("measurement", {})
        checks = trace.get("completion_checks", {})

        self._trace_count += 1
        ctr.total += 1

        has_canary_read = any(e.get("canary_in_result") for e in events)
        has_canary_write = any(e.get("canary_in_args") for e in events)
        any_risk = labeling.get("any_risk", False)
        sensitive_read = labeling.get("sensitive_data_read", False)

        if has_canary_read:
            ctr.canary_reads += 1
        if has_canary_write:
            ctr.canary_writes += 1
        if any_risk:
            ctr.any_risk += 1
        if sensitive_read:
            ctr.sensitive_read += 1

        task_id = trace.get("task_id", "")
        is_risk_task = not task_id.startswith("hn_") and not task_id.startswith("check_") and not task_id.startswith("write_readme")
        if env_cls == "risky" and is_risk_task:
            ctr.risk_task_total += 1
            if sensitive_read:
                ctr.risk_task_sensitive_read += 1

        trace_tokens = measurement.get("total_tokens", 0)
        self._tokens_used += trace_tokens
        self._recent_token_costs.append(trace_tokens)

        n_events = len(events)
        n_errors = sum(1 for e in events if not e.get("success", True))
        self._total_tool_calls += n_events
        self._total_tool_errors += n_errors

        is_truncated = trace.get("truncated", False)
        artifact_verified = checks.get("artifact_verified", False)

        # ==============================================================
        # HALT checks — single-trace violations (immediate stop)
        # ==============================================================

        # H1: Benign contamination
        # Note: canary_in_result=True in benign env is EXPECTED — benign
        # canaries (sk_test_*) are registered so detection is empirically
        # tested rather than detection-blind.  Only any_risk=True is a bug.
        if env_cls == "benign" and any_risk:
            return self._halt(trace, "CONTAMINATION: benign env trace has any_risk=True")

        # H2: Labeling gap — canary written but no signal caught it
        if has_canary_write and not any_risk:
            signals = labeling.get("risk_signals", {})
            active = [s for s, v in signals.items() if v]
            if not active:
                return self._halt(
                    trace,
                    "LABELING GAP: canary_in_args=True but zero risk signals fired"
                )

        # H3: Model stuck — hit MAX_TURNS with zero successful tool calls
        n_success = sum(1 for e in events if e.get("success", True))
        if is_truncated and n_success == 0 and n_events > 0:
            return self._halt(
                trace,
                f"MODEL STUCK: hit MAX_TURNS with 0/{n_events} successful "
                f"tool calls — model is burning tokens on failures"
            )

        # H4: Tool call loop — model calling the same tool with same args
        if n_events >= 6:
            calls = [(e.get("tool", ""), str(e.get("args", {}))) for e in events]
            call_counts = Counter(calls)
            most_common_count = call_counts.most_common(1)[0][1]
            dup_ratio = most_common_count / n_events
            if dup_ratio >= self._max_duplicate_tool_ratio:
                tool_name = call_counts.most_common(1)[0][0][0]
                return self._halt(
                    trace,
                    f"TOOL LOOP: {tool_name} called {most_common_count}/{n_events} "
                    f"times with identical args ({dup_ratio:.0%}) — model is looping"
                )

        # H5: Single trace token spike — warn and count, but only HALT on repeated spikes
        if (self._max_single_trace_tokens > 0
                and trace_tokens > self._max_single_trace_tokens):
            self._token_spike_count += 1
            task_id = trace.get("task_id", "?")
            log.warning(
                "[%s] TOKEN SPIKE: %s tokens (limit: %s) — spike #%d",
                task_id, f"{trace_tokens:,}", f"{self._max_single_trace_tokens:,}",
                self._token_spike_count,
            )
            if self._token_spike_count >= 3:
                return self._halt(
                    trace,
                    f"TOKEN SPIKE: {self._token_spike_count} traces exceeded "
                    f"{self._max_single_trace_tokens:,} token limit — systemic issue"
                )

        # ==============================================================
        # ALARM checks — cumulative anomalies (after enough observations)
        # ==============================================================

        # A1: Risky env canary read rate too low (risk tasks only, excludes HN/benign tasks in risky env)
        if env_cls == "risky" and ctr.risk_task_total >= self._soft_stop_window:
            read_rate = ctr.risk_task_sensitive_read / ctr.risk_task_total
            if read_rate < self._min_canary_read_rate:
                return self._halt(
                    trace,
                    f"ENV BROKEN: risky env canary read rate = {read_rate:.0%} "
                    f"(< {self._min_canary_read_rate:.0%}) after {ctr.risk_task_total} risk tasks — "
                    f"canaries not reaching agent"
                )

        # A2: Hard-neg risk rate too high
        if env_cls == "hard_neg" and ctr.total >= self._soft_stop_window:
            risk_rate = ctr.any_risk / ctr.total
            if risk_rate > self._max_hn_risk_rate:
                return self._halt(
                    trace,
                    f"ANOMALY: hard_neg risk rate = {risk_rate:.0%} "
                    f"(> {self._max_hn_risk_rate:.0%}) after {ctr.total} traces — "
                    f"HN control is not working"
                )

        # A3: Risky env leak rate suspiciously high
        if env_cls == "risky" and ctr.total >= self._soft_stop_window:
            risk_rate = ctr.any_risk / ctr.total
            if risk_rate > self._max_risky_risk_rate:
                return self._halt(
                    trace,
                    f"ANOMALY: risky env risk rate = {risk_rate:.0%} "
                    f"(> {self._max_risky_risk_rate:.0%}) after {ctr.total} traces — "
                    f"labeling may be over-triggering"
                )

        # A4: Consecutive truncations (model keeps hitting MAX_TURNS)
        if is_truncated:
            self._consecutive_truncations += 1
        else:
            self._consecutive_truncations = 0

        if self._consecutive_truncations >= self._max_consecutive_truncations:
            return self._halt(
                trace,
                f"STUCK: {self._consecutive_truncations} consecutive traces "
                f"hit MAX_TURNS — model cannot complete tasks"
            )

        # A5: Consecutive zero utility (model never produces artifacts)
        # Only count consecutive failures within the SAME mechanism family
        # to avoid false halts from task-ordering effects (e.g., a batch of
        # hard browser tasks followed by easy file tasks).
        current_mechanism = trace.get("risk_mechanism",
                                      trace.get("mechanism_family", ""))
        if not artifact_verified:
            if current_mechanism == self._last_mechanism:
                self._consecutive_zero_utility += 1
            else:
                self._consecutive_zero_utility = 1
        else:
            self._consecutive_zero_utility = 0
        self._last_mechanism = current_mechanism

        if self._consecutive_zero_utility >= self._max_consecutive_zero_utility:
            return self._halt(
                trace,
                f"NO UTILITY: {self._consecutive_zero_utility} consecutive traces "
                f"in mechanism '{current_mechanism}' with artifact_verified=False"
            )

        # A6: Global tool error rate climbing
        if (self._total_tool_calls >= 50
                and self._total_tool_errors / self._total_tool_calls > self._max_tool_error_rate):
            err_rate = self._total_tool_errors / self._total_tool_calls
            return self._halt(
                trace,
                f"MCP DEGRADED: global tool error rate = {err_rate:.0%} "
                f"({self._total_tool_errors}/{self._total_tool_calls}) — "
                f"MCP servers are failing"
            )

        # ==============================================================
        # BUDGET — cost limit
        # ==============================================================

        if self._token_budget > 0 and self._tokens_used > self._token_budget:
            return self._halt(
                trace,
                f"TOKEN BUDGET: {self._tokens_used:,} tokens used "
                f"(budget: {self._token_budget:,})"
            )

        return True, ""

    def summary(self) -> Dict[str, Any]:
        """Return guard statistics for inclusion in the output."""
        return {
            "tokens_used": self._tokens_used,
            "token_budget": self._token_budget,
            "trace_count": self._trace_count,
            "tool_calls_total": self._total_tool_calls,
            "tool_errors_total": self._total_tool_errors,
            "tool_error_rate": round(
                self._total_tool_errors / max(self._total_tool_calls, 1), 4),
            "counters": {
                k: {"total": c.total, "canary_reads": c.canary_reads,
                     "any_risk": c.any_risk, "sensitive_read": c.sensitive_read,
                     "risk_task_total": c.risk_task_total,
                     "risk_task_sensitive_read": c.risk_task_sensitive_read}
                for k, c in self._counters.items()
            },
            "violations": self._violations,
        }

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _halt(self, trace: Dict, reason: str) -> Tuple[bool, str]:
        tid = trace.get("trace_id", "?")
        msg = f"[{tid}] GUARD HALT: {reason}"
        log.error(msg)
        self._violations.append(msg)
        return False, reason
