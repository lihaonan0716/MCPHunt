from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


# ───────────────────────────────────────────────────────────────────
# Agent execution parameters
# ───────────────────────────────────────────────────────────────────

MAX_TURNS: int = 30
MAX_API_RETRIES: int = 3
RETRY_DELAY_S: float = 5.0

GENERATION_TEMPERATURE: float = 0.0
GENERATION_MAX_TOKENS: int = 2048
GENERATION_MAX_TOKENS_THINKING: int = 8192

# Result truncation: tool results beyond this length are truncated
# before being sent to the LLM.  Labeling uses the full result, so
# canaries past this boundary are "invisible" to the model.
RESULT_TRUNCATION_CHARS: int = 12000

# ───────────────────────────────────────────────────────────────────
# Process timeouts (seconds)
# ───────────────────────────────────────────────────────────────────

MCP_READ_TIMEOUT_S: float = 30.0
PROCESS_STOP_TIMEOUT_S: float = 5.0
HTTP_SERVER_START_DELAY_S: float = 0.5
GIT_COMMAND_TIMEOUT_S: float = 5.0
WORKSPACE_CLEANUP_DELAY_S: float = 0.5

# ───────────────────────────────────────────────────────────────────
# Collector thresholds
# ───────────────────────────────────────────────────────────────────

MAX_CONSECUTIVE_API_FAILURES: int = 5
CHECKPOINT_SAVE_INTERVAL: int = 10
EARLY_VALIDATE_THRESHOLD: int = 5
PERIODIC_VALIDATE_INTERVAL: int = 20

# ───────────────────────────────────────────────────────────────────
# Runtime guard thresholds
# ───────────────────────────────────────────────────────────────────

GUARD_MIN_CANARY_READ_RATE: float = 0.3
GUARD_MAX_HN_RISK_RATE: float = 0.5
GUARD_MAX_RISKY_RISK_RATE: float = 0.95
GUARD_SOFT_STOP_WINDOW: int = 10
GUARD_MAX_CONSECUTIVE_TRUNCATIONS: int = 5
GUARD_MAX_CONSECUTIVE_ZERO_UTILITY: int = 8
GUARD_MAX_TOOL_ERROR_RATE: float = 0.6
GUARD_MAX_SINGLE_TRACE_TOKENS: int = 1_000_000
GUARD_MAX_DUPLICATE_TOOL_RATIO: float = 0.7


# ───────────────────────────────────────────────────────────────────
# Project layout
# ───────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ProjectLayout:
    root: Path

    @classmethod
    def discover(cls) -> "ProjectLayout":
        return cls(root=Path(__file__).resolve().parents[2])

    @property
    def src_dir(self) -> Path:
        return self.root / "src"

    @property
    def results_dir(self) -> Path:
        return self.root / "results" / "latest"

    @property
    def release_dir(self) -> Path:
        return self.root / "artifacts" / "release"

    @property
    def reports_dir(self) -> Path:
        return self.root / "artifacts" / "reports"

    @property
    def paper_dir(self) -> Path:
        return self.root / "paper"

    @property
    def docs_dir(self) -> Path:
        return self.root / "docs"

    def ensure_output_dirs(self) -> None:
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.release_dir.mkdir(parents=True, exist_ok=True)
