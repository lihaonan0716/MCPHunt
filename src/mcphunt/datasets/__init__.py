"""Agent trace dataset package.

Sub-modules:
  agent_traces   — LLM agent trace loading, record construction, summary
  loader         — dataset loading and splitting
"""

from .loader import build_splits, load_records
from .agent_traces import AGENT_DATASET, load_agent_traces, load_agent_records, compute_summary

__all__ = [
    "AGENT_DATASET",
    "build_splits",
    "compute_summary",
    "load_agent_records",
    "load_agent_traces",
    "load_records",
]
