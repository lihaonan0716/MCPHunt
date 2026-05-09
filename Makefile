# MCPHunt — one-command pipeline targets
# Reviewer quickstart: make download && make reproduce
# Full pipeline:       make test && make verify

# Cross-platform shell and python detection
ifeq ($(OS),Windows_NT)
  PYTHON := python
else
  SHELL  := /bin/bash
  PYTHON := python3
endif

PYTHONPATH := src
export PYTHONPATH

TRACE_FILES := $(wildcard results/agent_traces/*/agent_traces.json)

# ── Core targets ──────────────────────────────────────────────

.PHONY: test download relabel reproduce sanitize all

## Run unit tests
test:
	$(PYTHON) -m pytest tests/ -v

## Download traces from HuggingFace to results/
download:
	$(PYTHON) scripts/download_traces.py

## Recompute all risk signals from raw trace events
relabel:
	@echo "=== Relabeling $(words $(TRACE_FILES)) trace files ==="
	@for f in $(TRACE_FILES); do \
		echo "  relabel: $$f"; \
		$(PYTHON) scripts/relabel_traces.py "$$f"; \
	done
	@echo "=== Done ==="

## Reproduce all 16 paper tables (6 main + 10 appendix) from raw traces
reproduce:
	$(PYTHON) scripts/reproduce_paper_tables.py

## Sanitize traces for anonymous release
sanitize:
	$(PYTHON) scripts/sanitize_traces.py --apply

## Full pipeline: relabel + reproduce
all: relabel reproduce
	@echo "=== All targets complete ==="
