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

.PHONY: test download relabel reproduce paired sanitize release all

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

## Recompute the matched-pair analyses (hard-negative 2x2 + live-guard pairs)
## Needs the supplemental arms (live-guard defense + browser replication);
## `make download` restores them to the paths these scripts default to, so the
## reviewer path is `make download && make paired` in a fresh clone.
paired:
	$(PYTHON) scripts/compute_hard_negative_ci.py
	$(PYTHON) scripts/analyze_paired_live_guard.py

## Sanitize traces for anonymous release
sanitize:
	$(PYTHON) scripts/sanitize_traces.py --apply

## Rebuild both HuggingFace staging bundles (sanitize -> recompute -> stage)
release:
	$(PYTHON) scripts/generate_croissant_metadata.py
	$(PYTHON) scripts/prepare_huggingface_release.py

## Full local pipeline: relabel + reproduce
## Keep `paired` explicit: it needs the supplemental release inputs, so folding
## it into `all` would reintroduce a hidden dependency for ordinary worktrees.
all: relabel reproduce
	@echo "=== All targets complete ==="
