# MCPHunt: An Evaluation Framework for Cross-Boundary Data Propagation in Multi-Server MCP Agents

MCPHunt is an evaluation framework for measuring *cross-boundary data
propagation* in multi-server Model Context Protocol (MCP) agents---cases where
sensitive data flows across trust boundaries as a structural side effect of
faithful task execution, not adversarial manipulation.

Three methodological pillars:

1. **Canary-based taint tracking** --- format-authentic canary secrets
   (`sk_live_*`, `AKIA*`, `ghp_*`) reduce propagation detection to objective
   string matching, eliminating reliance on human annotation.
2. **Environment-controlled design** --- each task runs in risky, benign, and
   hard-negative conditions with identical workspace structure; the difference
   in propagation rate isolates the causal effect of data content.
3. **CRS stratification** --- distinguishes task-mandated propagation
   (verbatim-transfer instructions) from policy-violating propagation
   (credentials included despite the option to redact).

---

## Key Results

Across **3,615 traces** from **5 models** (GPT-5.4, GPT-5.2, DeepSeek-V4-Flash,
Gemini-3.1-Pro, MiniMax-M2.7):

- Confirmed canary propagation in **20.2--45.2%** of risky-environment runs;
  benign controls produce **zero** signals.
- Risk is **pathway-specific**: a 25x mechanism range; browser-mediated
  pathways remain high-risk (66.7--92.3%) across all models.
- CRS stratification reveals **policy-violating propagation rates of
  11.5--41.3%**, concentrated in browser-mediated pathways.
- Graduated prompt mitigations reduce propagation from 22.9% to 2.3% while
  preserving 80.5% task utility.

---

## Repository Layout

| Path | Purpose |
|------|---------|
| `src/mcphunt/` | Installable package: agent loop, labeling, MCP driver, taxonomy |
| `scripts/` | Collection, relabeling, evaluation, and table reproduction |
| `tests/` | Unit tests for labeling integrity and project smoke tests |
| `configs/` | MCP server versions and API key template |
| `artifacts/release/` | Croissant metadata, experiment config, aggregated results |

---

## Data & Traces

Agent traces (3,615 main + 2,706 mitigation) are published on HuggingFace:

> **\<anonymous-dataset-url\>**

## Quickstart (Reproduce Paper Results)

```bash
# 1. Install
pip install -e ".[download]"

# 2. Download traces from HuggingFace (~500 MB)
make download

# 3. Reproduce all 16 data tables in the paper
make reproduce
```

---

## Running Experiments

To collect traces with your own model, install with `pip install -e ".[collect]"`,
create `configs/api_keys.yaml` (see `api_keys.yaml.example`), and run:

```bash
# Collect traces for a single model (all 147 tasks × 7 environments)
PYTHONPATH=src python3 scripts/collect_agent_traces.py \
  --model gpt-5.4 \
  --api-base "https://api.openai.com/v1" \
  --api-key "$OPENAI_API_KEY" \
  --out-dir results/agent_traces/my_model

# Quick smoke test (1 task × 3 environments)
PYTHONPATH=src python3 scripts/collect_agent_traces.py \
  --model gpt-5.4 \
  --api-base "https://api.openai.com/v1" \
  --api-key "$OPENAI_API_KEY" \
  --tasks 1 --envs risky_v1,benign,hard_neg_v1 \
  --out-dir results/smoke_test

# Run with prompt mitigation (M1/M2/M3)
PYTHONPATH=src python3 scripts/collect_agent_traces.py \
  --model gpt-5.4 \
  --api-base "https://api.openai.com/v1" \
  --api-key "$OPENAI_API_KEY" \
  --mitigation --mitigation-level detailed \
  --out-dir results/mitigation_traces/my_model_m3
```

The harness supports any OpenAI-compatible endpoint. Adding a new model
requires only the `--model`, `--api-base`, and `--api-key` flags.
Checkpoint/resume is automatic: interrupted runs restart from the last
completed trace.

## Development

```bash
make test       # run unit tests
make relabel    # recompute risk signals from raw trace events
make sanitize   # sanitize traces for anonymous release
```

---

## Evaluation Design

### 9 Risk Mechanism Families

| Mechanism | Source | Sink |
|-----------|--------|------|
| `file_to_file` | filesystem | filesystem |
| `file_to_doc` | filesystem | filesystem (doc) |
| `config_to_script` | config | executable |
| `db_to_artifact` | database | filesystem/KG |
| `sensitive_to_shell` | file/DB | shell command |
| `forced_multi_hop` | varies | varies |
| `git_history_leak` | git | filesystem |
| `browser_to_local` | browser | file/DB/KG |
| `indirect_exposure` | incidental | varies |

### Environment Variants

- **Risky** (v1/v2/v3): canary-seeded workspaces with format-authentic secrets
- **Benign**: identical structure, innocuous placeholder values
- **Hard-negative** (v1/v2/v3): human-readable placeholder canaries for
  detector specificity testing

### Signal Detection

11 binary risk signals in two tiers:
- **Tier-1 (confirmed propagation, 8 signals):** `data_flow`,
  `cross_boundary_flow`, `secret_in_executable`, `secret_in_command`,
  `opaque_transfer`, `browser_sensitive_input`, `partial_leak`, `semantic_leak`
- **Tier-2 (structural risk, 3 signals):** `sensitive_schema_flow`,
  `external_after_sensitive`, `authority_escalation`

### 8 MCP Servers

filesystem, git, sqlite, memory/KG, fetch, time, browser, shell

---

## Reproducibility

```bash
# Relabel traces with current labeling rules
PYTHONPATH=src python3 scripts/relabel_traces.py <trace_file.json>

# Reproduce all 16 data tables from raw traces
PYTHONPATH=src python3 scripts/reproduce_paper_tables.py

```

Every numeric value in the paper traces back through:
1. `src/mcphunt/taxonomy.py` (task & mechanism definitions)
2. `src/mcphunt/labeling.py` (11-signal risk labeling)
3. `scripts/relabel_traces.py` (offline re-computation)
4. `scripts/reproduce_paper_tables.py` (table reproduction & verification)

---

## Responsible Use

- **Synthetic only.** All canary values are synthetic. No production data,
  real credentials, or live MCP servers are used.
- **Non-adversarial.** The framework studies normal task execution, not
  attacks. All MCP servers are trusted and benign.
- **Defensive intent.** Intended for pre-deployment evaluation of MCP-agent
  safety, not offensive operations.
- **License:** Code under MIT; dataset under CC-BY-4.0.

---

## Citation

```bibtex
@misc{mcphunt2026,
  title  = {MCPHunt: An Evaluation Framework for Cross-Boundary Data
            Propagation in Multi-Server MCP Agents},
  author = {Anonymous},
  year   = {2026}
}
```
