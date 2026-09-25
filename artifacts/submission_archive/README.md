# Submission-Time Archive

Frozen, byte-exact copies of artifacts as they existed at the original NeurIPS
2026 submission. These files are **historical evidence, not deliverables**: they
record what reviewers actually saw, so that later corrections can be stated as
corrections rather than quietly overwritten.

**Nothing in this directory is published, uploaded, or consumed by any script.**
The live release artifacts are in `artifacts/release/`; the upload bundles are
built into `artifacts/huggingface-staging*/`. Never copy a file from here into
either location.

## Contents

| File | What it is |
|------|------------|
| `croissant.submitted-2026-05-06.json` | The Croissant metadata accompanying the original submission (`version` 1.0.0, `datePublished` 2026-05-06). |

### `croissant.submitted-2026-05-06.json`

- Archived verbatim from the maintainer's submitted copy, 2026-09-25.
- SHA-256: `421f365a30ceee24a21195e1a79f532b75d1cf3adcf6f81a76ce7b52c294402b`
- 13,629 bytes, UTF-8 (pure ASCII), LF line endings, no BOM.

**This file contains statements that are now known to be false.** It is retained
*because* of that, under the provenance-before-value invariant: the retraction is
only auditable if the retracted text survives. Do not reuse its wording.

Known-superseded content, and where the truth now lives:

| Field | Submitted copy says | Current status |
|-------|--------------------|----------------|
| `rai:dataAnnotationProtocol` | CRS labels assigned "before experiments by two annotators (Cohen's kappa = 0.89)" | **Unsupported; retracted.** No annotation event backed this. A genuine post-submission blind audit by two non-author annotators later gave kappa = 0.7097, agreement 138/147 = 93.9%. Raw labels: `artifacts/release/crs_audit/`; scoring: `scripts/score_annotation.py`. |
| `rai:dataAnnotationAnalysis` | "CRS inter-annotator agreement: 97.3%" | **Unsupported; retracted.** Same as above. |
| `description` | "2,885 mitigation-study traces" | Stale. The true mitigation count is 2,706 (6,321 released total). |
| `creator`, `publisher`, `citeAs` | `Anonymous` | Double-blind review placeholders. The named release records Haonan Li and the full author list. |
| `url` | `huggingface.co/datasets/mcphunt-benchmark/...` | The anonymous review-time HF organization (a real, working URL so reviewers could run `make download`; commit `02869da`). The de-anonymized dataset lives under `lihaonan0716/`. |
| `rai:dataLimitation(s)` | "exact and **near-exact** canary matches" | Imprecise. Detection is exact substring only (`find_canary_matches`); "near-exact" overstates coverage. |
| `rai:dataLimitations`, `rai:hasSyntheticData` | present | Dropped from the current metadata (`rai:dataLimitations` was a duplicate of `rai:dataLimitation`). |

## The checksums are a regression, not a design choice

One property of the submitted copy is *better* than the current release: every
`distribution` entry carried a `sha256`. All 13 entries in
`artifacts/release/croissant.json` currently carry none.

Those checksums were real, not decorative — the archived `meta/regression_data.csv`
hash (`6098d24d…`) still matches that file byte-for-byte today. The five trace
hashes no longer match, for a benign reason: commit `1e9d886` extended the
sanitizer with Windows/VSCode PII rules, so the released trace bytes legitimately
changed afterwards.

But no commit in this repository has ever produced a `croissant.json` containing
a checksum — not even the initial commit. Field-by-field, the submitted copy is
commit `02869da`'s generator output plus hand-added `sha256` values and two extra
RAI fields. The checksums were therefore added **by hand, downstream of
`scripts/generate_croissant_metadata.py`**, and every later regeneration silently
dropped them. This is exactly the failure mode invariant #1 exists to prevent:
hand-patching a generated artifact does not survive the next regeneration.

Restoring them belongs in the generator, not in an edited output file. Tracked as
camera-ready work; not a defect of this archive.

## Adding to this directory

Archive a file here only when it is (a) the exact bytes shown to reviewers or
another external party, and (b) superseded by something in `artifacts/release/`.
Record its SHA-256 and the date archived, and list every superseded claim in the
table above. Never edit an archived file after it lands — if it was archived
wrong, delete it and re-archive from the original source.
