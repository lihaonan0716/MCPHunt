"""Release-bundle contract tests for the reviewer reproduction path.

Pins the specific release/reproduction guarantees that must not drift:
`make download && make paired` restores the paired-analysis default inputs,
the staging bundle stays in step with the Croissant identities it ships,
Croissant declares the paired artifacts, and the dataset card documents where
paired analyses are recomputed before staging copies them into `meta/`.
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"
for p in (REPO_ROOT / "src", SCRIPTS_ROOT):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

import download_traces as DL  # noqa: E402
import generate_croissant_metadata as CRO  # noqa: E402
import prepare_huggingface_release as PREP  # noqa: E402


class DownloadRestoreContractTest(unittest.TestCase):
    def test_repo_id_resolution_precedence(self) -> None:
        with mock.patch.dict(DL.os.environ, {}, clear=False):
            repo_id, source = DL.resolve_repo_id(None)
            self.assertEqual(repo_id, DL.DEFAULT_HF_REPO_ID)
            self.assertEqual(source, "default")

        with mock.patch.dict(DL.os.environ,
                             {DL.HF_REPO_ENV_VAR: "env-owner/mcphunt-copy"},
                             clear=False):
            repo_id, source = DL.resolve_repo_id(None)
            self.assertEqual(repo_id, "env-owner/mcphunt-copy")
            self.assertEqual(source, DL.HF_REPO_ENV_VAR)

            repo_id, source = DL.resolve_repo_id("cli-owner/mcphunt-copy")
            self.assertEqual(repo_id, "cli-owner/mcphunt-copy")
            self.assertEqual(source, "CLI")

    def test_fetch_uses_explicit_repo_override_not_global_default(self) -> None:
        called = {}

        def fake_download(**kwargs):
            called.update(kwargs)
            src = tmpdir / "downloaded.json"
            src.write_text('{"ok": true}', encoding="utf-8")
            return str(src)

        with tempfile.TemporaryDirectory() as tmp:
            tmpdir = Path(tmp)
            target = tmpdir / "results" / "agent_traces.json"
            DL._fetch(fake_download, "cli-owner/mcphunt-copy",
                      "main/gpt_5_4.json", target)

        self.assertEqual(called["repo_id"], "cli-owner/mcphunt-copy")
        self.assertEqual(called["filename"], "main/gpt_5_4.json")

    def test_supplemental_downloads_restore_default_analysis_paths(self) -> None:
        mapping = dict(DL.SUPPLEMENTAL_FILES)
        self.assertEqual(
            mapping["live_guard_defense/deepseek_v4_flash.json"],
            "agent_traces/deepseek_v4_flash/agent_traces_deft.json",
        )
        self.assertEqual(
            mapping["browser_replication/deepseek_v4_flash_baseline.json"],
            "agent_traces_b3_replication/deepseek_v4_flash/agent_traces_browser.json",
        )
        self.assertEqual(
            mapping["browser_replication/deepseek_v4_flash_defense.json"],
            "agent_traces_b3_replication/deepseek_v4_flash/agent_traces_browser_deft.json",
        )

    def test_downloads_restore_all_released_paired_reference_artifacts(self) -> None:
        self.assertEqual(
            set(DL.PAIRED_META_FILES),
            {
                ("meta/guarded_run_provenance.json",
                 "live_guard_replication/guarded_run_provenance.json"),
                ("meta/paired_live_guard_analysis.json",
                 "live_guard_replication/paired_live_guard_analysis.json"),
                ("meta/live_guard_deepseek_v4_flash_paired.json",
                 "mitigation_analysis/live_guard_deepseek_v4_flash_paired.json"),
                ("meta/hard_negative_ci.json",
                 "hard_negative_analysis/hard_negative_ci.json"),
                # The manuscript's miss-prevalence macros read this file under
                # its run-tagged name, so a fresh clone must restore it there.
                ("recall_evaluation/recall_estimation.json",
                 "recall_evaluation/recall_estimation_claude-opus-4-8_seed20260729_n150.json"),
            },
        )

    def test_restored_recall_path_is_what_the_macro_generator_reads(self) -> None:
        import generate_results_macros as grm
        restored = dict(DL.PAIRED_META_FILES)["recall_evaluation/recall_estimation.json"]
        self.assertEqual(DL.RESULTS_DIR / restored, grm.MISS_PREVALENCE_ARTIFACT)


class ReleaseBundleContractTest(unittest.TestCase):
    def test_make_all_keeps_paired_explicit(self) -> None:
        makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
        self.assertIn("all: relabel reproduce", makefile)
        self.assertNotIn("all: relabel reproduce paired", makefile)
        self.assertIn("make download && make paired", makefile)

    def test_staging_variants_match_croissant_identities(self) -> None:
        self.assertEqual(set(PREP.STAGING_VARIANTS), set(CRO.RELEASE_IDENTITIES))
        for key, staging in PREP.STAGING_VARIANTS.items():
            self.assertEqual(staging["croissant"],
                             CRO.RELEASE_IDENTITIES[key]["filename"])

    def test_no_anonymous_release_identity_remains(self) -> None:
        # The anonymous review identity was retired after acceptance. This pins
        # it as retired so a merge or a copied dict cannot quietly revive an
        # identity that would publish under "Anonymous".
        self.assertNotIn("anon", CRO.RELEASE_IDENTITIES)
        self.assertNotIn("anon", PREP.STAGING_VARIANTS)

    def test_release_dir_has_no_orphaned_croissant(self) -> None:
        # generate_croissant_metadata.py only ever writes files; it does not
        # remove the output of an identity that has since been retired. Without
        # this check a stale croissant could sit in the public release dir
        # indefinitely, still declaring the old identity.
        release_dir = REPO_ROOT / "artifacts" / "release"
        declared = {i["filename"] for i in CRO.RELEASE_IDENTITIES.values()}
        on_disk = {p.name for p in release_dir.glob("croissant*.json")}
        self.assertEqual(
            on_disk, declared,
            f"orphaned croissant file(s): {sorted(on_disk - declared)}")

    def test_named_citation_keeps_full_arxiv_reference(self) -> None:
        named_meta = CRO.build_metadata(CRO.RELEASE_IDENTITIES["named"])
        named_cite = named_meta["citeAs"]
        self.assertIn("eprint = {2604.27819}", named_cite)
        self.assertIn("archivePrefix = {arXiv}", named_cite)
        self.assertIn("Li, Haonan", named_cite)

    def test_named_citation_matches_openreview_bibtex(self) -> None:
        # Venue and url follow the OpenReview-issued BibTeX for the accepted
        # paper; the HF README citation must say the same thing.
        croissant_cite = CRO.build_metadata(CRO.RELEASE_IDENTITIES["named"])["citeAs"]
        readme_cite = PREP.STAGING_VARIANTS["named"]["citation"]
        for cite in (croissant_cite, readme_cite):
            self.assertIn("openreview.net/forum?id=9mPzIg8uil", cite)
            self.assertIn("Systems Evaluations and Datasets Track", cite)

    def test_croissant_declares_hard_negative_ci_file(self) -> None:
        meta = CRO.build_metadata(CRO.RELEASE_IDENTITIES["named"])
        distribution = {obj["contentUrl"] for obj in meta["distribution"]}
        self.assertIn("meta/hard_negative_ci.json", distribution)
        self.assertIn("meta/paired_live_guard_analysis.json", distribution)
        self.assertIn("meta/live_guard_deepseek_v4_flash_paired.json", distribution)

    def test_croissant_requires_complete_camera_ready_payload(self) -> None:
        meta = CRO.build_metadata(CRO.RELEASE_IDENTITIES["named"])
        names = {obj["contentUrl"] for obj in meta["distribution"]}
        self.assertTrue({f"mitigation/{name}.json" for name in DL.MITIGATION_DIRS} <= names)
        self.assertIn("meta/guarded_run_provenance.json", names)
        self.assertIn("meta/mitigation_results.json", names)
        self.assertIn("README.md", names)

    def test_dataset_card_documents_recompute_then_stage_flow(self) -> None:
        card = PREP.DATASET_CARD
        self.assertIn("writing to `results/hard_negative_analysis/`", card)
        self.assertIn("`results/live_guard_replication/`", card)
        self.assertIn("copies those\noutputs into `meta/`", card)

    def test_required_paired_meta_stays_fail_closed(self) -> None:
        self.assertEqual(
            set(PREP.PAIRED_META),
            {
                "results/live_guard_replication/guarded_run_provenance.json",
                "results/live_guard_replication/paired_live_guard_analysis.json",
                "results/mitigation_analysis/live_guard_deepseek_v4_flash_paired.json",
                "results/hard_negative_analysis/hard_negative_ci.json",
            },
        )


if __name__ == "__main__":
    unittest.main()
