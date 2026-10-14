"""Release inventory checks use synthetic bytes and run without downloaded data."""
import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import generate_croissant_metadata as cro
import verify_release_consistency as verify


@pytest.fixture
def payload(tmp_path):
    names = ["README.md", "main/a.json", "mitigation/b.json",
             "live_guard_defense/c.json", "browser_replication/d.json",
             "meta/results.json"]
    for name in names:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"traces": [{}]}) if path.suffix == ".json"
                        else "Prepared for publication", encoding="utf-8")
    meta = {"description": "template", "distribution": [
        {"@id": "main_a", "@type": "cr:FileObject",
         "contentUrl": "main/a.json", "name": "main/a.json"}]}
    return tmp_path, cro.finalize_metadata(meta, tmp_path)


def test_finalized_metadata_covers_all_payload_bytes(payload):
    root, meta = payload
    assert len(meta["distribution"]) == 6
    for obj in meta["distribution"]:
        assert obj["sha256"] == hashlib.sha256((root / obj["contentUrl"]).read_bytes()).hexdigest()
    assert "Planned total: 4 traces" in meta["description"]
    assert meta["creativeWorkStatus"].startswith("Prepared")
    (root / "croissant.json").write_text(json.dumps(meta), encoding="utf-8")
    cro.validate_payload(meta, root)


@pytest.mark.parametrize("mutation", ["remove_file", "extra_file", "missing_hash",
                                     "wrong_hash", "changed_bytes", "duplicate",
                                     "escape_path", "empty_distribution"])
def test_rejects_broken_inventory(payload, mutation):
    root, original = payload
    meta = copy.deepcopy(original)
    if mutation == "remove_file":
        (root / "main/a.json").unlink()
    elif mutation == "extra_file":
        (root / "unlisted.json").write_text("{}", encoding="utf-8")
    elif mutation == "missing_hash":
        meta["distribution"][0].pop("sha256")
    elif mutation == "wrong_hash":
        meta["distribution"][0]["sha256"] = "0" * 64
    elif mutation == "changed_bytes":
        with (root / "main/a.json").open("ab") as fh:
            fh.write(b" ")
    elif mutation == "duplicate":
        meta["distribution"].append(copy.deepcopy(meta["distribution"][0]))
    elif mutation == "escape_path":
        meta["distribution"][0]["contentUrl"] = "../outside.json"
    else:
        meta["distribution"] = []
    with pytest.raises(ValueError):
        cro.validate_payload(meta, root)


def test_consistency_verifier_reports_undeclared_file(payload):
    root, meta = payload
    (root / "croissant.json").write_text(json.dumps(meta), encoding="utf-8")
    (root / "new.json").write_text("{}", encoding="utf-8")
    result = verify.CheckResult()
    verify._check_declared_files_present(result, root, "test bundle")
    assert any("undeclared payload" in e for e in result.errors)


def test_regeneration_is_deterministic_and_croissant_has_no_self_hash(payload):
    root, meta = payload
    (root / "croissant.json").write_text(json.dumps(meta), encoding="utf-8")
    rebuilt = cro.finalize_metadata(copy.deepcopy(meta), root)
    assert rebuilt == meta
    assert all(e["contentUrl"] != "croissant.json" for e in meta["distribution"])


def test_required_file_missing_aborts_generation(tmp_path):
    (tmp_path / "README.md").write_text("card", encoding="utf-8")
    meta = {"description": "", "distribution": [{"contentUrl": "main/missing.json"}]}
    with pytest.raises(ValueError, match="required release files missing"):
        cro.finalize_metadata(meta, tmp_path)
