"""The artifacts the adapter actually drives, and why they are ASTRA's and not ours.

T9's call, 12:19: drive from ASTRA's 74 materialised directories as the
artifacts of record. They are what he delivered, `delivery_validation.json`
counts 1,158 artifact hashes over them, and `profile_steps` is a contract he
froze. The materialiser shipped beside them is older than the run that produced
them and no longer emits `profile_steps` at all, so regenerating would quietly
replace a frozen contract with a lesser one.

Read only. Nothing here writes into the review directory.
"""
import json
import pathlib
import shutil
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import runner                                              # noqa: E402
from gen2 import artifacts                                 # noqa: E402


def _g2_13_first():
    for entry in runner.load_manifest()["scenarios"]:
        if entry["id"] == "G2-13":
            return entry, runner.scenario_of(entry)["variants"][0]
    raise AssertionError("G2-13 is not in the manifest")


@pytest.fixture
def copied(tmp_path):
    """A writable copy of one delivered directory, so drift can be simulated."""
    entry, variant = _g2_13_first()
    source = artifacts.MATERIALISED / f"{entry['id']}.{variant['name']}"
    dest = tmp_path / "materialized" / f"{entry['id']}.{variant['name']}"
    shutil.copytree(source, dest)
    return entry, variant, tmp_path / "materialized"


def test_the_record_gives_back_the_frozen_schedule_and_the_payload():
    entry, variant = _g2_13_first()

    record = artifacts.of_record(entry, variant)

    assert record.schedule["profile_steps"], (
        "profile_steps is the reason we read ASTRA's copy rather than rebuilding")
    assert [step["op"] for step in record.schedule["profile_steps"]] == \
        variant["schedule_operations"]
    assert record.payload, "the payload bytes did not come back"
    assert record.path.is_dir()
    assert record.digest


def test_an_artifact_whose_bytes_moved_is_refused(copied):
    """Someone edited a delivered fixture. The grid must not run on it."""
    entry, variant, root = copied
    target = root / f"{entry['id']}.{variant['name']}" / variant["requests"]
    target.write_bytes(target.read_bytes() + b"\n")

    with pytest.raises(artifacts.ArtifactsNotAsDelivered) as exc:
        artifacts.of_record(entry, variant, materialised=root)
    assert variant["requests"] in str(exc.value), str(exc.value)


def test_a_file_the_record_does_not_list_is_refused(copied):
    """An ADDED file is the case a hash sweep alone cannot see.

    Every listed artifact still matches; the directory simply contains one more
    thing than ASTRA recorded, and whatever reads the directory rather than the
    list would pick it up.
    """
    entry, variant, root = copied
    (root / f"{entry['id']}.{variant['name']}" / "extra.jsonl").write_bytes(b"{}\n")

    with pytest.raises(artifacts.ArtifactsNotAsDelivered) as exc:
        artifacts.of_record(entry, variant, materialised=root)
    assert "extra.jsonl" in str(exc.value), str(exc.value)


def test_a_record_built_from_a_different_payload_is_refused(copied):
    """The seed and the artifacts have to be talking about the same stimulus.

    `materialization.json` records the payload_source it built from. If that has
    drifted from the `payload_ref` in the package's scenario.json, the artifacts
    carry one stimulus and every expectation was written against another.
    """
    entry, variant, root = copied
    record_file = root / f"{entry['id']}.{variant['name']}" / "materialization.json"
    body = json.loads(record_file.read_text())
    body["payload_source"]["sha256"] = "0" * 64
    record_file.write_text(json.dumps(body, indent=2))

    with pytest.raises(artifacts.ArtifactsNotAsDelivered) as exc:
        artifacts.of_record(entry, variant, materialised=root)
    assert "payload" in str(exc.value).lower(), str(exc.value)


def test_every_second_generation_variant_verifies_as_delivered():
    """All 74, today, against what ASTRA recorded for each of them."""
    checked = 0
    for entry in runner.load_manifest()["scenarios"]:
        for variant in runner.scenario_of(entry)["variants"]:
            if "routes" not in variant:
                continue
            record = artifacts.of_record(entry, variant)
            assert record.schedule["variant"] == variant["name"]
            checked += 1

    assert checked == 74, f"expected 74 second generation variants, saw {checked}"
