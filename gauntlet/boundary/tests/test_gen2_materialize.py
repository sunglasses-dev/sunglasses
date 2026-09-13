"""Materialising a second generation variant, and the two copies underneath it.

The sixteen new seeds cannot materialise as delivered. Each `run.py` executes
`parents[2]/materialize_specs.py`, which resolves to the warroom root, and the
materialiser is not there: it lives in ASTRA's review directory and builds from
its OWN `fixtures/` copy of the seeds rather than from the installed package.

So there are two copies of every new seed, the loader reads one and the
materialiser reads the other, and nothing checks they still agree. They are
byte identical today. The point of the check is the day they are not: a run
would report on a scenario the harness never read, which is indistinguishable
from a candidate defect at every layer above it.
"""
import hashlib
import json
import pathlib
import shutil
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import runner                                              # noqa: E402
from gen2 import materialize                               # noqa: E402


def _two_copies(tmp_path, package_body: bytes, review_body: bytes):
    package = tmp_path / "package"
    review = tmp_path / "review" / "fixtures"
    (package / "13_g3_result_fields").mkdir(parents=True)
    (review / "13_g3_result_fields").mkdir(parents=True)
    (package / "13_g3_result_fields" / "scenario.json").write_bytes(package_body)
    (review / "13_g3_result_fields" / "scenario.json").write_bytes(review_body)
    return package, review


def test_copies_that_agree_return_a_digest_that_follows_the_content(tmp_path):
    """A digest OVER the seed, not a re-hash of one file.

    Asserted as behaviour rather than as an algorithm: identical copies give a
    stable answer, and a seed whose content moved gives a different one. Pinning
    the exact construction would make this a test of how it is computed.
    """
    package, review = _two_copies(tmp_path, b'{"id": "G2-13"}\n', b'{"id": "G2-13"}\n')
    first = materialize.assert_same_seed(
        "13_g3_result_fields", package=package, review=review)
    assert first == materialize.assert_same_seed(
        "13_g3_result_fields", package=package, review=review)

    moved = tmp_path / "moved"
    package2, review2 = _two_copies(moved, b'{"id": "G2-14"}\n', b'{"id": "G2-14"}\n')
    assert materialize.assert_same_seed(
        "13_g3_result_fields", package=package2, review=review2) != first


def test_copies_that_have_diverged_are_refused(tmp_path):
    """The failure this exists for.

    Without it the materialiser builds from the review copy while every
    expectation is read from the package copy, and the mismatch surfaces as a
    candidate that failed a scenario nobody ran.
    """
    package, review = _two_copies(
        tmp_path, b'{"id": "G2-13", "variants": 8}\n', b'{"id": "G2-13", "variants": 7}\n')

    with pytest.raises(materialize.SeedCopiesDiverged) as exc:
        materialize.assert_same_seed(
            "13_g3_result_fields", package=package, review=review)

    message = str(exc.value)
    assert "13_g3_result_fields" in message, message
    assert "package" in message and "review" in message, message


def test_a_seed_whose_EXPECTATION_diverged_is_refused(tmp_path):
    """scenario.json is not the only file that decides the answer.

    The schedule's `assert_five_layers` step points at the REVIEW copy's
    expected.json while the harness grades against the package's. Two
    expectations that disagree produce a verdict about a contract nobody wrote,
    so the invariant covers every file in the seed directory, not just the one
    the loader happens to read.
    """
    body = b'{"id": "G2-13"}\n'
    package, review = _two_copies(tmp_path, body, body)
    (package / "13_g3_result_fields" / "expected.json").write_bytes(b'{"finding": "yes"}\n')
    (review / "13_g3_result_fields" / "expected.json").write_bytes(b'{"finding": "no"}\n')

    with pytest.raises(materialize.SeedCopiesDiverged) as exc:
        materialize.assert_same_seed(
            "13_g3_result_fields", package=package, review=review)
    assert "expected.json" in str(exc.value), str(exc.value)


def test_a_seed_the_materialiser_cannot_see_is_refused(tmp_path):
    body = b'{"id": "G2-13"}\n'
    package, review = _two_copies(tmp_path, body, body)
    shutil.rmtree(review / "13_g3_result_fields")

    with pytest.raises(materialize.SeedCopiesDiverged):
        materialize.assert_same_seed(
            "13_g3_result_fields", package=package, review=review)


def test_every_second_generation_seed_agrees_across_the_two_copies():
    """The real package against the real review directory, today.

    The twelve first generation seeds are deliberately not in the review copy.
    They came from the original delivery and are materialised by their own
    `fixture.py`, so asking the review directory for them would assert the new
    shape over the old one.
    """
    checked = 0
    for entry in runner.load_manifest()["scenarios"]:
        variants = runner.scenario_of(entry)["variants"]
        if not any("routes" in v for v in variants):
            continue
        materialize.assert_same_seed(entry["directory"])
        checked += 1

    assert checked == 16, f"expected the 16 second generation seeds, saw {checked}"


# ── building the artifacts a variant names ─────────────────────────────────

import os                                                  # noqa: E402
import uuid                                                # noqa: E402


@pytest.fixture
def private_root():
    """ASTRA's materialiser refuses a root outside /private/tmp, by design.

    pytest's tmp_path is under /private/var on this machine, so a test that used
    it would be testing the refusal and not the build.
    """
    root = pathlib.Path("/private/tmp") / f"gen2-materialize-{uuid.uuid4().hex[:10]}"
    yield root
    shutil.rmtree(root, ignore_errors=True)


def _g2_13():
    for entry in runner.load_manifest()["scenarios"]:
        if entry["id"] == "G2-13":
            return entry, runner.scenario_of(entry)
    raise AssertionError("G2-13 is not in the manifest")


def test_materialising_writes_the_files_the_variant_names(private_root):
    entry, scenario = _g2_13()
    variant = scenario["variants"][0]

    built = materialize.materialize(entry, variant, run_root=private_root)

    for named in (variant["requests"], variant["upstream_output"],
                  variant["schedule_file"]):
        assert (private_root / named).is_file(), f"{named} was not written"
    assert built.schedule["scenario_id"] == "G2-13"
    assert built.schedule["variant"] == variant["name"]
    assert built.payload, "the resolved payload bytes did not come back"


def test_materialising_refuses_a_root_outside_the_private_tmp_tree(tmp_path):
    entry, scenario = _g2_13()

    with pytest.raises(materialize.UnsafeRunRoot):
        materialize.materialize(entry, scenario["variants"][0], run_root=tmp_path)


def test_materialising_checks_the_two_copies_first(private_root, monkeypatch):
    """READ THE CALL SITE, not just the function.

    `collect_drops` was correct, complete, and never called, and no test of the
    sink could catch that. A provenance check nothing invokes is the same bug
    wearing this lane's clothes.
    """
    called = []
    monkeypatch.setattr(materialize, "assert_same_seed",
                        lambda directory, **kw: called.append(directory) or "deadbeef")

    entry, scenario = _g2_13()
    materialize.materialize(entry, scenario["variants"][0], run_root=private_root)

    assert called == [entry["directory"]], called


def test_materialising_leaves_astras_evidence_exactly_as_it_found_it(private_root):
    """I broke this one for real before writing the test.

    ASTRA's materialiser rewrites `evidence/materialization_validation.json` in
    its own review directory on every single call. Eight test runs reduced a
    74 variant receipt to one entry naming a pytest temp directory. The file is
    ASTRA's record of THEIR materialisation and nothing about my runs belongs in
    it; my own receipts live in my run root.

    Driving 95 variants would have overwritten it 95 times.
    """
    evidence = (materialize.REVIEW_ROOT / "evidence"
                / "materialization_validation.json")
    before = evidence.read_bytes()

    entry, scenario = _g2_13()
    materialize.materialize(entry, scenario["variants"][0], run_root=private_root)

    assert evidence.read_bytes() == before, (
        "the materialiser rewrote ASTRA's receipt and it was not put back")
