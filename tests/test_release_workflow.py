"""Guards for release.yml, in the shape test_ci_gate.py already uses.

The workflow is loaded as YAML and checked SEMANTICALLY, and `check_release()`
returns a list of problems so the same checker can be run against mutated
documents. Every rule below has a negative control that must trip it, because a
guard nobody has seen fail is a guard that has never been tested.

The rule this file was written for: THE ATTACH JOB MUST NOT DEPEND ON THE
PUBLISH JOB.

`release-assets` uploads the SBOM and SHA256SUMS to the GitHub Release. Those
describe the BUILT artifacts and have nothing to do with PyPI. With
`needs: [pypi, sbom]`, a publish that fails or is skipped, which is exactly
what happens when a version is already on PyPI, takes the evidence down with
it: the tag gets a Release with no SBOM and no checksums, and the one thing
anybody would use to verify the release is missing because an unrelated step
did not run. The provenance of a build must not be contingent on its
distribution.
"""
from __future__ import annotations

import copy
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WF = ROOT / ".github" / "workflows" / "release.yml"

ATTACH = "release-assets"
PUBLISH = "pypi"
PINNED = re.compile(r"^[^@]+@[0-9a-f]{40}$")


def load():
    return yaml.safe_load(WF.read_text())


def check_release(doc):
    """Every problem found, as strings. Empty means the workflow is sound."""
    problems = []
    jobs = (doc or {}).get("jobs") or {}

    attach = jobs.get(ATTACH)
    if not isinstance(attach, dict):
        return [f"{ATTACH} job is missing"]

    needs = attach.get("needs") or []
    needs = [needs] if isinstance(needs, str) else list(needs)
    if PUBLISH in needs:
        problems.append(
            f"{ATTACH} depends on {PUBLISH}: a failed or skipped publish would "
            f"leave the Release with no SBOM and no checksums")
    for required in ("build", "sbom"):
        if required not in needs:
            problems.append(f"{ATTACH} must need {required}")

    # Every action pinned to a full commit sha. A moving tag is a third party
    # deciding what runs inside a job that holds contents:write.
    for name, job in jobs.items():
        for step in (job or {}).get("steps") or []:
            uses = (step or {}).get("uses")
            if uses and not PINNED.match(uses):
                problems.append(f"{name} uses an unpinned action: {uses}")
    return problems


# ── the workflow as it stands ────────────────────────────────────────────

def test_the_release_workflow_has_no_problems():
    assert check_release(load()) == []


def test_the_attach_job_does_not_need_the_publish_job():
    """Stated on its own as well as inside the checker, because this is the
    rule the file exists for and it should fail by name."""
    attach = load()["jobs"][ATTACH]
    needs = attach["needs"]
    assert PUBLISH not in needs
    assert set(needs) >= {"build", "sbom"}


def test_the_publish_job_still_gates_on_what_it_should():
    """The positive control. Loosening the attach job must not loosen the
    thing that actually uploads to PyPI."""
    needs = load()["jobs"][PUBLISH]["needs"]
    assert set(needs) >= {"build", "sbom", "provenance"}


# ── negative controls: every rule has to be reachable ────────────────────

def test_the_checker_catches_an_attach_job_that_needs_publish():
    doc = load()
    doc["jobs"][ATTACH]["needs"] = [PUBLISH, "sbom"]
    problems = check_release(doc)
    assert any(PUBLISH in p and ATTACH in p for p in problems)


def test_the_checker_catches_a_missing_build_dependency():
    doc = load()
    doc["jobs"][ATTACH]["needs"] = ["sbom"]
    assert any("must need build" in p for p in check_release(doc))


def test_the_checker_catches_an_unpinned_action():
    doc = load()
    doc["jobs"][ATTACH]["steps"][0]["uses"] = "actions/download-artifact@v8"
    assert any("unpinned" in p for p in check_release(doc))


def test_the_checker_catches_a_missing_attach_job():
    doc = load()
    del doc["jobs"][ATTACH]
    assert check_release(doc) == [f"{ATTACH} job is missing"]


def test_the_unmutated_document_is_the_control_for_all_of_them():
    """Without this, every negative control above passes against a checker
    that reports a problem for any input at all."""
    assert check_release(copy.deepcopy(load())) == []
