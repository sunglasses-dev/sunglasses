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

    # The wheel must be reproducible from the tagged commit: the Build step
    # exports SOURCE_DATE_EPOCH, taken from that commit, before it builds.
    build = jobs.get("build") or {}
    run = next((s.get("run", "") for s in build.get("steps") or []
                if (s or {}).get("name") == "Build"), None)
    if run is None:
        problems.append("build job has no step named Build")
    else:
        export = re.search(r"^\s*export SOURCE_DATE_EPOCH\b", run, re.M)
        assign = re.search(r"SOURCE_DATE_EPOCH=.*git log -1 --format=%ct", run)
        built = re.search(r"-m build\b", run)
        if not (export and assign):
            problems.append("Build does not export SOURCE_DATE_EPOCH from the tagged commit time")
        elif not built or built.start() < export.start():
            problems.append("Build runs the build before it exports SOURCE_DATE_EPOCH")
        # The sdist ignores SOURCE_DATE_EPOCH, so it is repacked after the build, and the
        # wheel's sha256 is taken before and checked after to prove the repack left it alone.
        repack = re.search(r"scripts/repack_sdist\.sh", run)
        if not repack:
            problems.append("Build does not repack the sdist with scripts/repack_sdist.sh")
        elif built and repack.start() < built.start():
            problems.append("Build repacks the sdist before it builds it")
        else:
            record = re.search(r"sha256sum (?!-c)", run)
            verify = re.search(r"sha256sum -c", run)
            if not (record and record.start() < repack.start()):
                problems.append("Build does not record the wheel sha256 before the repack")
            if not (verify and verify.start() > repack.start()):
                problems.append("Build does not check the wheel sha256 after the repack")
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


# ── reproducible wheel: SOURCE_DATE_EPOCH ────────────────────────────────

def _build_run(doc):
    return next(s for s in doc["jobs"]["build"]["steps"] if s.get("name") == "Build")


def test_the_build_step_pins_the_wheel_timestamp_to_the_tagged_commit():
    run = _build_run(load())["run"]
    assert "SOURCE_DATE_EPOCH=\"$(git log -1 --format=%ct)\"" in run
    assert run.index("export SOURCE_DATE_EPOCH") < run.index("-m build")


def test_the_checker_catches_a_build_without_source_date_epoch():
    doc = load()
    step = _build_run(doc)
    step["run"] = "\n".join(l for l in step["run"].splitlines() if "SOURCE_DATE_EPOCH" not in l)
    assert any("SOURCE_DATE_EPOCH" in p for p in check_release(doc))


def test_the_checker_catches_the_export_after_the_build():
    doc = load()
    step = _build_run(doc)
    lines = step["run"].splitlines()
    kept = [l for l in lines if "export SOURCE_DATE_EPOCH" not in l]
    step["run"] = "\n".join(kept + ["export SOURCE_DATE_EPOCH"])
    assert any("before it exports" in p for p in check_release(doc))


def test_the_checker_catches_a_missing_build_step():
    doc = load()
    _build_run(doc)["name"] = "Compile"
    assert any("no step named Build" in p for p in check_release(doc))



# ── reproducible sdist: the repack after the build ───────────────────────
# setuptools ignores SOURCE_DATE_EPOCH for the sdist, so the Build step repacks it
# with scripts/repack_sdist.sh, and proves the wheel did not move while doing it.

def test_the_build_step_repacks_the_sdist_after_the_build():
    run = _build_run(load())["run"]
    assert "scripts/repack_sdist.sh" in run
    assert run.index("-m build") < run.index("scripts/repack_sdist.sh")


def test_the_build_step_proves_the_wheel_is_unchanged_by_the_repack():
    run = _build_run(load())["run"]
    assert run.index("sha256sum") < run.index("scripts/repack_sdist.sh") < run.index("sha256sum -c")


def test_the_checker_catches_a_build_without_the_repack():
    doc = load()
    step = _build_run(doc)
    step["run"] = "\n".join(l for l in step["run"].splitlines() if "repack_sdist" not in l)
    assert any("repack" in p for p in check_release(doc))


def test_the_checker_catches_the_repack_before_the_build():
    doc = load()
    step = _build_run(doc)
    lines = step["run"].splitlines()
    rep = [l for l in lines if "repack_sdist" in l]
    rest = [l for l in lines if "repack_sdist" not in l]
    step["run"] = "\n".join(rep + rest)
    assert any("repack" in p and "before" in p for p in check_release(doc))


def test_the_checker_catches_a_repack_with_no_wheel_check():
    doc = load()
    step = _build_run(doc)
    step["run"] = "\n".join(l for l in step["run"].splitlines() if "sha256sum" not in l)
    assert any("wheel" in p and "sha256" in p for p in check_release(doc))


def test_the_checker_catches_a_wheel_check_that_runs_before_the_repack():
    doc = load()
    step = _build_run(doc)
    lines = step["run"].splitlines()
    kept = [l for l in lines if "sha256sum -c" not in l]
    chk = [l for l in lines if "sha256sum -c" in l]
    i = next(i for i, l in enumerate(kept) if "repack_sdist" in l)
    step["run"] = "\n".join(kept[:i] + chk + kept[i:])
    assert any("wheel" in p and "after" in p for p in check_release(doc))
