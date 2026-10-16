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
    problems += check_postcondition(doc)
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


# ── the postcondition job: PyPI holds what the tag builds ────────────────
# After the upload, scripts/release_postcondition.sh compares what PyPI serves with a fresh
# build of the tag, by content. The job only reads: it never uploads again, yanks, or deletes.
# A failure turns the run red and that is all it does.

POST = "postcondition"
SCRIPT_NAME = "scripts/release_postcondition.sh"


def _post_steps(doc):
    return ((doc.get("jobs") or {}).get(POST) or {}).get("steps") or []


def _post_run(doc):
    return next((s.get("run", "") for s in _post_steps(doc) if SCRIPT_NAME in (s.get("run") or "")), None)


def check_postcondition(doc):
    problems = []
    jobs = (doc or {}).get("jobs") or {}
    job = jobs.get(POST)
    if not isinstance(job, dict):
        return [f"{POST} job is missing"]

    needs = job.get("needs") or []
    needs = [needs] if isinstance(needs, str) else list(needs)
    if PUBLISH not in needs:
        problems.append(f"{POST} must need {PUBLISH}: it checks what the upload left on PyPI")

    cond = str(job.get("if") or "")
    if re.search(r"always\(\)|failure\(\)|cancelled\(\)", cond):
        problems.append(f"{POST} runs after a failed publish: its `if` is `{cond}`")
    if job.get("continue-on-error") is True or any((s or {}).get("continue-on-error") is True for s in job.get("steps") or []):
        problems.append(f"{POST} can fail without turning the run red (continue-on-error)")

    for other in (ATTACH, PUBLISH, "build", "sbom", "provenance"):
        n = (jobs.get(other) or {}).get("needs") or []
        n = [n] if isinstance(n, str) else list(n)
        if POST in n:
            problems.append(f"{other} depends on {POST}: evidence and uploads must not be contingent on the check")

    run = _post_run(doc)
    if run is None:
        problems.append(f"{POST} never runs {SCRIPT_NAME}")
    else:
        if not re.search(r'release_postcondition\.sh\s+"\$VERSION"', run) or "GITHUB_REF_NAME#v" not in run:
            problems.append(f"{POST} does not pass the release version (the tag without its v) to the script")
        if not (re.search(r"\bwhile\b", run) and re.search(r"\bsleep\b", run)):
            problems.append(f"{POST} has no retry loop for PyPI propagation")
        m = re.search(r"POSTCONDITION_WAIT:-(\d+)", run)
        if not m or int(m.group(1)) != 300:
            problems.append(f"{POST} must wait at most 300 seconds for PyPI, found {m.group(1) if m else 'no limit'}")

    forbidden = (r"twine\s+upload", r"gh release (delete|edit)", r"gh api .*DELETE", r"\byank\b",
                 r"git push", r"git tag -d", r"pypa/gh-action-pypi-publish")
    for s in job.get("steps") or []:
        text = f"{(s or {}).get('run', '')} {(s or {}).get('uses', '')}"
        for pat in forbidden:
            if re.search(pat, text):
                problems.append(f"{POST} must only read, but a step matches `{pat}`")
    if (job.get("permissions") or {}).get("contents") not in ("read", None) or "id-token" in (job.get("permissions") or {}):
        problems.append(f"{POST} needs read access only")
    return problems


def _wf_post(doc=None):
    return doc if doc is not None else load()


def test_the_workflow_has_a_sound_postcondition_job():
    assert check_postcondition(load()) == []


def test_the_postcondition_job_needs_the_publish_job():
    assert PUBLISH in load()["jobs"][POST]["needs"]


def test_the_postcondition_job_is_in_check_release_too():
    """check_release() is the one checker the rest of the file calls, so it carries these rules."""
    doc = load()
    del doc["jobs"][POST]
    assert any(POST in p for p in check_release(doc))


def test_check_release_still_passes_the_whole_workflow():
    assert check_release(load()) == []


def test_the_attach_job_still_does_not_wait_for_the_postcondition():
    assert POST not in load()["jobs"][ATTACH]["needs"]


# negative controls, one per rule

def _mut(fn):
    doc = copy.deepcopy(load())
    fn(doc)
    return doc


def test_the_checker_catches_a_missing_postcondition_job():
    assert check_postcondition(_mut(lambda d: d["jobs"].pop(POST))) == [f"{POST} job is missing"]


def test_the_checker_catches_a_postcondition_that_does_not_need_publish():
    doc = _mut(lambda d: d["jobs"][POST].update(needs=["build"]))
    assert any("must need" in p for p in check_postcondition(doc))


def test_the_checker_catches_a_postcondition_that_runs_after_a_failed_publish():
    doc = _mut(lambda d: d["jobs"][POST].update({"if": "${{ always() }}"}))
    assert any("failed publish" in p for p in check_postcondition(doc))


def test_the_checker_catches_continue_on_error_on_the_job():
    doc = _mut(lambda d: d["jobs"][POST].update({"continue-on-error": True}))
    assert any("continue-on-error" in p for p in check_postcondition(doc))


def test_the_checker_catches_continue_on_error_on_the_step():
    def f(d):
        next(s for s in d["jobs"][POST]["steps"] if SCRIPT_NAME in (s.get("run") or ""))["continue-on-error"] = True
    assert any("continue-on-error" in p for p in check_postcondition(_mut(f)))


def test_the_checker_catches_the_attach_job_waiting_for_the_postcondition():
    doc = _mut(lambda d: d["jobs"][ATTACH].update(needs=["build", "sbom", POST]))
    assert any(f"{ATTACH} depends on {POST}" in p for p in check_postcondition(doc))


def test_the_checker_catches_a_postcondition_that_never_runs_the_script():
    def f(d):
        s = next(s for s in d["jobs"][POST]["steps"] if SCRIPT_NAME in (s.get("run") or ""))
        s["run"] = "echo checked"
    assert any("never runs" in p for p in check_postcondition(_mut(f)))


def test_the_checker_catches_a_postcondition_that_passes_no_version():
    def f(d):
        s = next(s for s in d["jobs"][POST]["steps"] if SCRIPT_NAME in (s.get("run") or ""))
        s["run"] = s["run"].replace('release_postcondition.sh "$VERSION"', "release_postcondition.sh")
    assert any("does not pass the release version" in p for p in check_postcondition(_mut(f)))


def test_the_checker_catches_a_postcondition_without_a_retry_loop():
    def f(d):
        s = next(s for s in d["jobs"][POST]["steps"] if SCRIPT_NAME in (s.get("run") or ""))
        s["run"] = "VERSION=\"${GITHUB_REF_NAME#v}\"\nbash scripts/release_postcondition.sh \"$VERSION\"\n"
    assert any("no retry loop" in p for p in check_postcondition(_mut(f)))


def test_the_checker_catches_a_wait_longer_than_five_minutes():
    def f(d):
        s = next(s for s in d["jobs"][POST]["steps"] if SCRIPT_NAME in (s.get("run") or ""))
        s["run"] = s["run"].replace("POSTCONDITION_WAIT:-300", "POSTCONDITION_WAIT:-900")
    assert any("at most 300" in p for p in check_postcondition(_mut(f)))


@pytest.mark.parametrize("line", [
    "twine upload dist/*", "gh release delete v1.2.3 -y", "pip install yank && yank sunglasses",
    "git push origin :refs/tags/v1.2.3", "git tag -d v1.2.3",
])
def test_the_checker_catches_a_step_that_writes_back(line):
    def f(d):
        d["jobs"][POST]["steps"].append({"name": "undo", "run": line})
    assert any("must only read" in p for p in check_postcondition(_mut(f))), line


def test_the_checker_catches_the_publish_action_inside_the_postcondition():
    def f(d):
        d["jobs"][POST]["steps"].append({"uses": "pypa/gh-action-pypi-publish@" + "a" * 40})
    assert any("must only read" in p for p in check_postcondition(_mut(f)))


def test_the_checker_catches_write_permissions():
    doc = _mut(lambda d: d["jobs"][POST].update(permissions={"contents": "write"}))
    assert any("read access only" in p for p in check_postcondition(doc))


def test_the_postcondition_job_uses_only_pinned_actions():
    uses = [s["uses"] for s in load()["jobs"][POST]["steps"] if s.get("uses")]
    assert uses and all(PINNED.match(u) for u in uses), uses


# the retry loop, executed: the step's own run block against a stub of the script

def _run_block():
    return _post_run(load())


def _run_loop(tmp_path, codes, wait="2", pause="1"):
    """Run the step's script with a stub release_postcondition.sh that exits with each of
    `codes` in turn (the last one repeats). Returns (rc, attempts, args seen)."""
    (tmp_path / "scripts").mkdir(exist_ok=True)
    counter, args = tmp_path / "n", tmp_path / "args"
    counter.write_text("0")
    stub = tmp_path / "scripts" / "release_postcondition.sh"
    stub.write_text(
        '#!/usr/bin/env bash\n'
        f'n=$(cat "{counter}"); n=$((n+1)); echo $n > "{counter}"\n'
        f'echo "$@" >> "{args}"\n'
        f'codes=({" ".join(str(c) for c in codes)})\n'
        'i=$((n-1)); [ "$i" -lt "${#codes[@]}" ] || i=$((${#codes[@]}-1))\n'
        'exit "${codes[$i]}"\n')
    env = {"PATH": __import__("os").environ["PATH"], "GITHUB_REF_NAME": "v1.2.3",
           "POSTCONDITION_WAIT": wait, "POSTCONDITION_PAUSE": pause}
    import subprocess
    r = subprocess.run(["bash", "-e", "-c", _run_block()], cwd=tmp_path, env=env,
                       capture_output=True, text=True, timeout=60)
    return r, int(counter.read_text()), args.read_text().split() if args.exists() else []


def test_the_loop_passes_on_the_first_success(tmp_path):
    r, n, args = _run_loop(tmp_path, [0])
    assert r.returncode == 0 and n == 1, (r.stdout, r.stderr)
    assert args == ["1.2.3"], "the script gets the version without the v"


def test_the_loop_fails_at_once_on_a_content_difference(tmp_path):
    r, n, _ = _run_loop(tmp_path, [1])
    assert r.returncode != 0 and n == 1, (n, r.stdout, r.stderr)


def test_the_loop_retries_while_the_script_cannot_measure_then_passes(tmp_path):
    r, n, _ = _run_loop(tmp_path, [2, 2, 0], wait="30", pause="1")
    assert r.returncode == 0 and n == 3, (n, r.stdout, r.stderr)


def test_the_loop_gives_up_with_a_failure_when_pypi_never_answers(tmp_path):
    r, n, _ = _run_loop(tmp_path, [2], wait="2", pause="1")
    assert r.returncode != 0, (r.stdout, r.stderr)
    assert 2 <= n <= 4, f"{n} attempts for a 2 second budget"


def test_the_loop_stops_retrying_when_a_retry_turns_into_a_content_difference(tmp_path):
    r, n, _ = _run_loop(tmp_path, [2, 1, 0], wait="30", pause="1")
    assert r.returncode != 0 and n == 2, (n, r.stdout, r.stderr)
