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
    problems += check_stats(doc)
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


# ── the stats job: the one pull request an upload from this workflow owes ─
# A workflow upload never writes stats/current.json `last_updated`, so the stats job runs
# scripts/stats_last_updated.py after the upload and opens a pull request with the two-line
# fix. It may push ONE new branch and open ONE pull request. It never merges, never pushes to
# main, never forces, and nothing waits for it. The JOB carries continue-on-error so a stats
# problem cannot turn the release run red (the release chain reads the run's conclusion and
# would read a good upload as a failed release); no STEP may carry it, so the job itself still
# fails visibly with an ::error:: annotation.

STATS = "stats"
STATS_SCRIPT = "scripts/stats_last_updated.py"
STATS_FORBIDDEN = (r"gh pr merge", r"--admin", r"--force", r"--force-with-lease", r"git push\s+(-\w+\s+)*\S+\s+\+",
                   r"git push[^\n]*\b(main|HEAD:main|refs/heads/main)\b", r"twine\s+upload",
                   r"gh release", r"pypa/gh-action-pypi-publish", r"git tag", r"\byank\b",
                   r"claude|anthropic|co-authored|generated with")


def _stats_steps(doc):
    return ((doc.get("jobs") or {}).get(STATS) or {}).get("steps") or []


def _stats_run(doc, needle):
    return next((s.get("run", "") for s in _stats_steps(doc) if needle in (s.get("run") or "")), None)


def check_stats(doc):
    problems = []
    jobs = (doc or {}).get("jobs") or {}
    job = jobs.get(STATS)
    if not isinstance(job, dict):
        return [f"{STATS} job is missing"]

    needs = job.get("needs") or []
    needs = [needs] if isinstance(needs, str) else list(needs)
    if PUBLISH not in needs:
        problems.append(f"{STATS} must need {PUBLISH}: it stamps the time PyPI recorded for the upload")
    cond = str(job.get("if") or "")
    if re.search(r"always\(\)|failure\(\)|cancelled\(\)", cond):
        problems.append(f"{STATS} runs after a failed publish: its `if` is `{cond}`")
    if job.get("continue-on-error") is not True:
        problems.append(f"{STATS} must set continue-on-error: true on the job, or a stats failure turns a good release run red")
    if any((s or {}).get("continue-on-error") is True for s in job.get("steps") or []):
        problems.append(f"{STATS} has a step with continue-on-error: the job must fail visibly, not hide the failure inside a green job")

    for other, spec in jobs.items():
        n = (spec or {}).get("needs") or []
        n = [n] if isinstance(n, str) else list(n)
        if STATS in n:
            problems.append(f"{other} depends on {STATS}: the upload and the evidence must not wait for a stats pull request")

    # The write permissions belong to this job and release-assets, nowhere else.
    perms = job.get("permissions") or {}
    if perms.get("contents") != "write" or perms.get("pull-requests") != "write":
        problems.append(f"{STATS} needs contents: write and pull-requests: write, and nothing else wider")
    if set(perms) - {"contents", "pull-requests"}:
        problems.append(f"{STATS} asks for more than contents and pull-requests: {sorted(set(perms) - {'contents', 'pull-requests'})}")
    if (doc.get("permissions") or "read-all") != "read-all":
        problems.append("the workflow-level permissions must stay read-all")
    for other, spec in jobs.items():
        p = (spec or {}).get("permissions") or {}
        if other != STATS and p.get("pull-requests") == "write":
            problems.append(f"{other} has pull-requests: write, which only {STATS} needs")
        if other not in (STATS, ATTACH) and p.get("contents") == "write":
            problems.append(f"{other} has contents: write, which only {STATS} and {ATTACH} need")

    checkout = next((s for s in job.get("steps") or [] if "actions/checkout@" in str((s or {}).get("uses", ""))), None)
    if not checkout or (checkout.get("with") or {}).get("ref") != "main":
        problems.append(f"{STATS} must check out main, so the pull request holds only the stats change")

    stamp = _stats_run(doc, STATS_SCRIPT)
    if stamp is None:
        problems.append(f"{STATS} never runs {STATS_SCRIPT}")
    else:
        if not re.search(r'stats_last_updated\.py\s+"\$VERSION"', stamp) or "GITHUB_REF_NAME#v" not in stamp:
            problems.append(f"{STATS} does not pass the release version (the tag without its v) to the script")
        if not re.search(r"\b3\)", stamp) or "changed=false" not in stamp:
            problems.append(f"{STATS} does not treat exit 3 (already stamped) as nothing to do")
        if not re.search(r"\*\)[^\n]*exit 1", stamp):
            problems.append(f"{STATS} does not fail on a refusal from the script")
        if not re.search(r"\*\)[^\n]*::error::", stamp):
            problems.append(f"{STATS} does not annotate a refusal from the script with ::error::")

    pr = _stats_run(doc, "gh pr create")
    if pr is None:
        problems.append(f"{STATS} never opens a pull request")
    else:
        if 'BRANCH="stats/' not in pr or 'HEAD:refs/heads/$BRANCH' not in pr:
            problems.append(f"{STATS} must push only to its own stats/<version>-last-updated branch")
        if "ls-remote" not in pr:
            problems.append(f"{STATS} does not check whether the branch already exists before pushing")
        if "--base main" not in pr:
            problems.append(f"{STATS} must open the pull request against main")
        if not re.search(r"::error::[^\n]*unexpected change", pr):
            problems.append(f"{STATS} does not annotate an unexpected change with ::error::")
        if "git diff --name-only" not in pr or "HEAD:stats/current.json" not in pr or "rest(old) != rest(new)" not in pr:
            problems.append(f"{STATS} does not confine the change to the top-level last_updated fields of stats/current.json")
        if "263686995+azrollin@users.noreply.github.com" not in pr:
            problems.append(f"{STATS} commits under the wrong identity")

    for s in job.get("steps") or []:
        text = f"{(s or {}).get('run', '')} {(s or {}).get('uses', '')}"
        for pat in STATS_FORBIDDEN:
            if re.search(pat, text, re.I):
                problems.append(f"{STATS} must only open a pull request, but a step matches `{pat}`")
    return problems


def test_the_workflow_has_a_sound_stats_job():
    assert check_stats(load()) == []


def test_the_stats_job_comes_after_the_upload_and_nothing_waits_for_it():
    jobs = load()["jobs"]
    assert jobs[STATS]["needs"] == PUBLISH
    assert not [j for j, spec in jobs.items() if STATS in ([spec.get("needs")] if isinstance(spec.get("needs"), str) else spec.get("needs") or [])]


def test_the_write_permissions_are_scoped_to_the_stats_job():
    doc = load()
    assert doc["permissions"] == "read-all"
    assert doc["jobs"][STATS]["permissions"] == {"contents": "write", "pull-requests": "write"}
    assert [j for j, s in doc["jobs"].items() if (s.get("permissions") or {}).get("pull-requests") == "write"] == [STATS]


def test_the_stats_job_cannot_turn_the_release_run_red():
    """The release chain reads the run's conclusion, so the job may not decide it."""
    doc = load()
    assert doc["jobs"][STATS]["continue-on-error"] is True
    assert not [s for s in doc["jobs"][STATS]["steps"] if "continue-on-error" in s]
    assert "continue-on-error" not in {k for j, spec in doc["jobs"].items() if j != STATS for k in spec}


def test_the_stats_job_uses_only_pinned_actions():
    uses = [s["uses"] for s in load()["jobs"][STATS]["steps"] if s.get("uses")]
    assert uses and all(PINNED.match(u) for u in uses), uses


def test_the_stats_job_is_in_check_release_too():
    doc = load()
    del doc["jobs"][STATS]
    assert any(STATS in p for p in check_release(doc))


def test_check_stats_negative_controls():
    def broken(fn):
        return check_stats(_mut(fn))

    assert broken(lambda d: d["jobs"].pop(STATS)) == [f"{STATS} job is missing"]
    assert any("must need" in p for p in broken(lambda d: d["jobs"][STATS].update(needs=["build"])))
    assert any("failed publish" in p for p in broken(lambda d: d["jobs"][STATS].update({"if": "always()"})))
    assert any("must set continue-on-error" in p for p in broken(lambda d: d["jobs"][STATS].pop("continue-on-error")))
    assert any("must set continue-on-error" in p for p in broken(lambda d: d["jobs"][STATS].update({"continue-on-error": False})))
    assert any("a step with continue-on-error" in p for p in broken(
        lambda d: d["jobs"][STATS]["steps"][2].update({"continue-on-error": True})))
    assert any("::error::" in p for p in broken(
        lambda d: [s.update(run=s["run"].replace("::error::", "")) for s in d["jobs"][STATS]["steps"] if STATS_SCRIPT in (s.get("run") or "")]))
    assert any("::error::" in p for p in broken(
        lambda d: [s.update(run=s["run"].replace("::error::REFUSED", "REFUSED")) for s in d["jobs"][STATS]["steps"] if "gh pr create" in (s.get("run") or "")]))
    assert any(f"{ATTACH} depends on {STATS}" in p for p in broken(
        lambda d: d["jobs"][ATTACH].update(needs=["build", "sbom", STATS])))
    assert any("asks for more" in p for p in broken(lambda d: d["jobs"][STATS]["permissions"].update({"id-token": "write"})))
    assert any("only stats needs" in p.replace(STATS, "stats") or "only" in p for p in broken(
        lambda d: d["jobs"][POST].update(permissions={"contents": "read", "pull-requests": "write"})))
    assert any("has contents: write" in p for p in broken(lambda d: d["jobs"]["build"].update(permissions={"contents": "write"})))
    assert any("read-all" in p for p in broken(lambda d: d.update(permissions="write-all")))
    assert any("must check out main" in p for p in broken(
        lambda d: d["jobs"][STATS]["steps"][0]["with"].update(ref="${{ github.sha }}")))
    assert any("never runs" in p for p in broken(
        lambda d: [s.update(run="echo") for s in d["jobs"][STATS]["steps"] if STATS_SCRIPT in (s.get("run") or "")]))
    assert any("exit 3" in p for p in broken(
        lambda d: [s.update(run=s["run"].replace("changed=false", "changed=true")) for s in d["jobs"][STATS]["steps"] if STATS_SCRIPT in (s.get("run") or "")]))
    assert any("does not fail on a refusal" in p for p in broken(
        lambda d: [s.update(run=s["run"].replace("exit 1", "exit 0")) for s in d["jobs"][STATS]["steps"] if STATS_SCRIPT in (s.get("run") or "")]))


@pytest.mark.parametrize("line", [
    "gh pr merge --squash --admin", "git push --force origin HEAD:refs/heads/stats/x", "git push origin HEAD:main",
    "git push origin +HEAD:refs/heads/stats/x", "gh release delete v1 -y", "git tag -d v1",
    "twine upload dist/*", "git commit -m 'x' -m 'Co-Authored-By: someone'",
])
def test_check_stats_catches_a_step_that_does_more_than_open_a_pull_request(line):
    def f(d):
        d["jobs"][STATS]["steps"].append({"name": "more", "run": line})
    assert any("must only open a pull request" in p for p in check_stats(_mut(f))), line


@pytest.mark.parametrize("old, new, needle", [
    ('HEAD:refs/heads/$BRANCH', 'HEAD:refs/heads/main', "own stats/"),
    ('ls-remote', 'rev-parse', "already exists"),
    ('--base main', '--base release', "against main"),
    ('git diff --name-only', 'git diff --stat', "confine the change"),
    ('rest(old) != rest(new)', 'rest(old) == rest(old)', "confine the change"),
    ('263686995+azrollin@users.noreply.github.com', 'ci@example.com', "identity"),
])
def test_check_stats_catches_a_weakened_pull_request_step(old, new, needle):
    def f(d):
        for s in d["jobs"][STATS]["steps"]:
            if "gh pr create" in (s.get("run") or ""):
                s["run"] = s["run"].replace(old, new)
    assert any(needle in p for p in check_stats(_mut(f))), (old, new)


# the stats job's own run blocks, executed: a bare origin, a shimmed gh, a stubbed script

import os
import subprocess
import textwrap


def _stats_env(tmp_path, script_rc, gh_rc=0):
    """A clone of a bare origin whose stats/current.json the stub script edits (or not)."""
    origin, repo, bin_dir = tmp_path / "origin.git", tmp_path / "repo", tmp_path / "bin"
    git = lambda *a, cwd=None: subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True, text=True).stdout
    git("init", "-q", "--bare", "-b", "main", str(origin))
    git("clone", "-q", str(origin), str(repo))
    (repo / "stats").mkdir()
    (repo / "scripts").mkdir()
    (repo / "stats" / "current.json").write_text('{\n  "version": "1.2.3",\n  "last_updated": "old",\n'
                                                 '  "last_updated_by": "old",\n  "released": "2026-10-19"\n}\n')
    (repo / "scripts" / "stats_last_updated.py").write_text(textwrap.dedent(f"""
        import pathlib, sys
        if {script_rc} == 0:
            p = pathlib.Path("stats/current.json")
            p.write_text(p.read_text().replace('"last_updated": "old"', '"last_updated": "new"')
                                      .replace('"last_updated_by": "old"', '"last_updated_by": "release.yml"'))
        print("stub script", sys.argv[1:])
        sys.exit({script_rc})
        """))
    git("-c", "user.name=t", "-c", "user.email=t@t", "add", "-A", cwd=repo)
    git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "base", cwd=repo)
    git("push", "-q", "origin", "HEAD:refs/heads/main", cwd=repo)
    bin_dir.mkdir()
    gh = bin_dir / "gh"
    gh.write_text(f'#!/usr/bin/env bash\necho "gh $@" >> "{tmp_path}/gh.log"\n[ {gh_rc} -eq 0 ] && echo https://example.test/pull/1\nexit {gh_rc}\n')
    gh.chmod(0o755)
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "GITHUB_REF_NAME": "v1.2.3", "GITHUB_REPOSITORY": "o/r",
           "GITHUB_SERVER_URL": "https://github.test", "GITHUB_OUTPUT": str(tmp_path / "out"),
           "STATS_WAIT": "0", "STATS_PAUSE": "0", "GIT_CONFIG_GLOBAL": "/dev/null"}
    (tmp_path / "out").write_text("")
    return repo, origin, env


def _run_step(repo, env, needle):
    return subprocess.run(["bash", "-e", "-c", _stats_run(load(), needle)], cwd=repo, env=env,
                          capture_output=True, text=True, timeout=60)


def _outputs(tmp_path):
    return (tmp_path / "out").read_text().split()


def test_the_stamp_step_reports_a_change(tmp_path):
    repo, _, env = _stats_env(tmp_path, 0)
    r = _run_step(repo, env, STATS_SCRIPT)
    assert r.returncode == 0 and _outputs(tmp_path) == ["changed=true"], (r.stdout, r.stderr)
    assert "['1.2.3', '--wait', '0', '--pause', '0']" in r.stdout


def test_the_stamp_step_treats_exit_3_as_nothing_to_do(tmp_path):
    repo, _, env = _stats_env(tmp_path, 3)
    r = _run_step(repo, env, STATS_SCRIPT)
    assert r.returncode == 0 and _outputs(tmp_path) == ["changed=false"], (r.stdout, r.stderr)


@pytest.mark.parametrize("rc", [1, 2, 64])
def test_the_stamp_step_goes_red_on_a_refusal(tmp_path, rc):
    repo, _, env = _stats_env(tmp_path, rc)
    r = _run_step(repo, env, STATS_SCRIPT)
    assert r.returncode == 1 and _outputs(tmp_path) == [], (r.stdout, r.stderr)
    assert f"::error::the stats script exited {rc}" in r.stdout


def test_the_pr_step_pushes_one_new_branch_and_opens_the_pull_request(tmp_path):
    repo, origin, env = _stats_env(tmp_path, 0)
    assert _run_step(repo, env, STATS_SCRIPT).returncode == 0
    r = _run_step(repo, env, "gh pr create")
    assert r.returncode == 0, (r.stdout, r.stderr)
    g = lambda *a: subprocess.run(["git", "-C", str(origin), *a], capture_output=True, text=True, check=True).stdout
    assert g("for-each-ref", "--format=%(refname:short)", "refs/heads").split() == ["main", "stats/1.2.3-last-updated"]
    assert g("diff", "--name-only", "main", "stats/1.2.3-last-updated").split() == ["stats/current.json"]
    assert g("log", "-1", "--format=%an <%ae>|%B", "stats/1.2.3-last-updated").strip() == \
        "AZ Rollin <263686995+azrollin@users.noreply.github.com>|stats: 1.2.3 last_updated is the PyPI upload time"
    log = (tmp_path / "gh.log").read_text()
    assert "pr create --repo o/r --base main --head stats/1.2.3-last-updated --title stats: 1.2.3 last_updated is the PyPI upload time" in log
    assert not re.search(r"claude|anthropic|opus|sonnet|fable|astra|codex|gpt|co-authored|generated with|\bT(8|9|10|11)\b", log, re.I)


def test_a_refused_pull_request_still_leaves_the_branch_and_a_compare_link(tmp_path):
    repo, origin, env = _stats_env(tmp_path, 0, gh_rc=1)
    _run_step(repo, env, STATS_SCRIPT)
    r = _run_step(repo, env, "gh pr create")
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "::warning::stats/1.2.3-last-updated is pushed but the pull request was not opened" in r.stdout
    assert "https://github.test/o/r/compare/main...stats/1.2.3-last-updated?expand=1" in r.stdout
    assert "stats/1.2.3-last-updated" in subprocess.run(["git", "-C", str(origin), "branch", "--list"],
                                                        capture_output=True, text=True).stdout


def test_an_existing_branch_is_left_alone_without_force(tmp_path):
    repo, origin, env = _stats_env(tmp_path, 0)
    subprocess.run(["git", "-C", str(origin), "branch", "stats/1.2.3-last-updated", "main"], check=True)
    before = subprocess.run(["git", "-C", str(origin), "rev-parse", "stats/1.2.3-last-updated"],
                            capture_output=True, text=True).stdout
    _run_step(repo, env, STATS_SCRIPT)
    r = _run_step(repo, env, "gh pr create")
    assert r.returncode == 0 and "already exists on origin" in r.stdout, (r.stdout, r.stderr)
    after = subprocess.run(["git", "-C", str(origin), "rev-parse", "stats/1.2.3-last-updated"],
                           capture_output=True, text=True).stdout
    assert before == after and not (tmp_path / "gh.log").exists()


def test_a_change_of_the_wrong_shape_is_not_committed(tmp_path):
    repo, origin, env = _stats_env(tmp_path, 0)
    _run_step(repo, env, STATS_SCRIPT)
    (repo / "README.md").write_text("x\n")
    path = repo / "stats" / "current.json"
    path.write_text(path.read_text().replace('"released": "2026-10-19"', '"released": "2026-10-20"'))
    r = _run_step(repo, env, "gh pr create")
    assert r.returncode == 1 and "::error::REFUSED: unexpected change" in r.stdout, (r.stdout, r.stderr)
    assert subprocess.run(["git", "-C", str(origin), "for-each-ref", "--format=%(refname:short)", "refs/heads"], capture_output=True, text=True).stdout.split() == ["main"]


# the second release after the first automated stamp: last_updated_by is already release.yml,
# so the real script changes ONE line. Real script, real step blocks, no stub.

REAL_STATS = '{\n  "version": "1.2.3",\n  "last_updated": "%s",\n  "last_updated_by": "%s",\n  "released": "2026-10-19"\n}\n'
WRAPPER = """import importlib.util, sys
spec = importlib.util.spec_from_file_location("real", %r)
real = importlib.util.module_from_spec(spec)
spec.loader.exec_module(real)
fetch = lambda url: {"urls": [{"packagetype": "bdist_wheel", "upload_time_iso_8601": "2026-10-19T14:26:03.195413Z"}]}
sys.exit(real.main(sys.argv, fetch=fetch))
"""


def _real_script_env(tmp_path, last_updated, by, extra=""):
    repo, origin, env = _stats_env(tmp_path, 3)
    (repo / "scripts" / "stats_last_updated.py").write_text(WRAPPER % str(ROOT / "scripts" / "stats_last_updated.py"))
    (repo / "stats" / "current.json").write_text((REAL_STATS % (last_updated, by)).replace('  "released"', extra + '  "released"'))
    ident = ["-c", "user.name=t", "-c", "user.email=t@t"]
    subprocess.run(["git", *ident, "add", "-A"], cwd=repo, check=True)
    subprocess.run(["git", *ident, "commit", "-q", "-m", "fixture"], cwd=repo, check=True)
    subprocess.run(["git", "push", "-q", "origin", "HEAD:refs/heads/main"], cwd=repo, check=True)
    return repo, origin, env


def _branch_diff(origin):
    return subprocess.run(["git", "-C", str(origin), "diff", "main", "stats/1.2.3-last-updated", "--", "stats/current.json"],
                          capture_output=True, text=True, check=True).stdout


def test_a_later_release_with_the_uploader_already_set_still_opens_its_pull_request(tmp_path):
    repo, origin, env = _real_script_env(tmp_path, "2026-10-12T09:00:00-07:00", "release.yml")
    stamp = _run_step(repo, env, STATS_SCRIPT)
    assert stamp.returncode == 0 and _outputs(tmp_path) == ["changed=true"], (stamp.stdout, stamp.stderr)
    pr = _run_step(repo, env, "gh pr create")
    assert pr.returncode == 0, (pr.stdout, pr.stderr)
    changed = [l for l in _branch_diff(origin).splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---"))]
    assert changed == ['-  "last_updated": "2026-10-12T09:00:00-07:00",',
                       '+  "last_updated": "2026-10-19T07:26:03-07:00",'], changed
    assert "pr create --repo o/r --base main" in (tmp_path / "gh.log").read_text()


def test_the_first_automated_stamp_still_changes_both_fields(tmp_path):
    repo, origin, env = _real_script_env(tmp_path, "2026-10-15T16:50:14-07:00", "sunglasses-publish-sh")
    assert _run_step(repo, env, STATS_SCRIPT).returncode == 0
    assert _run_step(repo, env, "gh pr create").returncode == 0
    changed = [l for l in _branch_diff(origin).splitlines() if l[:1] in "+-" and not l.startswith(("+++", "---"))]
    assert len(changed) == 4 and '+  "last_updated_by": "release.yml",' in changed, changed


def test_a_change_to_a_second_file_is_not_committed(tmp_path):
    repo, origin, env = _stats_env(tmp_path, 0)
    _run_step(repo, env, STATS_SCRIPT)
    (repo / "scripts" / "stats_last_updated.py").write_text("print('edited')\n")
    r = _run_step(repo, env, "gh pr create")
    assert r.returncode == 1 and "::error::REFUSED: unexpected change" in r.stdout, (r.stdout, r.stderr)


def test_an_unchanged_tree_is_not_committed(tmp_path):
    repo, origin, env = _stats_env(tmp_path, 3)
    r = _run_step(repo, env, "gh pr create")
    assert r.returncode == 1 and "::error::REFUSED: unexpected change" in r.stdout, (r.stdout, r.stderr)


# the boundary cases the guard has to hold, each through the real step blocks

def _no_pr_and_no_branch(tmp_path, origin):
    refs = subprocess.run(["git", "-C", str(origin), "for-each-ref", "--format=%(refname:short)", "refs/heads"],
                          capture_output=True, text=True).stdout.split()
    return refs == ["main"] and not (tmp_path / "gh.log").exists()


def test_a_nested_timestamp_is_refused_by_the_real_script_and_nothing_is_pushed(tmp_path):
    repo, origin, env = _real_script_env(tmp_path, "x", "y")
    nested = ('{\n  "version": "1.2.3",\n  "meta": {\n    "last_updated": "2026-10-12T09:00:00-07:00",\n'
              '    "last_updated_by": "release.yml"\n  },\n  "released": "2026-10-19"\n}\n')
    (repo / "stats" / "current.json").write_text(nested)
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-am", "nested"], cwd=repo, check=True)
    subprocess.run(["git", "push", "-q", "origin", "HEAD:refs/heads/main"], cwd=repo, check=True)
    stamp = _run_step(repo, env, STATS_SCRIPT)
    assert stamp.returncode == 1 and _outputs(tmp_path) == [], (stamp.stdout, stamp.stderr)
    assert "top-level strings" in stamp.stdout
    assert (repo / "stats" / "current.json").read_text() == nested
    assert _no_pr_and_no_branch(tmp_path, origin)


def _edited_pr_step(tmp_path, edit, extra=""):
    """Stamp with the real script, then let `edit` change the file, then run the PR step."""
    repo, origin, env = _real_script_env(tmp_path, "2026-10-12T09:00:00-07:00", "release.yml", extra)
    assert _run_step(repo, env, STATS_SCRIPT).returncode == 0
    path = repo / "stats" / "current.json"
    path.write_text(edit(path.read_text()))
    r = _run_step(repo, env, "gh pr create")
    return r, tmp_path, origin


@pytest.mark.parametrize("edit", [
    # another property on a line the old guard allowed by prefix
    lambda text: text.replace('"last_updated_by": "release.yml",', '"last_updated_by": "release.yml", "released": "2026-10-20",'),
    # a different value on the released line
    lambda text: text.replace('"released": "2026-10-19"', '"released": "2026-10-20"'),
    # a nested copy of the field name added on its own line
    lambda text: text.replace('"released"', '"x": {"last_updated": "1"},\n  "released"'),
    # a reformatting of the whole file that leaves the parsed document alone
    lambda text: text.replace("\n  ", "\n      "),
    # the stamped values removed
    lambda text: text.replace('"last_updated_by": "release.yml",', '"last_updated_by": 7,'),
])
def test_the_pr_step_refuses_an_edit_outside_the_two_top_level_values(tmp_path, edit):
    r, tp, origin = _edited_pr_step(tmp_path, edit)
    assert r.returncode == 1 and "::error::REFUSED: unexpected change" in r.stdout, (r.stdout, r.stderr)
    assert _no_pr_and_no_branch(tp, origin)


@pytest.mark.parametrize("extra, edit", [
    # an unrelated true turned into the number 1: equal in Python, different in JSON
    ('  "beta": true,\n', lambda text: text.replace('"beta": true', '"beta": 1')),
    ('  "ratio": 1,\n', lambda text: text.replace('"ratio": 1', '"ratio": 1.0')),
    # one unrelated line re-indented (inside the old two-line budget)
    ('  "beta": true,\n', lambda text: text.replace('  "beta": true', '      "beta": true')),
    # the two stamped keys swapped places
    ('', lambda text: text.replace('  "last_updated": "2026-10-19T07:26:03-07:00",\n  "last_updated_by": "release.yml",\n',
                                   '  "last_updated_by": "release.yml",\n  "last_updated": "2026-10-19T07:26:03-07:00",\n')),
])
def test_the_pr_step_keeps_json_types_and_every_other_line(tmp_path, extra, edit):
    repo, origin, env = _real_script_env(tmp_path, "2026-10-12T09:00:00-07:00", "release.yml", extra)
    assert _run_step(repo, env, STATS_SCRIPT).returncode == 0
    path = repo / "stats" / "current.json"
    before = path.read_text()
    path.write_text(edit(before))
    assert path.read_text() != before
    r = _run_step(repo, env, "gh pr create")
    assert r.returncode == 1 and "::error::REFUSED: unexpected change" in r.stdout, (r.stdout, r.stderr)
    assert _no_pr_and_no_branch(tmp_path, origin)


def test_the_pr_step_refuses_a_file_that_is_not_a_json_object(tmp_path):
    r, tp, origin = _edited_pr_step(tmp_path, lambda text: "[]\n")
    assert r.returncode == 1 and "::error::REFUSED: unexpected change" in r.stdout, (r.stdout, r.stderr)
    assert _no_pr_and_no_branch(tp, origin)
