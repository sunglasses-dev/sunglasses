"""Say which tree the suite just ran on.

Three times in one day a green suite was reported as evidence for a merge, and
all three were green on a tree CI does not test: the branch had been cut before
a gate merged, so the run proved something about a tree that no longer existed.
The tell was always available and never printed.

So every local run now opens with the sha of the working tree, the sha of
`origin/main` as this checkout last fetched it, and whether HEAD contains it.
It reads the refs on disk and never fetches, because a test run must not depend
on the network and a stale ref is itself the thing worth seeing: "origin/main as
of your last fetch" is the honest phrasing, and it is what the line says.

Nothing here can fail a run. If the checkout is not a git repository, or the ref
is missing, the line says so and the suite proceeds.
"""
import subprocess


def _git(*args):
    """The value, or None. A missing ref is information, not an error."""
    try:
        out = subprocess.run(("git",) + args, capture_output=True, text=True,
                             timeout=10)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def pytest_report_header(config):
    head = _git("rev-parse", "HEAD")
    if head is None:
        return "tree: not a git checkout, so this run names no tree"

    dirty = _git("status", "--porcelain")
    state = "dirty" if dirty else "clean"
    branch = _git("rev-parse", "--abbrev-ref", "HEAD") or "?"
    line = f"tree: HEAD {head[:7]} on {branch} ({state})"

    main = _git("rev-parse", "refs/remotes/origin/main")
    if main is None:
        return [line, "tree: no origin/main ref in this checkout, "
                      "so containment is unknown"]

    contains = subprocess.run(
        ("git", "merge-base", "--is-ancestor", main, head),
        capture_output=True).returncode == 0
    verdict = "CONTAINS it" if contains else "DOES NOT CONTAIN it"
    return [line,
            f"tree: origin/main {main[:7]} as of your last fetch, and HEAD "
            f"{verdict}",
            "tree: CI tests refs/pull/N/merge, so a run on a HEAD that does not "
            "contain origin/main is not evidence about what CI will run"]


# ASTRA's artifact controls (tests/proxy/test_artifact_review.py) read their
# payload specimens out of the review layout, `tests/stack/tests/...`, so that
# path is a symlink back to this suite's own file. Collecting it twice is an
# import-file-mismatch, and the controls are vendored unchanged, so the
# directory is skipped here rather than the control being edited.
# `stack/` is that, and `source/` is the same shape: the review layout lays a
# symlink there so ASTRA's controls resolve this suite's sources at the paths
# they were written against. It is laid down locally rather than tracked,
# because a directory symlink pointing back at its own parent is a cycle for
# anything that walks the tree. The glob is listed either way, so laying the
# layout down never turns a green suite into an import-file-mismatch.
collect_ignore_glob = ["stack/*", "source/*"]


# Child PROCESSES this suite spawns must be able to import the package.
# `python -m sunglasses.proxy` works because -m puts the working directory on
# sys.path, but `python tests/scripts/artifact_peer.py` puts only the SCRIPT's
# directory there, so a peer that imports sunglasses dies on ImportError with
# its stderr pointed at DEVNULL by the proxy that spawned it. The failure then
# looks like the proxy never sending anything, which is a long way from the
# cause. Exported here rather than in each control, because the controls are
# vendored unchanged.
import os as _os
import pathlib as _pathlib

_ROOT = str(_pathlib.Path(__file__).resolve().parents[1])
if _ROOT not in _os.environ.get("PYTHONPATH", "").split(_os.pathsep):
    _os.environ["PYTHONPATH"] = _os.pathsep.join(
        [_ROOT] + [p for p in _os.environ.get("PYTHONPATH", "").split(_os.pathsep) if p])
