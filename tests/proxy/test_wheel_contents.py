"""C7. The shipped artifact contains the things R1 spawns.

D3, narrowed by T9 on 2026-09-15: no new files and no MANIFEST change, because
a `.py` module inside a package already ships. What was missing is the GATE --
the assertion that it actually did, made against the BUILT WHEEL rather than
against the tree.

The distinction is the whole row. Every other test in this suite imports from
the source tree, where `sunglasses/proxy/__main__.py` is obviously present; a
packaging mistake is invisible there and visible only to the user who pip
installs and runs `python -m sunglasses.proxy`. So this builds the wheel and
reads its member list.

It is deliberately NOT a skipif-when-build-tools-are-missing test. A check that
skips itself is worse than no check (Sep-13 rule): if the wheel cannot be
built, that is a failure of the thing this row exists to measure.
"""
import pathlib
import shutil
import subprocess
import sys
import zipfile

import pytest

REPO = pathlib.Path(__file__).resolve().parents[2]

# What `python -m sunglasses.proxy` needs in order to exist at all, and what
# T10.R1's self test spawns. Named explicitly rather than globbed: a glob over
# the wheel would pass on whatever happens to be in it.
REQUIRED_MEMBERS = (
    "sunglasses/proxy/__main__.py",
    "sunglasses/proxy/echo_server.py",
    "sunglasses/proxy/commands.py",
    "sunglasses/proxy/serve.py",
)


@pytest.fixture(scope="module")
def wheel_members(tmp_path_factory):
    """Build the wheel from a CLEAN COPY of the tree and return its members.

    THE COPY IS THE GATE, and finding that out took four wrong mutations.
    Building in place produced a wheel that contained `__main__.py` after I had
    DELETED the file from the tree: setuptools' `build/lib` persists between
    builds and build_py copies into it incrementally, so it never drops a file
    that has gone. A packaging gate that reads that wheel reports on whatever
    the last build left behind -- green forever, measuring nothing.

    `--no-cache-dir` is here for the same reason one layer up: pip will return
    a wheel it built earlier for the same name and version.

    Not a skipif when the build fails, either. If the wheel cannot be built,
    that IS the failure this row exists to report (Sep-13 rule).
    """
    source = tmp_path_factory.mktemp("source") / "repo"
    shutil.copytree(REPO, source, ignore=shutil.ignore_patterns(
        ".git", "build", "dist", "*.egg-info", "__pycache__", ".pytest_cache"))
    out = tmp_path_factory.mktemp("wheel")
    build = subprocess.run(
        # BUILD ISOLATION IS BACK ON (T9 ruling, 2026-09-18). With
        # `--no-build-isolation` pip must find the backend in the CURRENT
        # environment, and on the runner it cannot: `BackendUnavailable: Cannot
        # import 'setuptools.build_meta'`. Metadata preparation finished `done`
        # first, so packaging was never the problem -- the build ENVIRONMENT
        # was. This row's subject is WHAT THE WHEEL CARRIES, not how the build
        # environment is provisioned, and the docstring above justifies the
        # clean copy and `--no-cache-dir` without ever claiming isolation-off
        # was deliberate. The alternative -- keep it and skip when setuptools
        # is absent -- is the check that skips itself: green forever on any
        # runner that never has it. No skips.
        [sys.executable, "-m", "pip", "wheel", "--no-deps",
         "--no-cache-dir", "-w", str(out), str(source)],
        capture_output=True, text=True, timeout=900)
    assert build.returncode == 0, (
        f"the wheel did not build, which is this row's subject and not an "
        f"excuse to skip it:\n{build.stdout[-2000:]}\n{build.stderr[-2000:]}")
    wheels = sorted(out.glob("sunglasses-*.whl"))
    assert wheels, f"pip wheel wrote no sunglasses wheel into {out}"
    with zipfile.ZipFile(wheels[-1]) as archive:
        return set(archive.namelist())


@pytest.mark.parametrize("member", REQUIRED_MEMBERS)
def test_C7_the_wheel_carries_what_the_entry_point_needs(member, wheel_members):
    """Each member, named, so a failure says WHICH one is missing."""
    assert member in wheel_members, (
        f"{member} is not in the built wheel. `python -m sunglasses.proxy` and "
        f"the self test it spawns are broken for every installed user, and no "
        f"test that reads the source tree can see it.")


def test_C7_the_gate_reads_the_wheel_and_not_the_tree(wheel_members):
    """The gate's own honesty check.

    A member list that came from the source tree would contain this test file;
    a wheel does not ship tests. Without this, a future refactor that pointed
    the fixture at the checkout would leave every row above green while
    measuring nothing about the artifact.
    """
    assert not any(name.startswith("tests/") for name in wheel_members), (
        "the member list contains test files, so it is not a wheel")
    assert any(name.endswith(".dist-info/METADATA") for name in wheel_members), (
        "the member list has no dist-info, so it is not a wheel")
