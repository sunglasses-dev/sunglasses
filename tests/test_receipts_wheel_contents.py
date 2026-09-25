"""The receipts wheel carries the spec and the vectors, and not the tests or
the vector generator (T9 ruling 47, outsider rehearsal gaps G1 and G2).

The 10-3 claim is that `pip install "sunglasses[receipts]"` verifies a fixture
receipt. At 5480cdd the wheel carried neither WIRE_SPEC.md nor VECTORS.json, so
the fixture and the spec had to come from GitHub, and it DID carry seven test
files plus make_vectors.py, which fails on import from an installed wheel
(`No module named 'codes'`). Every other receipts test reads the source tree,
where all of that looks right, so this one builds the wheel and reads its
member list.

The build follows tests/proxy/test_wheel_contents.py and for the same reasons:
a CLEAN COPY of the tree (build/lib persists between builds and never drops a
file), `--no-cache-dir`, build isolation on, and no skip when the build fails,
because a wheel that will not build is this row's subject. The `network` mark
lets an offline runner deselect it by name; nothing deselects it by default.
"""
import pathlib
import shutil
import subprocess
import sys
import zipfile

import pytest

pytestmark = pytest.mark.network

REPO = pathlib.Path(__file__).resolve().parents[1]

# Named, never globbed: a glob over the wheel passes on whatever is in it.
MUST_SHIP = (
    "sunglasses/receipts/WIRE_SPEC.md",
    "sunglasses/receipts/VECTORS.json",
    "sunglasses/receipts/codes.py",
    "sunglasses/receipts/verify.py",
)


@pytest.fixture(scope="module")
def wheel_members(tmp_path_factory):
    source = tmp_path_factory.mktemp("source") / "repo"
    shutil.copytree(REPO, source, ignore=shutil.ignore_patterns(
        ".git", "build", "dist", "*.egg-info", "__pycache__", ".pytest_cache"))
    out = tmp_path_factory.mktemp("wheel")
    build = subprocess.run(
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


@pytest.mark.parametrize("member", MUST_SHIP)
def test_the_wheel_carries_the_spec_and_the_vectors(member, wheel_members):
    assert member in wheel_members, (
        f"{member} is not in the built wheel, so an outsider who installs "
        f"sunglasses[receipts] has to fetch it from GitHub")


def test_the_wheel_carries_no_tests(wheel_members):
    shipped = sorted(name for name in wheel_members
                     if "/tests/" in name or name.startswith("tests/")
                     or pathlib.PurePosixPath(name).name.startswith("test_"))
    assert shipped == []


def test_the_wheel_does_not_carry_the_vector_generator(wheel_members):
    assert not any(name.endswith("make_vectors.py") for name in wheel_members)


def test_the_gate_reads_a_wheel(wheel_members):
    """The control: a member list from the tree would carry this file and no
    dist-info."""
    assert any(name.endswith(".dist-info/METADATA") for name in wheel_members)
    assert "sunglasses/receipts/wire.py" in wheel_members
