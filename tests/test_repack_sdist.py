"""scripts/repack_sdist.sh must turn one sdist into one byte sequence.

setuptools ignores SOURCE_DATE_EPOCH for the sdist. The 0.6.5 measurement found four
builds of one commit and the file PyPI holds all different, with the same member names,
order, modes and bytes every time. Only three things moved: member mtimes, the gzip
header time and the owner ids (the CI runner is 1001, a laptop is 501). The script
rewrites exactly those three and nothing else, so the sdist sha256 becomes a fact about
the commit like the wheel's already is.

Rows pinned here:
1. the control: two archives of the same content with different times, owners, member
   order and gzip time really do differ before the repack, so a pass below proves the script,
2. after the repack they are byte identical, and a second repack changes nothing,
3. names, modes, sizes and file bytes survive, every mtime is SOURCE_DATE_EPOCH, every
   owner is 0, the gzip header time is 0,
4. the script refuses (and leaves the file alone) with no SOURCE_DATE_EPOCH, with an empty
   one, with a name that is not .tar.gz, with a corrupt archive, with an archive that
   has two top directories, and with a tar that is not GNU tar.
"""
import gzip
import hashlib
import io
import os
import pathlib
import shutil
import stat
import subprocess
import tarfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "repack_sdist.sh"
SDE = "1790955083"

_tar_version = subprocess.run(["tar", "--version"], capture_output=True, text=True).stdout
needs_gnu_tar = pytest.mark.skipif("GNU tar" not in _tar_version,
                                   reason="the repack needs GNU tar, the release runner has it")

FILES = [  # (name, bytes, mode)
    ("pkg-1.0/PKG-INFO", b"Name: pkg\nVersion: 1.0\n", 0o644),
    ("pkg-1.0/setup.cfg", b"[egg_info]\ntag_build =\n", 0o644),
    ("pkg-1.0/pyproject.toml", b"[project]\nname = 'pkg'\n", 0o644),
    ("pkg-1.0/pkg/__init__.py", b"__version__ = '1.0'\n", 0o644),
    ("pkg-1.0/pkg/run.sh", b"#!/bin/sh\necho hi\n", 0o755),
    ("pkg-1.0/pkg.egg-info/SOURCES.txt", b"pkg/__init__.py\n", 0o644),
]
DIRS = ["pkg-1.0", "pkg-1.0/pkg", "pkg-1.0/pkg.egg-info"]


def make_sdist(path, *, mtime, uid, uname, gzip_mtime, reverse=False, files=FILES, dirs=DIRS, tree_sorted=False):
    members = [(d, None, 0o755) for d in dirs] + list(files)
    if reverse:
        members = members[::-1]
    if tree_sorted:
        members.sort(key=lambda m: tuple(m[0].split("/")))
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for name, data, mode in members:
            ti = tarfile.TarInfo(name)
            ti.mtime, ti.uid, ti.gid, ti.uname, ti.gname, ti.mode = mtime, uid, uid, uname, uname, mode
            if data is None:
                ti.type = tarfile.DIRTYPE
                tf.addfile(ti)
            else:
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
    with open(path, "wb") as fh:
        with gzip.GzipFile(filename="", fileobj=fh, mode="wb", mtime=gzip_mtime) as gz:
            gz.write(raw.getvalue())
    return path


def sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def repack(path, env_extra=None, sde=SDE, path_prefix=None):
    env = {k: v for k, v in os.environ.items() if k != "SOURCE_DATE_EPOCH"}
    if sde is not None:
        env["SOURCE_DATE_EPOCH"] = sde
    if path_prefix:
        env["PATH"] = f"{path_prefix}{os.pathsep}{env['PATH']}"
    env.update(env_extra or {})
    # umask 077: an extract without -p would lose the group and other bits, so a repack that
    # forgot -p changes modes and the script's own before and after check must refuse it
    return subprocess.run(["bash", "-c", 'umask 077; exec bash "$0" "$1"', str(SCRIPT), str(path)],
                          capture_output=True, text=True, env=env, timeout=120)


def members(path):
    out = {}
    with tarfile.open(path, "r:gz") as tf:
        for m in tf.getmembers():
            data = tf.extractfile(m).read() if m.isfile() else None
            out[m.name] = (stat.S_IMODE(m.mode), m.size, hashlib.sha256(data).hexdigest() if data is not None else None, m.type)
    return out


MANY = [(f"pkg-1.0/pkg/m{(i * 7919) % 1000:03d}_{'zyx'[i % 3]}.py", f"v{i}\n".encode(), 0o644) for i in range(60)]


@pytest.fixture
def two(tmp_path):
    a = make_sdist(tmp_path / "a.tar.gz", mtime=1700000000, uid=1001, uname="runner", gzip_mtime=1700000111)
    b = make_sdist(tmp_path / "b.tar.gz", mtime=1790999999, uid=501, uname="laptopuser", gzip_mtime=1790999000, reverse=True)
    return a, b


def test_the_control_two_sdists_of_one_content_differ_before_the_repack(two):
    a, b = two
    assert sha(a) != sha(b)
    assert members(a) == members(b), "the control must hold the same names, modes, sizes and bytes"
    assert len(members(a)) == len(FILES) + len(DIRS) > 0


@needs_gnu_tar
def test_two_different_sdists_of_one_content_repack_to_the_same_bytes(two):
    a, b = two
    ra, rb = repack(a), repack(b)
    assert ra.returncode == 0, ra.stderr
    assert rb.returncode == 0, rb.stderr
    assert sha(a) == sha(b)


@needs_gnu_tar
def test_a_second_repack_changes_nothing(two):
    a, _ = two
    assert repack(a).returncode == 0
    first = sha(a)
    assert repack(a).returncode == 0
    assert sha(a) == first


@needs_gnu_tar
def test_names_modes_sizes_and_bytes_survive(two):
    a, _ = two
    before = members(a)
    assert repack(a).returncode == 0
    after = members(a)
    assert after == before and len(after) > 0
    assert after["pkg-1.0/pkg/run.sh"][0] == 0o755
    assert after["pkg-1.0/pkg/__init__.py"][0] == 0o644


@needs_gnu_tar
def test_every_time_and_owner_field_is_pinned(two):
    a, _ = two
    assert repack(a).returncode == 0
    raw = a.read_bytes()
    assert raw[:2] == b"\x1f\x8b"
    assert raw[4:8] == b"\x00\x00\x00\x00", "gzip header mtime must be zero"
    with tarfile.open(a, "r:gz") as tf:
        ms = tf.getmembers()
        assert len(ms) == len(FILES) + len(DIRS)
        assert {m.mtime for m in ms} == {int(SDE)}
        assert {(m.uid, m.gid) for m in ms} == {(0, 0)}
        names = [m.name for m in ms]
        assert names == sorted(names, key=lambda n: tuple(n.split("/"))), "members are in sorted tree order"
        assert not any(m.pax_headers for m in ms), "no pax headers: they would carry a pid or a time"


@needs_gnu_tar
def test_a_repack_leaves_no_temp_file_beside_the_sdist(two):
    a, _ = two
    before = sorted(p.name for p in a.parent.iterdir())
    assert repack(a).returncode == 0
    assert sorted(p.name for p in a.parent.iterdir()) == before


# ── refusals: each leaves the input untouched ────────────────────────────

def _refused(path, **kw):
    before = sha(path) if pathlib.Path(path).exists() else None
    r = repack(path, **kw)
    assert r.returncode != 0, (r.stdout, r.stderr)
    assert r.stderr.strip(), "a refusal must say why"
    if before is not None:
        assert sha(path) == before, "a refused repack must not touch the input"
    return r


@needs_gnu_tar
def test_it_refuses_without_source_date_epoch(two):
    r = _refused(two[0], sde=None)
    assert "SOURCE_DATE_EPOCH" in r.stderr


@needs_gnu_tar
def test_it_refuses_an_empty_source_date_epoch(two):
    r = _refused(two[0], sde="")
    assert "SOURCE_DATE_EPOCH" in r.stderr


@needs_gnu_tar
def test_it_refuses_a_non_numeric_source_date_epoch(two):
    _refused(two[0], sde="yesterday")


@needs_gnu_tar
def test_it_refuses_a_name_that_is_not_tar_gz(tmp_path):
    p = make_sdist(tmp_path / "x.zip", mtime=1, uid=1, uname="u", gzip_mtime=1)
    _refused(p)


@needs_gnu_tar
def test_it_refuses_a_corrupt_archive(tmp_path):
    p = tmp_path / "bad.tar.gz"
    p.write_bytes(b"this is not a gzip file")
    _refused(p)


@needs_gnu_tar
def test_it_refuses_an_archive_with_two_top_directories(tmp_path):
    files = FILES + [("other-1.0/x.py", b"x\n", 0o644)]
    p = make_sdist(tmp_path / "two.tar.gz", mtime=1, uid=1, uname="u", gzip_mtime=1,
                   files=files, dirs=DIRS + ["other-1.0"])
    _refused(p)


@needs_gnu_tar
def test_it_refuses_a_missing_file(tmp_path):
    _refused(tmp_path / "nope.tar.gz")


def test_it_refuses_a_tar_that_is_not_gnu_tar(tmp_path):
    """Runs everywhere. A stub tar that claims to be bsdtar must stop the script before it
    touches anything: bsdtar has no --sort, and a pax or ustar repack is not reproducible."""
    stub = tmp_path / "bin"
    stub.mkdir()
    (stub / "tar").write_text('#!/bin/sh\necho "bsdtar 3.5.3 - libarchive 3.5.3"\n')
    (stub / "tar").chmod(0o755)
    p = make_sdist(tmp_path / "a.tar.gz", mtime=1, uid=1, uname="u", gzip_mtime=1)
    r = _refused(p, path_prefix=str(stub))
    assert "GNU tar" in r.stderr


def test_the_script_exists_and_is_executable_shell():
    assert SCRIPT.is_file(), SCRIPT
    assert SCRIPT.read_text().startswith("#!/usr/bin/env bash")
    assert "set -euo pipefail" in SCRIPT.read_text()


@needs_gnu_tar
def test_many_files_in_a_scrambled_creation_order_repack_to_the_same_bytes(tmp_path):
    """Directory read order on the runner is not sorted, so only --sort=name makes the order a
    fact. Sixty files created in a scrambled order, in two archives that list them in opposite
    orders, must repack to one file."""
    files = FILES + MANY
    a = make_sdist(tmp_path / "a.tar.gz", mtime=5, uid=1001, uname="runner", gzip_mtime=5, files=files)
    b = make_sdist(tmp_path / "b.tar.gz", mtime=9, uid=501, uname="me", gzip_mtime=9, files=files, reverse=True)
    assert sha(a) != sha(b) and len(members(a)) == len(files) + len(DIRS)
    assert repack(a).returncode == 0 and repack(b).returncode == 0
    assert sha(a) == sha(b)
    with tarfile.open(a, "r:gz") as tf:
        names = [m.name for m in tf.getmembers()]
    assert names == sorted(names, key=lambda n: tuple(n.split("/")))


# ── the script's own postcondition: a tool that lies must be refused ─────

def _stub_gzip(tmp_path, archive):
    stub = tmp_path / "stubbin"
    stub.mkdir(exist_ok=True)
    # tar -z calls `gzip -d` to read the input, so only the compressing call is replaced
    real = shutil.which("gzip")
    (stub / "gzip").write_text(f'#!/bin/sh\ncase "$*" in *-d*) exec "{real}" "$@";; esac\ncat >/dev/null\ncat "{archive}"\n')
    (stub / "gzip").chmod(0o755)
    return str(stub)


@needs_gnu_tar
def test_it_refuses_a_repack_whose_content_differs(tmp_path):
    changed = [(n, d + b"TAMPERED" if n.endswith("__init__.py") else d, m) for n, d, m in FILES]
    evil = make_sdist(tmp_path / "evil.tar.gz", mtime=int(SDE), uid=0, uname="", gzip_mtime=0,
                      files=changed, tree_sorted=True)
    good = make_sdist(tmp_path / "a.tar.gz", mtime=1, uid=1, uname="u", gzip_mtime=1)
    r = _refused(good, path_prefix=_stub_gzip(tmp_path, evil))
    assert "changed content" in r.stderr


@needs_gnu_tar
def test_it_refuses_a_repack_that_left_the_times_unpinned(tmp_path):
    late = make_sdist(tmp_path / "late.tar.gz", mtime=int(SDE) + 60, uid=0, uname="", gzip_mtime=0, tree_sorted=True)
    good = make_sdist(tmp_path / "a.tar.gz", mtime=1, uid=1, uname="u", gzip_mtime=1)
    r = _refused(good, path_prefix=_stub_gzip(tmp_path, late))
    assert "still carries mtime" in r.stderr


@needs_gnu_tar
def test_it_refuses_a_repack_with_a_gzip_header_time(tmp_path):
    stamped = make_sdist(tmp_path / "stamped.tar.gz", mtime=int(SDE), uid=0, uname="", gzip_mtime=1790955083, tree_sorted=True)
    good = make_sdist(tmp_path / "a.tar.gz", mtime=1, uid=1, uname="u", gzip_mtime=1)
    r = _refused(good, path_prefix=_stub_gzip(tmp_path, stamped))
    assert "gzip header time" in r.stderr


@needs_gnu_tar
def test_the_stub_control_a_good_archive_through_the_same_stub_is_accepted(tmp_path):
    """Without this the three refusals above would pass against a script that refuses everything."""
    ok = make_sdist(tmp_path / "ok.tar.gz", mtime=int(SDE), uid=0, uname="", gzip_mtime=0, tree_sorted=True)
    good = make_sdist(tmp_path / "a.tar.gz", mtime=1, uid=1, uname="u", gzip_mtime=1)
    r = repack(good, path_prefix=_stub_gzip(tmp_path, ok))
    assert r.returncode == 0, r.stderr
    assert sha(good) == sha(ok)


@needs_gnu_tar
@pytest.mark.parametrize("mode", [0o644, 0o664, 0o600])
def test_the_file_mode_of_the_sdist_itself_is_kept(two, mode):
    """The repack stages its output in a temp file, which is created 0600. The sdist in dist/
    must keep the mode it had, not inherit the temp file's."""
    a, _ = two
    a.chmod(mode)
    assert repack(a).returncode == 0
    assert stat.S_IMODE(a.stat().st_mode) == mode
