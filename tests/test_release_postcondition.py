"""scripts/release_postcondition.sh compares what PyPI serves with what the tag builds.

The check is on CONTENT: both wheels are unpacked, both sdists are unpacked, and the trees
are compared with diff -r. It never compares the archive sha of the wheel, because that
moves with build time and tells you nothing (the 0.6.5 lesson). A second check, equality of
the sdist sha, only applies when the tag carries scripts/repack_sdist.sh, since only then is
the sdist's sha a fact about the commit. On a tag without it (0.6.5) the check is reported
as NOT APPLICABLE and never fails.

Rows pinned here:
1. the control: two archives of one content whose bytes differ (zip dates, owners, gzip
   time) must still PASS, with a non zero count of files compared, so a pass proves the
   reader saw data and compared content,
2. a tampered wheel, a tampered sdist, an extra file and a missing file each FAIL and name
   the path, with at most five paths listed even when more differ,
3. nothing to compare is a refusal (exit 2), never a pass: an empty wheel, a missing sdist,
   two wheels in one directory, a bad version, no tag in the repo,
4. the sdist sha check: equal passes, different fails when the repack is live, and is
   NOT APPLICABLE when it is not,
5. the fetch path (a stub curl stands in for PyPI): a download whose sha256 is not the one
   PyPI states is refused.
"""
import gzip
import hashlib
import io
import json
import os
import pathlib
import subprocess
import tarfile
import zipfile

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "release_postcondition.sh"
PKG = "sunglasses"
VER = "1.2.3"

CONTENT = {
    "sunglasses/__init__.py": b"__version__ = '1.2.3'\n",
    "sunglasses/engine.py": b"class E:\n    pass\n",
    "sunglasses/data/patterns.json": b'{"n": 3}\n',
    "sunglasses-1.2.3.dist-info/METADATA": b"Name: sunglasses\nVersion: 1.2.3\n",
    "sunglasses-1.2.3.dist-info/RECORD": b"sunglasses/__init__.py,sha256=x,21\n",
}
SDIST_CONTENT = {f"sunglasses-{VER}/{k}": v for k, v in CONTENT.items() if "dist-info" not in k}
SDIST_CONTENT[f"sunglasses-{VER}/PKG-INFO"] = b"Name: sunglasses\nVersion: 1.2.3\n"


def make_wheel(d, files=None, date=(2026, 10, 2, 8, 0, 0), name=None):
    d.mkdir(parents=True, exist_ok=True)
    p = d / (name or f"{PKG}-{VER}-py3-none-any.whl")
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        for n, data in (CONTENT if files is None else files).items():
            zi = zipfile.ZipInfo(n, date_time=date)
            zi.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(zi, data)
    return p


def make_sdist(d, files=None, mtime=1790955083, uid=0, gz_mtime=0):
    d.mkdir(parents=True, exist_ok=True)
    p = d / f"{PKG}-{VER}.tar.gz"
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for n, data in (SDIST_CONTENT if files is None else files).items():
            ti = tarfile.TarInfo(n)
            ti.size, ti.mtime, ti.uid, ti.gid = len(data), mtime, uid, uid
            tf.addfile(ti, io.BytesIO(data))
    with open(p, "wb") as fh:
        with gzip.GzipFile(filename="", fileobj=fh, mode="wb", mtime=gz_mtime) as gz:
            gz.write(raw.getvalue())
    return p


def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def run(pypi, built, *, live=None, version=VER, extra_env=None, path_prefix=None):
    env = {k: v for k, v in os.environ.items() if k not in ("PYPI_DIST_DIR", "BUILT_DIST_DIR", "REPACK_LIVE")}
    if pypi is not None:
        env["PYPI_DIST_DIR"] = str(pypi)
    if built is not None:
        env["BUILT_DIST_DIR"] = str(built)
    if live is not None:
        env["REPACK_LIVE"] = live
    if path_prefix:
        env["PATH"] = f"{path_prefix}{os.pathsep}{env['PATH']}"
    env.update(extra_env or {})
    args = ["bash", str(SCRIPT)] + ([version] if version is not None else [])
    return subprocess.run(args, capture_output=True, text=True, env=env, timeout=120)


def pair(tmp_path, wheel_b=None, sdist_b=None, **sd):
    a, b = tmp_path / "pypi", tmp_path / "built"
    make_wheel(a)
    make_sdist(a)
    make_wheel(b, files=wheel_b, date=(2026, 10, 2, 9, 30, 0))
    make_sdist(b, files=sdist_b, mtime=1800000000, uid=1001, gz_mtime=1800000001, **sd)
    return a, b


def diffs(r):
    return [l for l in r.stderr.splitlines() if l.startswith("DIFF ")]


# ── 1. the control ────────────────────────────────────────────────────────

def test_the_control_archives_that_differ_in_bytes_but_not_in_content_pass(tmp_path):
    a, b = pair(tmp_path)
    assert sha(next(a.glob("*.whl"))) != sha(next(b.glob("*.whl")))
    assert sha(next(a.glob("*.tar.gz"))) != sha(next(b.glob("*.tar.gz")))
    r = run(a, b)
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "content equal" in r.stdout
    assert f"{len(CONTENT)} files" in r.stdout and f"{len(SDIST_CONTENT)} files" in r.stdout, r.stdout


# ── 2. content differences fail and name the path ────────────────────────

def test_a_tampered_wheel_fails_and_names_the_file(tmp_path):
    tampered = dict(CONTENT)
    tampered["sunglasses/engine.py"] = b"class E:\n    import os\n"
    a, b = pair(tmp_path, wheel_b=tampered)
    r = run(a, b)
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert any("sunglasses/engine.py" in l and "wheel" in l for l in diffs(r)), r.stderr


def test_a_tampered_sdist_fails_and_names_the_file(tmp_path):
    tampered = dict(SDIST_CONTENT)
    tampered[f"sunglasses-{VER}/sunglasses/data/patterns.json"] = b'{"n": 4}\n'
    a, b = pair(tmp_path, sdist_b=tampered)
    r = run(a, b)
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
    assert any("patterns.json" in l and "sdist" in l for l in diffs(r)), r.stderr


def test_a_file_only_one_side_has_fails(tmp_path):
    extra = dict(CONTENT)
    extra["sunglasses/backdoor.py"] = b"x = 1\n"
    a, b = pair(tmp_path, wheel_b=extra)
    r = run(a, b)
    assert r.returncode == 1
    assert any("backdoor.py" in l for l in diffs(r)), r.stderr


def test_a_file_missing_from_the_rebuild_fails(tmp_path):
    fewer = {k: v for k, v in CONTENT.items() if not k.endswith("engine.py")}
    a, b = pair(tmp_path, wheel_b=fewer)
    r = run(a, b)
    assert r.returncode == 1
    assert any("engine.py" in l for l in diffs(r)), r.stderr


def test_at_most_five_paths_are_listed_and_the_total_is_said(tmp_path):
    many = {f"sunglasses/m{i}.py": b"a\n" for i in range(8)}
    base = dict(CONTENT, **many)
    changed = dict(base, **{f"sunglasses/m{i}.py": b"b\n" for i in range(8)})
    a, b = tmp_path / "pypi", tmp_path / "built"
    make_wheel(a, files=base)
    make_sdist(a)
    make_wheel(b, files=changed)
    make_sdist(b)
    r = run(a, b)
    assert r.returncode == 1
    assert len(diffs(r)) == 5, r.stderr
    assert "8 differing" in r.stderr and "first 5" in r.stderr, r.stderr


def test_the_wheel_sha_is_never_the_judge(tmp_path):
    """Same content, different zip bytes, with the repack live and the sdists equal: still a pass."""
    a, b = pair(tmp_path)
    shutil_copy = (a / f"{PKG}-{VER}.tar.gz").read_bytes()
    (b / f"{PKG}-{VER}.tar.gz").write_bytes(shutil_copy)
    assert sha(next(a.glob("*.whl"))) != sha(next(b.glob("*.whl")))
    r = run(a, b, live="yes")
    assert r.returncode == 0, (r.stdout, r.stderr)


# ── 3. nothing to compare is a refusal, never a pass ─────────────────────

def test_an_empty_wheel_is_refused_not_passed(tmp_path):
    a, b = pair(tmp_path)
    make_wheel(a, files={})
    make_wheel(b, files={})
    r = run(a, b)
    assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)
    assert "REFUSED" in r.stderr


def test_a_missing_sdist_is_refused(tmp_path):
    a, b = pair(tmp_path)
    next(b.glob("*.tar.gz")).unlink()
    r = run(a, b)
    assert r.returncode == 2 and "REFUSED" in r.stderr


def test_two_wheels_in_one_directory_are_refused(tmp_path):
    a, b = pair(tmp_path)
    make_wheel(a, name=f"{PKG}-{VER}-py3-none-manylinux.whl")
    r = run(a, b)
    assert r.returncode == 2 and "REFUSED" in r.stderr


def test_a_different_wheel_filename_fails(tmp_path):
    a, b = pair(tmp_path)
    next(b.glob("*.whl")).rename(b / f"{PKG}-{VER}-py2-none-any.whl")
    r = run(a, b)
    assert r.returncode == 1 and any("filename" in l for l in diffs(r)), r.stderr


@pytest.mark.parametrize("version", [None, "", "1.2", "v1.2.3", "1.2.3; rm -rf /", "../1.2.3"])
def test_a_bad_version_is_refused(tmp_path, version):
    a, b = pair(tmp_path)
    r = run(a, b, version=version)
    assert r.returncode == 2 and "REFUSED" in r.stderr


def test_a_repo_without_the_tag_is_refused(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    for cmd in (["git", "init", "-q"], ["git", "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "--allow-empty", "-m", "x"]):
        subprocess.run(cmd, cwd=repo, check=True, capture_output=True)
    a = tmp_path / "pypi"
    make_wheel(a)
    make_sdist(a)
    r = run(a, None, extra_env={"REPO_URL": str(repo)})
    assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)
    assert "tag" in r.stderr and f"v{VER}" in r.stderr


# ── 4. the sdist sha check ───────────────────────────────────────────────

def test_the_sdist_sha_is_not_applicable_when_the_repack_is_not_live(tmp_path):
    a, b = pair(tmp_path)
    r = run(a, b, live="no")
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "sdist sha256: NOT APPLICABLE" in r.stdout


def test_the_sdist_sha_defaults_to_not_applicable(tmp_path):
    a, b = pair(tmp_path)
    r = run(a, b)
    assert r.returncode == 0 and "NOT APPLICABLE" in r.stdout


def test_equal_sdist_sha_passes_when_the_repack_is_live(tmp_path):
    a, b = pair(tmp_path)
    (b / f"{PKG}-{VER}.tar.gz").write_bytes((a / f"{PKG}-{VER}.tar.gz").read_bytes())
    r = run(a, b, live="yes")
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "sdist sha256: equal" in r.stdout


def test_a_different_sdist_sha_fails_when_the_repack_is_live(tmp_path):
    a, b = pair(tmp_path)  # same content, different bytes
    r = run(a, b, live="yes")
    assert r.returncode == 1, (r.stdout, r.stderr)
    assert "sdist sha256" in r.stderr and "differ" in r.stderr


# ── 5. the fetch path, with a stub curl standing in for PyPI ─────────────

def _stub_curl(tmp_path, files, lie_about=None):
    """A curl that serves pypi.org's JSON for the version and the files from a directory."""
    stub = tmp_path / "stubbin"
    stub.mkdir(exist_ok=True)
    urls = []
    for f in files:
        digest = hashlib.sha256(f.read_bytes()).hexdigest() if f.name != lie_about else "0" * 64
        urls.append({"filename": f.name, "url": f"http://stub.invalid/{f.name}",
                     "packagetype": "bdist_wheel" if f.suffix == ".whl" else "sdist",
                     "digests": {"sha256": digest}})
    (tmp_path / "pypi.json").write_text(json.dumps({"urls": urls}))
    (stub / "curl").write_text(f"""#!/usr/bin/env python3
import shutil, sys
a = sys.argv[1:]
out = a[a.index("-o") + 1] if "-o" in a else None
url = next(x for x in a if x.startswith("http"))
src = {str(tmp_path / "pypi.json")!r} if url.endswith("/json") else {str(files[0].parent)!r} + "/" + url.rsplit("/", 1)[1]
if out:
    shutil.copy(src, out)
else:
    sys.stdout.write(open(src).read())
""")
    (stub / "curl").chmod(0o755)
    return str(stub)


def test_the_fetch_path_downloads_from_the_listed_urls_and_compares(tmp_path):
    a, b = pair(tmp_path)
    r = run(None, b, path_prefix=_stub_curl(tmp_path, sorted(a.iterdir())))
    assert r.returncode == 0, (r.stdout, r.stderr)
    assert "content equal" in r.stdout


def test_a_download_with_the_wrong_sha256_is_refused(tmp_path):
    a, b = pair(tmp_path)
    r = run(None, b, path_prefix=_stub_curl(tmp_path, sorted(a.iterdir()), lie_about=f"{PKG}-{VER}-py3-none-any.whl"))
    assert r.returncode == 2, (r.stdout, r.stderr)
    assert "sha256" in r.stderr and "REFUSED" in r.stderr


def test_a_failed_download_is_refused_not_passed(tmp_path):
    stub = tmp_path / "stubbin"
    stub.mkdir()
    (stub / "curl").write_text("#!/bin/sh\nexit 22\n")
    (stub / "curl").chmod(0o755)
    _, b = pair(tmp_path)
    r = run(None, b, path_prefix=str(stub))
    assert r.returncode == 2 and "REFUSED" in r.stderr


def test_the_script_exists_and_is_strict_shell():
    assert SCRIPT.is_file(), SCRIPT
    text = SCRIPT.read_text()
    assert text.startswith("#!/usr/bin/env bash") and "set -euo pipefail" in text


def test_a_diff_that_itself_fails_is_refused_never_passed(tmp_path):
    """diff exits 1 for a difference and 2 for trouble. Trouble prints nothing on stdout, so a
    script that only reads the output would call it equal."""
    stub = tmp_path / "diffbin"
    stub.mkdir()
    (stub / "diff").write_text("#!/bin/sh\necho 'diff: cannot read' >&2\nexit 2\n")
    (stub / "diff").chmod(0o755)
    a, b = pair(tmp_path)
    r = run(a, b, path_prefix=str(stub))
    assert r.returncode == 2, (r.returncode, r.stdout, r.stderr)
    assert "REFUSED" in r.stderr and "diff failed" in r.stderr


def test_the_diff_stub_control_a_diff_that_exits_one_with_output_fails_not_refuses(tmp_path):
    """Pairs with the row above, so that row is not a script that refuses on any stub."""
    stub = tmp_path / "diffbin"
    stub.mkdir()
    (stub / "diff").write_text("#!/bin/sh\necho \"Files $2/x.py and $3/x.py differ\"\nexit 1\n")
    (stub / "diff").chmod(0o755)
    a, b = pair(tmp_path)
    r = run(a, b, path_prefix=str(stub))
    assert r.returncode == 1, (r.returncode, r.stdout, r.stderr)
