"""The standalone verifier, run the way verify.py says it is handed out.

verify.py's docstring names the files an auditor needs beside it. This runs
exactly that list, copied into an empty directory, under `python -I` (no
site, no PYTHONPATH, no script directory on the path, so `sunglasses` cannot
be found), on a log written by the real writer and signed with a real key.
It failed from 2026-10-21 (`_fs.py` began to import `_shown.py`, the docstring
list did not say so) until the list was corrected.
"""
import pathlib
import re
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
PKG = HERE.parent
sys.path.insert(0, str(PKG))

import chain                                               # noqa: E402
import keys                                                # noqa: E402

DRIVER = (
    "import sys, pathlib\n"
    "sys.path.insert(0, sys.argv[1])\n"
    "import verify\n"
    "assert 'sunglasses' not in sys.modules\n"
    "rep = verify.verify_log(sys.argv[2], pathlib.Path(sys.argv[3]).read_bytes())\n"
    "print(rep.results['chain_integrity'], rep.results['lifecycle'])\n"
)


def _documented_files():
    """The names verify.py's docstring says the bundle needs, plus verify.py."""
    text = re.sub(r"\s+", " ", (PKG / "verify.py").read_text(encoding="utf-8"))
    said = re.search(r"needs this directory's (.*?) and PyCA's", text)
    assert said, "verify.py no longer says which files the standalone bundle needs"
    return {"verify.py"} | set(re.findall(r"`([A-Za-z_]+\.py)`", said.group(1)))


@pytest.fixture
def signed_log(tmp_path):
    home = tmp_path / "home"
    fingerprint = keys.init(home)
    writer = chain.Chain(home / "receipts" / "chain", keys.load(home), producer="hook")
    for n in range(3):
        writer.write([{"event": "in_flight", "body": {"eval_id": f"e{n}"}},
                      {"event": "decision", "body": {"eval_id": f"e{n}"}}])
    writer.close()
    return home / "receipts" / "chain", keys.public_path(home, fingerprint)


def _run(bundle, log, public):
    return subprocess.run([sys.executable, "-I", "-c", DRIVER, str(bundle), str(log), str(public)],
                          capture_output=True, text=True, timeout=120, cwd=str(bundle))


def _bundle(tmp_path, names):
    bundle = tmp_path / "bundle"
    bundle.mkdir()
    for name in names:
        (bundle / name).write_bytes((PKG / name).read_bytes())
    return bundle


def test_the_documented_files_verify_a_real_signed_log_under_python_dash_i(tmp_path, signed_log):
    log, public = signed_log
    names = _documented_files()
    assert len(names) == 5, names           # verify + the four the docstring names
    out = _run(_bundle(tmp_path, names), log, public)
    assert out.returncode == 0, out.stderr[-600:]
    assert out.stdout.split() == ["CHAIN_OK", "LIFECYCLE_COMPLETE"]


@pytest.mark.parametrize("missing", ["wire.py", "codes.py", "_fs.py", "_shown.py"])
def test_every_documented_file_is_needed(tmp_path, signed_log, missing):
    """Each name on the list earns its place: without it the bundle does not import."""
    log, public = signed_log
    names = _documented_files() - {missing}
    assert missing in _documented_files()
    out = _run(_bundle(tmp_path, names), log, public)
    assert out.returncode != 0 and "Error" in out.stderr
