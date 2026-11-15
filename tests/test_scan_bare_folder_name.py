"""`sunglasses scan <name>` where <name> is a folder that exists.

A single positional argument that names a folder is a usage error, whether it is
written `./docs` or `docs`. The error names `--dir`, the option that scans a folder,
and `--text`, the option that scans the word. Nothing is scanned and no verdict is
printed. A word that is not a folder is still scanned as text, and `--text` still
scans the word when a folder of that name exists.
"""
import json
import os
import subprocess
import sys

import pytest


_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _scan(cwd, *argv):
    # The folder under test is the cwd, so the package under test is put on the path.
    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", NO_COLOR="1", PYTHONPATH=_ROOT)
    return subprocess.run([sys.executable, "-m", "sunglasses.cli", "scan", *argv],
                          cwd=cwd, env=env, capture_output=True, text=True, timeout=120)


@pytest.fixture
def work(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.txt").write_text("hello")
    return tmp_path


@pytest.mark.parametrize("spelling", ["docs", "./docs", "docs/"])
def test_a_folder_name_is_a_usage_error_in_every_spelling(work, spelling):
    done = _scan(work, spelling)
    assert done.returncode == 2, (done.returncode, done.stdout, done.stderr)
    text = done.stdout + done.stderr
    assert "is a directory" in text
    assert "--dir" in text
    assert "--text" in text
    assert "PASS" not in text


def test_the_bare_name_and_the_dotted_name_give_the_same_error(work):
    bare, dotted = _scan(work, "docs"), _scan(work, "./docs")
    assert bare.returncode == dotted.returncode == 2
    assert (bare.stdout + bare.stderr).replace("./docs", "docs") == \
        (dotted.stdout + dotted.stderr).replace("./docs", "docs")


def test_the_error_is_a_document_under_json(work):
    done = _scan(work, "docs", "--json")
    assert done.returncode == 2, (done.stdout, done.stderr)
    document = json.loads(done.stdout)
    assert document["scanned"] is False
    assert document["exit_code"] == 2
    assert document["decision"] is None
    assert "is a directory" in document["error"]
    assert "--dir docs" in document["hint"]
    assert "--text" in document["hint"]
    assert "PASS" not in done.stdout + done.stderr


def test_a_word_that_is_not_a_folder_is_still_scanned(work):
    done = _scan(work, "hello")
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert "PASS" in done.stdout + done.stderr


def test_text_scans_the_word_when_a_folder_of_that_name_exists(work):
    done = _scan(work, "--text", "docs")
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert "PASS" in done.stdout + done.stderr


def test_dir_scans_the_folder(work):
    done = _scan(work, "--dir", "docs", "--json")
    assert done.returncode == 0, (done.stdout, done.stderr)
    assert json.loads(done.stdout)


def test_a_file_name_without_a_slash_is_still_promoted_to_a_file_scan(work):
    (work / "note.txt").write_text("hello")
    done = _scan(work, "note.txt")
    assert done.returncode == 0, (done.stdout, done.stderr)
