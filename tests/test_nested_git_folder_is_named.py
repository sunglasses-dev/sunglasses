"""A `.git` folder below the scan root is named in the report, not dropped without a word.

The walk does not enter dependency, build and version-control folders, and names each one
it left out under `excluded_folders`. The root's own `.git` is the tree's metadata and
stays unnamed, but a `.git` folder further down (an archive that unpacks a vendored
copy of another repository, for instance) is content: skipping it silently let a scan
report a complete inspection of a tree it had only partly read.
"""
import json
import subprocess
import sys

import pytest


def _scan(path, fmt):
    return subprocess.run([sys.executable, "-m", "sunglasses", "scan", "--dir", str(path), "-o", fmt],
                          capture_output=True, text=True, timeout=120)


def _tree(tmp_path, nested):
    root = tmp_path / "t"
    (root / "pkg" / "sub").mkdir(parents=True)
    (root / "ok.md").write_text("clean notes\n", encoding="utf-8")
    (root / "build").mkdir()
    (root / "build" / "x.md").write_text("generated\n", encoding="utf-8")
    if nested:
        (root / "pkg" / "sub" / ".git").mkdir()
        (root / "pkg" / "sub" / ".git" / "note.md").write_text("held\n", encoding="utf-8")
    return root


def test_a_nested_git_folder_is_named_in_json(tmp_path):
    out = _scan(_tree(tmp_path, nested=True), "json")
    doc = json.loads(out.stdout)
    assert any(name.replace("\\", "/") == "pkg/sub/.git" for name in doc["excluded_folders"])


def test_a_nested_git_folder_is_named_in_sarif(tmp_path):
    out = _scan(_tree(tmp_path, nested=True), "sarif")
    props = json.loads(out.stdout)["runs"][0]["properties"]
    assert any(name.replace("\\", "/") == "pkg/sub/.git" for name in props["excludedFolders"])


def test_the_roots_own_git_folder_stays_unnamed(tmp_path):
    root = _tree(tmp_path, nested=False)
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    doc = json.loads(_scan(root, "json").stdout)
    assert [n for n in doc["excluded_folders"] if n.endswith(".git")] == []


def test_other_pruned_folders_are_still_named(tmp_path):
    doc = json.loads(_scan(_tree(tmp_path, nested=True), "json").stdout)
    assert "build" in doc["excluded_folders"]


def test_the_human_report_names_it(tmp_path):
    out = _scan(_tree(tmp_path, nested=True), "human")
    assert ".git" in out.stdout and "Folders not entered" in out.stdout
