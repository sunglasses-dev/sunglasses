"""`produce.py --run PATH --out PATH`: the report is built from a run document anywhere and
written anywhere, so a scheduled run in a clean checkout leaves that checkout clean.

The tracked report, `evidence/nightly.json`, and the run document beside produce.py were the two
files a run changed in the tree; the nightly refuses a dirty worktree, so wiring the report build
into it had no safe place to put either. These rows tell the two apart by the reason code the report
carries: a run document that is not valid JSON is RUN_REFUSED, an absent one is EXEC_NONE (the
build refuses either way today, for different reasons).
"""
import json
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import produce  # noqa: E402

BROKEN = "{ this is not json"
UNREADABLE, ABSENT = "RUN_REFUSED", "EXEC_NONE"


def _reason(path):
    return json.loads(pathlib.Path(path).read_text())["run"]["reason_code"]


@pytest.fixture()
def tree_report(tmp_path, monkeypatch):
    """The tracked report path, swapped for a scratch file so a stray write is visible."""
    path = tmp_path / "tree" / "nightly.json"
    path.parent.mkdir()
    path.write_text("UNTOUCHED\n")
    monkeypatch.setattr(produce, "REPORT_PATH", path)
    return path


def test_out_writes_there_and_never_to_the_tree_report(tmp_path, tree_report):
    out = tmp_path / "elsewhere" / "report.json"
    produce.main(["--run", str(tmp_path / "absent.json"), "--out", str(out)])
    assert out.is_file() and tree_report.read_text() == "UNTOUCHED\n"
    assert _reason(out) == ABSENT


def test_run_names_the_file_that_is_read(tmp_path, tree_report, monkeypatch):
    broken = tmp_path / "run.json"
    broken.write_text(BROKEN)
    monkeypatch.setattr(produce, "EXECUTION_RUN", tmp_path / "absent.json")
    produce.main(["--run", str(broken), "--out", str(tmp_path / "r.json")])
    assert _reason(tmp_path / "r.json") == UNREADABLE


def test_run_given_means_the_in_tree_run_file_is_not_consulted(tmp_path, tree_report, monkeypatch):
    broken = tmp_path / "tree_run.json"
    broken.write_text(BROKEN)
    monkeypatch.setattr(produce, "EXECUTION_RUN", broken)       # a dirty tree
    produce.main(["--run", str(tmp_path / "absent.json"), "--out", str(tmp_path / "r.json")])
    assert _reason(tmp_path / "r.json") == ABSENT


def test_without_flags_the_old_paths_are_still_used(tmp_path, tree_report, monkeypatch):
    broken = tmp_path / "tree_run.json"
    broken.write_text(BROKEN)
    monkeypatch.setattr(produce, "EXECUTION_RUN", broken)
    assert produce.main([]) == 3
    assert _reason(tree_report) == UNREADABLE


def _unbound(path):
    cov = json.loads(pathlib.Path(path).read_text())["coverage"]
    return cov.get("execution_reason_code") == "EVIDENCE_UNBOUND"


def test_a_readable_run_given_by_flag_is_the_one_that_is_examined(tmp_path, tree_report, monkeypatch):
    """A readable document that binds to nothing is set aside with a reason; an absent one is not.
    Which of the two the build saw tells which path it read, not only which it checked exists."""
    odd = tmp_path / "odd.json"
    odd.write_text('{"x": 1}')
    absent = tmp_path / "absent.json"
    monkeypatch.setattr(produce, "EXECUTION_RUN", absent)
    produce.main(["--run", str(odd), "--out", str(tmp_path / "given.json")])
    monkeypatch.setattr(produce, "EXECUTION_RUN", odd)
    produce.main(["--run", str(absent), "--out", str(tmp_path / "other.json")])
    assert _unbound(tmp_path / "given.json") and not _unbound(tmp_path / "other.json")
