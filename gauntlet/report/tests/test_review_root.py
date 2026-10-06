"""GAUNTLET_REVIEW_ROOT: one key, and an unset or bad value NARROWS, never widens.

T9 ruling 2026-09-23 (a). Each row runs a fresh interpreter, because the key is
read once at import and the suite's own conftest has already set it here.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

REPORT = pathlib.Path(__file__).resolve().parents[1]
BOUNDARY = REPORT.parent / "boundary"


def _probe(value):
    env = {k: v for k, v in os.environ.items() if k != "GAUNTLET_REVIEW_ROOT"}
    if value is not None:
        env["GAUNTLET_REVIEW_ROOT"] = value
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys,json;sys.path.insert(0,sys.argv[1]);import review_root as r;"
         "print(json.dumps([str(r.ROOT),str(r.ABSENT)]))", str(BOUNDARY)],
        env=env, capture_output=True, text=True, check=True, cwd="/")
    return json.loads(out.stdout)


@pytest.mark.parametrize("value", [None, "", "   ", "relative/dir", "."])
def test_unset_empty_or_relative_is_the_absent_root_never_the_cwd(value):
    root, absent = _probe(value)
    assert root == absent
    assert not pathlib.Path(absent).exists(), "the default must not exist"


def test_an_absolute_value_is_obeyed(tmp_path):
    root, _ = _probe(str(tmp_path))
    assert root == str(tmp_path)


def test_a_clean_checkout_produces_the_honest_refusal_not_a_crash(tmp_path):
    """No key, as in CI: produce still writes a schema-valid REFUSED report."""
    env = {k: v for k, v in os.environ.items() if k != "GAUNTLET_REVIEW_ROOT"}
    out = subprocess.run(
        [sys.executable, "-c",
         "import sys,json;sys.path.insert(0,sys.argv[1]);import produce,validate;"
         "r,c=produce.build(run_id='clean');"
         "print(json.dumps([c,r['run']['outcome'],r['coverage'].get('reason_code'),"
         "len(validate.validate_report(r))]))", str(REPORT)],
        env=env, capture_output=True, text=True, cwd=str(tmp_path))
    assert out.returncode == 0, out.stderr[-800:]
    code, outcome, reason, findings = json.loads(out.stdout)
    assert (code != 0, outcome, reason, findings) == (True, "refused", "EVIDENCE_UNBOUND", 0)


@pytest.mark.skipif(hasattr(os, "geteuid") and os.geteuid() == 0,
                    reason="root can list a mode 000 folder, so the fixture proves nothing")
def test_a_set_but_unlistable_corpus_is_the_same_refusal_with_the_os_text_on_stderr(tmp_path):
    """A review folder that exists and cannot be listed (a privacy block on the Mac,
    mode 000 here) ends in the designed refusal, not a traceback.

    Before: `plan_corpus` raised PermissionError at `materialised.iterdir()`, the run
    died with rc 1 and no report. The reason code stays EVIDENCE_UNBOUND and the panel
    carries no sentence (a free form string has nothing in the report to bind it), so the
    "cannot be listed" text with the OS error goes to stderr, never into the report, and
    the path is not in it.
    """
    corpus = tmp_path / "GATE3_DESIGN_REVIEW_2026-09-13" / "materialized"
    (corpus / "v1").mkdir(parents=True)
    corpus.chmod(0)
    try:
        if os.access(corpus, os.R_OK):
            pytest.skip("this filesystem still lets the current user list a mode 000 folder")
        env = dict(os.environ, GAUNTLET_REVIEW_ROOT=str(tmp_path))
        out = subprocess.run(
            [sys.executable, "-c",
             "import sys,json;sys.path.insert(0,sys.argv[1]);import produce,validate;"
             "r,c=produce.build(run_id='unreadable');"
             "print(json.dumps([c,r['run']['outcome'],r['coverage'].get('reason_code'),"
             "sorted(r['coverage']),len(validate.validate_report(r))]))", str(REPORT)],
            env=env, capture_output=True, text=True, cwd=str(tmp_path))
    finally:
        corpus.chmod(0o755)
    assert out.returncode == 0, out.stderr[-800:]
    code, outcome, reason, keys, findings = json.loads(out.stdout)
    assert (code, outcome, reason, findings) == (3, "refused", "EVIDENCE_UNBOUND", 0)
    assert keys == ["reason_code", "state"], keys              # no free form detail in the panel
    assert "cannot be listed" in out.stderr and "PermissionError" in out.stderr, out.stderr
    assert str(tmp_path) not in out.stderr, "the console text must not carry the path"
