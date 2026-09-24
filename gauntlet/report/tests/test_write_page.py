"""The landing writer: the page the site receives, and what it refuses to write.

Design note: warroom/GAUNTLET_LANDING_WRITER_2026-09-23.md (T9 rulings 17:2x).

Four promises, each with a row that fails without it:

  THE SELECTION SURVIVES THE PROCESS. publish.Published refuses an older attempt
  in memory; a nightly and a manual rerun are two processes, so the refusal has
  to live in a file both read. Proven here with a REAL second process.

  THE REFUSAL PAGE IS THE DEFAULT. An unreviewed map is not an error that leaves
  the old page up; it writes a page that says refused, why, and when.

  AN INVALID ARTIFACT WRITES NOTHING. The page already up is left byte for byte,
  and ages out on the reader's side.

  EXPIRY IS READ FROM THE PERSISTED HISTORY, so a writer that stopped entirely
  is still noticed.
"""
import copy
import datetime
import json
import pathlib
import re
import subprocess
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import classify     # noqa: E402
import produce      # noqa: E402
import publish      # noqa: E402
import write_page   # noqa: E402

UTC = datetime.timezone.utc


@pytest.fixture(scope="module")
def honest():
    report, _ = produce.build(run_id="writer-fixture")
    return report


def _at(report, finished, measured=None, run_id=None):
    r = copy.deepcopy(report)
    r["run"]["finished_at"] = finished
    r["freshness"]["measured_at"] = measured or finished
    if run_id:
        r["run"]["id"] = run_id
    return r


def _dump(tmp_path, name, report):
    path = tmp_path / name
    path.write_text(json.dumps(report))
    return path


def _lines(path):
    return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]


def test_the_page_lands_in_the_landing_checkout_and_the_attempt_is_recorded(honest, tmp_path):
    landing, attempts = tmp_path / "landing", tmp_path / "attempts.jsonl"
    landing.mkdir()
    report = _at(honest, "2026-09-23T03:30:00+00:00", run_id="night-1")
    page = write_page.write(_dump(tmp_path, "r.json", report), landing, attempts)
    assert page == landing / "gauntlet.html"
    assert 'data-bound="run.id">night-1<' in page.read_text()
    [line] = _lines(attempts)
    assert line["run_id"] == "night-1" and line["selected"] is True
    assert len(line["report_sha256"]) == 64


def test_an_older_attempt_from_ANOTHER_PROCESS_is_refused_and_still_recorded(honest, tmp_path):
    landing, attempts = tmp_path / "landing", tmp_path / "attempts.jsonl"
    landing.mkdir()
    newer = _dump(tmp_path, "newer.json",
                  _at(honest, "2026-09-23T04:00:00+00:00", run_id="newer"))
    older = _dump(tmp_path, "older.json",
                  _at(honest, "2026-09-23T03:00:00+00:00", run_id="older"))
    # The newer attempt lands in a separate interpreter: nothing is shared
    # between the two but the history file.
    done = subprocess.run(
        [sys.executable, str(HERE.parent / "write_page.py"), "--report", str(newer),
         "--landing", str(landing), "--attempts", str(attempts)],
        capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    before = (landing / "gauntlet.html").read_bytes()
    with pytest.raises(publish.StaleOverwrite):
        write_page.write(older, landing, attempts)
    assert (landing / "gauntlet.html").read_bytes() == before, "the newer page stays up"
    lines = _lines(attempts)
    assert [(x["run_id"], x["selected"]) for x in lines] == [("newer", True), ("older", False)], \
        "a refused attempt is still part of the history"


def test_rewriting_the_SAME_attempt_is_a_retry_not_a_stale_overwrite(honest, tmp_path):
    landing, attempts = tmp_path / "landing", tmp_path / "attempts.jsonl"
    landing.mkdir()
    report = _dump(tmp_path, "r.json", _at(honest, "2026-09-23T03:30:00+00:00"))
    write_page.write(report, landing, attempts)
    write_page.write(report, landing, attempts)
    assert len(_lines(attempts)) == 1, "a retried PR must not grow the history"


def test_a_DIFFERENT_report_with_the_same_finish_time_is_refused(honest, tmp_path):
    landing, attempts = tmp_path / "landing", tmp_path / "attempts.jsonl"
    landing.mkdir()
    write_page.write(_dump(tmp_path, "a.json", _at(honest, "2026-09-23T03:30:00+00:00",
                                                   run_id="a")), landing, attempts)
    with pytest.raises(publish.StaleOverwrite):
        write_page.write(_dump(tmp_path, "b.json", _at(honest, "2026-09-23T03:30:00+00:00",
                                                       run_id="b")), landing, attempts)


def test_a_refusal_replaces_a_green_page_latest_attempt_not_latest_success(honest, tmp_path):
    landing, attempts = tmp_path / "landing", tmp_path / "attempts.jsonl"
    landing.mkdir()
    green = _at(honest, "2026-09-23T03:00:00+00:00", run_id="green")
    green["run"].update({"outcome": "complete", "exit_code": 0})
    green["run"].pop("reason_code", None)
    refused = _at(honest, "2026-09-23T04:00:00+00:00", run_id="refused")
    refused["run"].update({"outcome": "refused", "exit_code": 3, "reason_code": "RUN_REFUSED"})
    write_page.write(_dump(tmp_path, "g.json", green), landing, attempts)
    write_page.write(_dump(tmp_path, "r.json", refused), landing, attempts)
    page = (landing / "gauntlet.html").read_text()
    assert 'data-bound="run.outcome">refused<' in page


def test_an_UNREVIEWED_map_still_writes_the_refusal_page(tmp_path, monkeypatch):
    """The Oct 12 case if the map review slips: a page that says so, not a blank."""
    unreviewed = tmp_path / "capability_map.json"
    raw = json.loads(pathlib.Path(classify.MAP_PATH).read_text())
    raw["review_state"] = "unreviewed"
    raw.pop("review_receipt", None)
    unreviewed.write_text(json.dumps(raw))
    monkeypatch.setattr(classify, "MAP_PATH", unreviewed)
    report, code = produce.build(run_id="unreviewed-night")
    assert code != 0 and report["run"]["outcome"] == "refused"
    landing, attempts = tmp_path / "landing", tmp_path / "attempts.jsonl"
    landing.mkdir()
    page = write_page.write(_dump(tmp_path, "r.json", report), landing, attempts).read_text()
    assert "REFUSED" in page.split("<title>")[0], "the meta description says refused"
    assert 'data-bound="run.outcome">refused<' in page
    assert "unverified" in page.split("<script>")[0]


def test_an_INVALID_artifact_writes_nothing_and_records_nothing(honest, tmp_path):
    landing, attempts = tmp_path / "landing", tmp_path / "attempts.jsonl"
    landing.mkdir()
    write_page.write(_dump(tmp_path, "ok.json", _at(honest, "2026-09-23T03:00:00+00:00")),
                     landing, attempts)
    before = (landing / "gauntlet.html").read_bytes()
    broken = _at(honest, "2026-09-23T04:00:00+00:00")
    broken["run"]["outcome"] = "refused"
    broken["run"]["exit_code"] = 0          # a refusal that exits zero is invalid (C4)
    with pytest.raises(write_page.render.WillNotRender):
        write_page.write(_dump(tmp_path, "bad.json", broken), landing, attempts)
    assert (landing / "gauntlet.html").read_bytes() == before
    assert len(_lines(attempts)) == 1


def test_the_cli_refuses_with_a_nonzero_exit_and_says_why(honest, tmp_path):
    landing, attempts = tmp_path / "landing", tmp_path / "attempts.jsonl"
    landing.mkdir()
    broken = _at(honest, "2026-09-23T04:00:00+00:00")
    broken["run"]["exit_code"] = 0
    broken["run"]["outcome"] = "refused"
    done = subprocess.run(
        [sys.executable, str(HERE.parent / "write_page.py"), "--report",
         str(_dump(tmp_path, "bad.json", broken)), "--landing", str(landing),
         "--attempts", str(attempts)], capture_output=True, text=True)
    assert done.returncode != 0
    assert "REFUSED" in done.stderr
    assert not (landing / "gauntlet.html").exists()


def test_a_landing_that_is_not_a_directory_is_refused(honest, tmp_path):
    with pytest.raises(write_page.WriterRefused):
        write_page.write(_dump(tmp_path, "r.json", _at(honest, "2026-09-23T03:00:00+00:00")),
                         tmp_path / "nowhere", tmp_path / "attempts.jsonl")


@pytest.mark.parametrize("hours_ago, expired", [(35, False), (37, True)])
def test_expiry_is_read_from_the_PERSISTED_history(honest, tmp_path, hours_ago, expired):
    landing, attempts = tmp_path / "landing", tmp_path / "attempts.jsonl"
    landing.mkdir()
    now = datetime.datetime(2026, 9, 24, 12, tzinfo=UTC)
    when = (now - datetime.timedelta(hours=hours_ago)).isoformat()
    write_page.write(_dump(tmp_path, "r.json", _at(honest, when)), landing, attempts)
    assert write_page.expired(attempts, now=now) is expired


def test_no_history_at_all_is_expired_not_green(tmp_path):
    assert write_page.expired(tmp_path / "absent.jsonl") is True


def test_a_refused_attempt_does_not_refresh_expiry(honest, tmp_path):
    """Only the SELECTED attempt is what is up; a refused straggler is not."""
    landing, attempts = tmp_path / "landing", tmp_path / "attempts.jsonl"
    landing.mkdir()
    now = datetime.datetime(2026, 9, 24, 12, tzinfo=UTC)
    old = (now - datetime.timedelta(hours=40)).isoformat()
    older = (now - datetime.timedelta(hours=41)).isoformat()
    write_page.write(_dump(tmp_path, "a.json", _at(honest, old, run_id="a")), landing, attempts)
    stale = _at(honest, older, measured=now.isoformat(), run_id="b")
    with pytest.raises(publish.StaleOverwrite):
        write_page.write(_dump(tmp_path, "b.json", stale), landing, attempts)
    assert write_page.expired(attempts, now=now) is True


def test_the_page_declares_its_language_as_the_landing_lint_requires(honest, tmp_path):
    """Measured 2026-09-23: the landing `site_lint` refused the written page for
    `<html> has no lang attribute`, and the dry run hid it by linting the tree
    with the page staged OUT of it."""
    landing = tmp_path / "landing"
    landing.mkdir()
    page = write_page.write(_dump(tmp_path, "r.json", _at(honest, "2026-09-23T03:00:00+00:00")),
                            landing, tmp_path / "attempts.jsonl").read_text()
    assert re.search(r'<html[^>]*\blang="en"', page)


def test_an_UNBOUND_identity_says_not_bound_never_the_word_None(tmp_path, monkeypatch):
    """Measured 2026-09-23 22:5x on the first fresh refusal page: "Capability map
    revision None, review state None". A refused map leaves both identities null,
    render printed Python's repr, and the landing dry run passed it because the
    bound text "None" equals str(None). A null is unbound, and says so in words."""
    unreviewed = tmp_path / "capability_map.json"
    raw = json.loads(pathlib.Path(classify.MAP_PATH).read_text())
    raw["review_state"] = "unreviewed"
    raw.pop("review_receipt", None)
    unreviewed.write_text(json.dumps(raw))
    monkeypatch.setattr(classify, "MAP_PATH", unreviewed)
    report, _ = produce.build(run_id="unbound-identities")
    assert report["identities"]["capability_map_revision"] is None
    landing = tmp_path / "landing"
    landing.mkdir()
    page = write_page.write(_dump(tmp_path, "r.json", report), landing,
                            tmp_path / "attempts.jsonl").read_text()
    visible = re.sub(r"<script.*?</script>", "", page, flags=re.S)
    assert not re.search(r">\s*None\s*<", visible), "a null rendered as the word None"
    assert 'data-bound="identities.capability_map_revision"' not in visible, \
        "an unbound value must not be dressed as a bound figure"
    inputs = visible.split('id="inputs"')[1]
    assert inputs.count("not bound") == 2


def test_the_public_page_names_no_internal_session(tmp_path, monkeypatch):
    """The first fresh refusal page told the public "Budget policy is T9's".
    T8/T9/T10/T11 are our terminals, not anything a reader can look up."""
    unreviewed = tmp_path / "capability_map.json"
    raw = json.loads(pathlib.Path(classify.MAP_PATH).read_text())
    raw["review_state"] = "unreviewed"
    raw.pop("review_receipt", None)
    unreviewed.write_text(json.dumps(raw))
    monkeypatch.setattr(classify, "MAP_PATH", unreviewed)
    report, _ = produce.build(run_id="no-session-names")
    landing = tmp_path / "landing"
    landing.mkdir()
    page = write_page.write(_dump(tmp_path, "r.json", report), landing,
                            tmp_path / "attempts.jsonl").read_text()
    visible = re.sub(r"<script.*?</script>", "", page, flags=re.S)
    assert not re.findall(r"\bT(?:8|9|10|11)\b", visible)
