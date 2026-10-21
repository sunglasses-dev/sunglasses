"""scripts/stats_last_updated.py: the one edit the release workflow's stats job makes.

A release uploaded by the workflow never wrote `last_updated`, so `released` ran
ahead of it and the site stamp gate stopped. The script reads the wheel's upload
time from PyPI and writes `last_updated` (Pacific time) and `last_updated_by`.
Every refusal below must leave the file byte-for-byte alone, because a wrong
stamp that merges is worse than a missing one.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("stats_last_updated", ROOT / "scripts" / "stats_last_updated.py")
sla = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sla)

V = "0.6.10"
UPLOAD = "2026-10-19T14:26:03.195413Z"          # 07:26:03 Pacific, the 19th
STATS = """{
  "version": "0.6.10",
  "team_size": 5,
  "last_updated": "2026-10-15T16:50:14-07:00",
  "last_updated_by": "sunglasses-publish-sh",
  "released": "%s"
}
"""


def served(upload=UPLOAD):
    return lambda url: {"urls": [{"packagetype": "sdist", "upload_time_iso_8601": "2000-01-01T00:00:00Z"},
                                 {"packagetype": "bdist_wheel", "upload_time_iso_8601": upload}]}


def tree(tmp_path, text):
    (tmp_path / "stats").mkdir()
    path = tmp_path / "stats" / "current.json"
    path.write_text(text)
    return path


def no_sleep(_):
    raise AssertionError("slept when it should not have")


def test_writes_exactly_the_two_fields_from_the_wheel_time(tmp_path):
    path = tree(tmp_path, STATS % "2026-10-19")
    code, message = sla.stamp(tmp_path, V, fetch=served(), sleep=no_sleep)
    assert code == 0, message
    new = path.read_text()
    assert new == (STATS % "2026-10-19").replace("2026-10-15T16:50:14-07:00", "2026-10-19T07:26:03-07:00") \
        .replace("sunglasses-publish-sh", "release.yml")
    assert json.loads(new)["last_updated"] == "2026-10-19T07:26:03-07:00"


def test_uses_the_wheel_not_the_sdist(tmp_path):
    tree(tmp_path, STATS % "2026-10-19")
    code, message = sla.stamp(tmp_path, V, fetch=served(), sleep=no_sleep)
    assert code == 0 and "2026-10-19T14:26:03Z" in message, message


def test_a_late_evening_upload_is_the_pacific_date_not_the_utc_date(tmp_path):
    # 2026-10-20 03:30 UTC is still the 19th in Pacific time.
    path = tree(tmp_path, STATS % "2026-10-19")
    code, message = sla.stamp(tmp_path, V, fetch=served("2026-10-20T03:30:00.5Z"), sleep=no_sleep)
    assert code == 0, message
    assert json.loads(path.read_text())["last_updated"] == "2026-10-19T20:30:00-07:00"


def test_already_stamped_is_nothing_to_do(tmp_path):
    stamped = (STATS % "2026-10-19").replace("2026-10-15T16:50:14-07:00", "2026-10-19T07:26:03-07:00") \
        .replace("sunglasses-publish-sh", "release.yml")
    path = tree(tmp_path, stamped)
    code, message = sla.stamp(tmp_path, V, fetch=served(), sleep=no_sleep)
    assert code == 3 and "NOTHING TO DO" in message, message
    assert path.read_text() == stamped


@pytest.mark.parametrize("text, needle", [
    ((STATS % "2026-10-19").replace('"version": "0.6.10"', '"version": "0.6.9"'), "did not bump"),
    (STATS % "2026-10-18", "Pacific upload date"),
    ((STATS % "2026-10-19").replace('"last_updated_by": "sunglasses-publish-sh",', ""), "top-level strings"),
    ((STATS % "2026-10-19").replace('"team_size": 5,',
                                    '"team_size": 5, "last_updated": "2026-01-01T00:00:00-08:00",'), "strict JSON"),
    # a root field plus a nested copy of the same name: the depth-blind edit would be ambiguous
    ((STATS % "2026-10-19").replace('"team_size": 5,', '"team_size": {"last_updated": "z"},'), "exactly one"),
    # the only timestamp is nested: the text edit would hit it, the root still has none
    ('{\n  "version": "0.6.10",\n  "nested": {\n    "last_updated": "x",\n    "last_updated_by": "y"\n  },\n'
     '  "released": "2026-10-19"\n}\n', "top-level strings"),
    # a root field that is not a string
    ((STATS % "2026-10-19").replace('"last_updated_by": "sunglasses-publish-sh"', '"last_updated_by": null'), "top-level strings"),
])
def test_refusals_leave_the_file_untouched(tmp_path, text, needle):
    path = tree(tmp_path, text)
    code, message = sla.stamp(tmp_path, V, fetch=served(), sleep=no_sleep)
    assert code == 2 and needle in message, message
    assert path.read_text() == text


def test_no_wheel_on_pypi_is_refused_after_the_wait(tmp_path):
    path = tree(tmp_path, STATS % "2026-10-19")
    sdist_only = lambda url: {"urls": [{"packagetype": "sdist", "upload_time_iso_8601": UPLOAD}]}
    clock = iter(range(0, 1000, 100))
    naps = []
    real = sla.time.monotonic
    sla.time.monotonic = lambda: next(clock)
    try:
        code, message = sla.stamp(tmp_path, V, fetch=sdist_only, wait=250, pause=1, sleep=naps.append)
    finally:
        sla.time.monotonic = real
    assert code == 2 and "no wheel" in message, message
    assert path.read_text() == STATS % "2026-10-19"
    assert naps, "it should have retried before giving up"


def test_retries_until_pypi_serves_the_file(tmp_path):
    tree(tmp_path, STATS % "2026-10-19")
    calls = []

    def flaky(url):
        calls.append(url)
        if len(calls) < 3:
            raise OSError("404 not propagated yet")
        return served()(url)

    naps = []
    code, message = sla.stamp(tmp_path, V, fetch=flaky, wait=300, pause=20, sleep=naps.append)
    assert code == 0, message
    assert len(calls) == 3 and naps == [20, 20]
    assert calls[0] == "https://pypi.org/pypi/sunglasses/0.6.10/json"


@pytest.mark.parametrize("argv", [["x"], ["x", "0.6"], ["x", "v0.6.10"], ["x", "0.6.10", "--wait", "soon"],
                                  ["x", "0.6.10", "extra"]])
def test_bad_arguments_exit_64(argv, capsys):
    assert sla.main(argv) == 64


def test_main_reports_and_returns_the_code(tmp_path, capsys):
    tree(tmp_path, STATS % "2026-10-19")
    rc = sla.main(["x", V, "--root", str(tmp_path), "--wait", "0"], fetch=served())
    assert rc == 0
    assert "last_updated 2026-10-19T07:26:03-07:00 by release.yml" in capsys.readouterr().out


def test_a_duplicate_key_in_the_file_is_refused_and_the_file_untouched(tmp_path):
    text = (STATS % "2026-10-19").replace('"team_size": 5,', '"team_size": 5,\n  "released": "2026-10-19",')
    path = tree(tmp_path, text)
    code, message = sla.stamp(tmp_path, V, fetch=served(), sleep=no_sleep)
    assert code == 2 and "not strict JSON" in message, message
    assert path.read_text() == text
