"""The report that a folder scan sends holds the match of a found secret, not the marker of it.

A found secret is masked once per output: the folder screen, its JSON, a SARIF file, and the report file each
mask the full match at their own door. The report without the text option carries the length and the SHA-256 of
the MATCH (the README says so); with the option it carries the marker. The keys below are made up and built from
pieces, so this file holds no key shape.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_report_to import _Server, _run, REPO  # noqa: E402,F401

from sunglasses import door_mask, report_to  # noqa: E402

AWS = "".join(("AK", "IA", "Q7ZT", "M4KX", "P2WD", "N8RB"))


@pytest.fixture
def server():
    made = []

    def make(**kwargs):
        made.append(_Server(**kwargs))
        return made[-1]

    yield make
    for each in made:
        each.close()


def _tree(tmp_path):
    tree = tmp_path / "proj"
    (tree / "conf").mkdir(parents=True, exist_ok=True)
    (tree / "conf" / "deploy.env").write_text("# notes\naws_access_key_id = %s\n" % AWS)
    return tree


def _secret_findings(envelope):
    return [f for r in envelope["scan"]["file_results"] for f in r["findings"] if f.get("id", "").startswith("GLS-SD-")]


def test_the_report_without_the_text_option_carries_the_digest_of_the_match(tmp_path, server):
    srv = server()
    proc = _run(["--dir", str(_tree(tmp_path)), "--json", "--report-to", srv.url])
    assert proc.returncode == 1
    body = srv.requests[0]["body"].decode()
    found = _secret_findings(json.loads(body))
    assert found
    assert all(f["matched_text"] == report_to._digest(AWS) for f in found)
    assert all(f["matched_text"] != report_to._digest(door_mask.mask(AWS, f["id"])) for f in found)
    assert AWS not in body


def test_the_report_with_the_text_option_carries_the_marker_once(tmp_path, server):
    srv = server()
    _run(["--dir", str(_tree(tmp_path)), "--json", "--report-to", srv.url, "--report-include-text"])
    body = srv.requests[0]["body"].decode()
    found = _secret_findings(json.loads(body))
    assert found and all(f["matched_text"] == door_mask.mask(AWS, f["id"]) for f in found)   # the marker names the rule that found it
    assert AWS not in body


@pytest.mark.parametrize("extra", ((), ("--json",)), ids=("human", "json"))
def test_the_folder_screen_and_its_json_still_show_one_marker(tmp_path, extra):
    out = _run(["--dir", str(_tree(tmp_path)), *extra]).stdout
    assert "AKIA" in out and "a3059ab8" in out
    assert not any(AWS[i:i + 12] in out for i in range(len(AWS) - 11))
    assert "a3059ab8" in out and "] [" not in out            # one marker, never a marker of a marker


def test_the_option_gives_the_full_match_back_on_the_folder_json(tmp_path):
    out = _run(["--dir", str(_tree(tmp_path)), "--json", "--show-secrets"]).stdout
    assert AWS in out


# --- every way into the report describes the match of the finding, once, with and without the show option ---------------

def _ways(tmp_path):
    f = _tree(tmp_path) / "conf" / "deploy.env"
    return {"text": ["--text", "aws_access_key_id = " + AWS], "file": ["--file", str(f)],
            "folder": ["--dir", str(_tree(tmp_path))]}


@pytest.mark.parametrize("way", ("text", "file", "folder"))
@pytest.mark.parametrize("show", ((), ("--show-secrets",)), ids=("no-show", "show"))
def test_the_report_describes_the_match_of_a_found_secret_on_every_way_in(tmp_path, server, way, show):
    srv = server()
    _run([*_ways(tmp_path)[way], "--json", *show, "--report-to", srv.url])
    _run([*_ways(tmp_path)[way], "--json", *show, "--report-to", srv.url, "--report-include-text"])
    hashed, texted = (json.loads(r["body"]) for r in srv.requests)
    for env, want_text in ((hashed, False), (texted, True)):
        findings = [f for f in (env["scan"].get("findings") or []) +
                    [g for r in env["scan"].get("file_results") or [] for g in r["findings"]]
                    if f.get("id", "").startswith("GLS-SD-")]
        assert findings, (way, show)
        for f in findings:
            want = door_mask.mask(AWS, f["id"]) if want_text else report_to._digest(AWS)
            assert f["matched_text"] == want, (way, show, want_text)
    assert AWS not in srv.requests[0]["body"].decode() and AWS not in srv.requests[1]["body"].decode()


def test_the_line_of_a_found_secret_stays_in_the_report_of_a_folder_scan(tmp_path, server):
    srv = server()
    _run(["--dir", str(_tree(tmp_path)), "--json", "--report-to", srv.url])
    found = _secret_findings(json.loads(srv.requests[0]["body"]))
    assert found and all(f.get("line") == 2 for f in found)
