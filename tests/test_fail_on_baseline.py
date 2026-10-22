"""
test_fail_on_baseline.py -- `scan --fail-on` and `scan --baseline` decide the exit code for
CI without changing what the scan reports.

Two options, one rule that holds for both: an option may lower the exit code for findings a
team has chosen to live with, and it may never hide them, and never turn an unread file into
a clean one.

  * `--fail-on LEVEL` (any, low, medium, high, critical, none) exits 1 only for a finding at
    or above the level. `any` is today's behaviour and is the default.
  * `--baseline FILE` marks findings already listed in the file as known: same rule, same
    path under the scan root, same file content. They stay in every output format. A critical
    finding is known only when the command line names its rule id.
  * `--write-baseline FILE` writes that list from the current scan.
  * Exit 3 (part of the input was not read) stays 3 under every level and every baseline.
  * Anything wrong with the options or the file is exit 2, never a pass.

The scanner here is a four-rule stub (one keyword per severity), so the severities do not
depend on which real rules exist today.
"""
import json
import os
import sys

import pytest

from sunglasses import baseline as bl
from sunglasses import cli
from sunglasses.engine import SunglassesEngine

LEVELS = "any low medium high critical none".split()
SEVERITIES = "low medium high critical".split()
RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
FAIL_RANK = {"any": 0, "low": 1, "medium": 2, "high": 3, "critical": 4, "none": 99}

MARKER = {s: f"zz-{s}-marker" for s in SEVERITIES}
RULE_ID = {s: f"GLS-T-{s.upper()}" for s in SEVERITIES}
STUB = [
    {"id": RULE_ID[s], "name": f"stub {s}", "category": "prompt_injection", "severity": s,
     "channel": "message file tool_output".split(), "keywords": [MARKER[s]],
     "description": "test rule"}
    for s in SEVERITIES
]


class StubEngine(SunglassesEngine):
    def __init__(self, *args, **kwargs):
        super().__init__(patterns=STUB, mechanisms=False)


@pytest.fixture(autouse=True)
def stub_engine(monkeypatch):
    monkeypatch.setattr(cli, "SunglassesEngine", StubEngine)
    monkeypatch.setenv("NO_COLOR", "1")


def run(capsys, monkeypatch, *argv):
    """Run `sunglasses scan ...` in-process. Returns (exit code, stdout, stderr)."""
    monkeypatch.setattr(sys, "argv", ["sunglasses", "scan", *argv])
    capsys.readouterr()
    try:
        cli.main()
        code = 0
    except SystemExit as exc:
        code = exc.code if isinstance(exc.code, int) else 1
    out = capsys.readouterr()
    return code, out.out, out.err


def tree(tmp_path, files):
    root = tmp_path / "proj"
    root.mkdir()
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return str(root)


def doc(out):
    return json.loads(out)


# -- default behaviour is untouched ---------------------------------------------------------

@pytest.mark.parametrize("sev", SEVERITIES)
def test_default_exit_is_one_for_any_finding(capsys, monkeypatch, tmp_path, sev):
    root = tree(tmp_path, {"a.md": f"hello {MARKER[sev]} there"})
    assert run(capsys, monkeypatch, "--dir", root)[0] == 1
    assert run(capsys, monkeypatch, "--dir", root, "--fail-on", "any")[0] == 1


def test_default_exit_is_zero_when_clean(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": "nothing here"})
    assert run(capsys, monkeypatch, "--dir", root)[0] == 0
    assert run(capsys, monkeypatch, "--dir", root, "--fail-on", "none")[0] == 0


def test_default_exit_is_three_when_part_is_unread(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": "one", "b.md": "two"})
    assert run(capsys, monkeypatch, "--dir", root, "--max-files", "1")[0] == 3


def test_default_json_has_no_new_keys(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": f"x {MARKER['high']}"})
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "-o", "json")
    assert code == 1
    d = doc(out)
    for key in ("fail_on", "known_findings", "new_findings", "baseline_stale"):
        assert key not in d
    assert all("known" not in f for r in d["file_results"] for f in r["findings"])


def test_long_file_flag_abbreviation_still_means_file(capsys, monkeypatch, tmp_path):
    path = tmp_path / "x.md"
    path.write_text(f"x {MARKER['low']}", encoding="utf-8")
    assert run(capsys, monkeypatch, "--f", str(path))[0] == 1


# -- --fail-on ------------------------------------------------------------------------------

@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("sev", SEVERITIES)
def test_fail_on_matrix_for_a_directory(capsys, monkeypatch, tmp_path, level, sev):
    root = tree(tmp_path, {"a.md": f"x {MARKER[sev]}"})
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--fail-on", level, "-o", "json")
    assert code == (1 if RANK[sev] >= FAIL_RANK[level] else 0), (level, sev)
    d = doc(out)
    # The finding is reported whatever the exit code says.
    assert d["total_threats"] == 1
    if level != "any":
        assert d["fail_on"] == level
    assert [f["id"] for r in d["file_results"] for f in r["findings"]] == [RULE_ID[sev]]


@pytest.mark.parametrize("level", LEVELS)
@pytest.mark.parametrize("sev", SEVERITIES)
def test_fail_on_matrix_for_a_file_and_for_text(capsys, monkeypatch, tmp_path, level, sev):
    path = tmp_path / "x.md"
    path.write_text(f"x {MARKER[sev]}", encoding="utf-8")
    want = 1 if RANK[sev] >= FAIL_RANK[level] else 0
    assert run(capsys, monkeypatch, "--file", str(path), "--fail-on", level)[0] == want
    assert run(capsys, monkeypatch, "--text", f"x {MARKER[sev]}", "--fail-on", level)[0] == want


def test_the_highest_finding_decides(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["low"], "b.md": MARKER["high"]})
    assert run(capsys, monkeypatch, "--dir", root, "--fail-on", "high")[0] == 1
    assert run(capsys, monkeypatch, "--dir", root, "--fail-on", "critical")[0] == 0


@pytest.mark.parametrize("level", LEVELS)
def test_unread_stays_three_under_every_level(capsys, monkeypatch, tmp_path, level):
    clean = tree(tmp_path, {"a.md": "one", "b.md": "two"})
    assert run(capsys, monkeypatch, "--dir", clean, "--max-files", "1", "--fail-on", level)[0] == 3


@pytest.mark.parametrize("level", LEVELS)
def test_finding_below_level_does_not_hide_unread(capsys, monkeypatch, tmp_path, level):
    root = tree(tmp_path, {"a.md": MARKER["low"], "b.md": "two"})
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--max-files", "1",
                       "--fail-on", level, "-o", "json")
    d = doc(out)
    assert d["total_threats"] == 1 and d["files_skipped"] == 1
    assert code == (1 if FAIL_RANK[level] <= 1 else 3)


def test_findings_below_level_are_marked(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["low"], "b.md": MARKER["high"]})
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--fail-on", "high", "-o", "json")
    assert code == 1
    marks = {f["id"]: f.get("below_fail_on", False)
             for r in doc(out)["file_results"] for f in r["findings"]}
    assert marks == {RULE_ID["low"]: True, RULE_ID["high"]: False}


def test_review_ranks_below_low():
    assert bl.fails(["review"], "any") is True
    assert bl.fails(["review"], "low") is False
    assert bl.fails([], "any") is False
    assert bl.fails(["critical"], "none") is False


def test_unknown_level_is_a_usage_error(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": "x"})
    assert run(capsys, monkeypatch, "--dir", root, "--fail-on", "severe")[0] == 2


# -- --write-baseline and --baseline --------------------------------------------------------

def write_baseline(capsys, monkeypatch, root, path, *extra):
    return run(capsys, monkeypatch, "--dir", root, "--write-baseline", str(path), *extra)


def test_written_baseline_has_the_documented_shape(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"], "sub/b.md": MARKER["low"]})
    path = tmp_path / "base.json"
    code, _, _ = write_baseline(capsys, monkeypatch, root, path)
    assert code == 0
    d = json.loads(path.read_text(encoding="utf-8"))
    assert d["schema"] == 1 and isinstance(d["scanner_version"], str)
    assert [(e["file"], e["id"], e["severity"]) for e in d["entries"]] == [
        ("a.md", RULE_ID["high"], "high"), ("sub/b.md", RULE_ID["low"], "low")]
    assert all(len(e["file_sha256"]) == 64 for e in d["entries"])


def test_applied_baseline_makes_known_findings_exit_zero_and_keeps_them_visible(
        capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path), "-o", "json")
    d = doc(out)
    assert code == 0
    assert d["total_threats"] == 1 and d["known_findings"] == 1 and d["new_findings"] == 0
    assert d["baseline_stale"] == 0
    assert [f["known"] for r in d["file_results"] for f in r["findings"]] == [True]


def test_known_findings_stay_in_human_output(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path))
    assert code == 0
    assert "stub high" in out and "KNOWN" in out
    assert "Total threats:   1" in out


def test_known_findings_are_suppressed_not_dropped_in_sarif(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"], "b.md": MARKER["medium"]})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    (tmp_path / "proj" / "c.md").write_text(MARKER["low"], encoding="utf-8")
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path), "-o", "sarif")
    results = doc(out)["runs"][0]["results"]
    by_rule = {r["ruleId"]: r for r in results}
    assert set(by_rule) == {RULE_ID["high"], RULE_ID["medium"], RULE_ID["low"]}
    assert by_rule[RULE_ID["high"]]["suppressions"][0]["kind"] == "external"
    assert by_rule[RULE_ID["medium"]]["suppressions"][0]["kind"] == "external"
    assert "suppressions" not in by_rule[RULE_ID["low"]]
    assert code == 1


def test_a_new_finding_still_fails(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    (tmp_path / "proj" / "new.md").write_text(MARKER["medium"], encoding="utf-8")
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path), "-o", "json")
    d = doc(out)
    assert code == 1 and d["known_findings"] == 1 and d["new_findings"] == 1


def test_baseline_composes_with_fail_on(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    (tmp_path / "proj" / "new.md").write_text(MARKER["low"], encoding="utf-8")
    base = ("--dir", root, "--baseline", str(path))
    assert run(capsys, monkeypatch, *base, "--fail-on", "any")[0] == 1
    assert run(capsys, monkeypatch, *base, "--fail-on", "medium")[0] == 0


def test_editing_a_baselined_file_makes_the_finding_new_again(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    (tmp_path / "proj" / "a.md").write_text(MARKER["high"] + " and more text", encoding="utf-8")
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path), "-o", "json")
    d = doc(out)
    assert code == 1 and d["new_findings"] == 1 and d["known_findings"] == 0
    assert d["baseline_stale"] == 1


def test_the_same_content_in_another_path_is_not_known(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    os.rename(os.path.join(root, "a.md"), os.path.join(root, "moved.md"))
    assert run(capsys, monkeypatch, "--dir", root, "--baseline", str(path))[0] == 1


def test_a_baseline_for_a_different_rule_does_not_apply(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    d = json.loads(path.read_text(encoding="utf-8"))
    d["entries"][0]["id"] = "GLS-T-OTHER"
    path.write_text(json.dumps(d), encoding="utf-8")
    assert run(capsys, monkeypatch, "--dir", root, "--baseline", str(path))[0] == 1


def test_stale_entries_are_counted_not_an_error(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"], "b.md": MARKER["low"]})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    os.unlink(os.path.join(root, "b.md"))
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path), "-o", "json")
    d = doc(out)
    assert code == 0 and d["baseline_stale"] == 1


def test_baseline_never_makes_unread_files_clean(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"], "b.md": "two"})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    for level in LEVELS:
        code, _, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path),
                         "--max-files", "1", "--fail-on", level)
        assert code == 3, level


# -- critical findings ----------------------------------------------------------------------

def test_a_baseline_never_suppresses_a_critical_finding(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["critical"]})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    entries = json.loads(path.read_text(encoding="utf-8"))["entries"]
    assert [e["id"] for e in entries] == [RULE_ID["critical"]]    # written, but inert
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path), "-o", "json")
    d = doc(out)
    assert code == 1 and d["new_findings"] == 1 and d["known_findings"] == 0


def test_writing_a_baseline_does_not_pass_a_critical_finding(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["critical"]})
    assert write_baseline(capsys, monkeypatch, root, tmp_path / "base.json")[0] == 1


def test_accept_critical_names_the_rule(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["critical"]})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    base = ("--dir", root, "--baseline", str(path))
    assert run(capsys, monkeypatch, *base, "--accept-critical", RULE_ID["critical"])[0] == 0
    assert run(capsys, monkeypatch, *base, "--accept-critical", "GLS-T-OTHER")[0] == 1


def test_accept_critical_does_not_accept_a_file_that_changed(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["critical"]})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    (tmp_path / "proj" / "a.md").write_text(MARKER["critical"] + " x", encoding="utf-8")
    code = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path),
               "--accept-critical", RULE_ID["critical"])[0]
    assert code == 1


# -- write then apply -----------------------------------------------------------------------

def test_write_then_apply_round_trip_is_idempotent(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"], "d/b.md": MARKER["medium"], "c.md": "clean"})
    first, second = tmp_path / "one.json", tmp_path / "two.json"
    write_baseline(capsys, monkeypatch, root, first)
    write_baseline(capsys, monkeypatch, root, second)
    assert first.read_bytes() == second.read_bytes()
    assert run(capsys, monkeypatch, "--dir", root, "--baseline", str(first))[0] == 0


def test_writing_a_baseline_for_a_clean_tree_writes_an_empty_list(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": "clean"})
    path = tmp_path / "base.json"
    assert write_baseline(capsys, monkeypatch, root, path)[0] == 0
    assert json.loads(path.read_text(encoding="utf-8"))["entries"] == []


def test_write_baseline_on_an_incomplete_scan_still_exits_three(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": "one", "b.md": "two"})
    assert write_baseline(capsys, monkeypatch, root, tmp_path / "b.json", "--max-files", "1")[0] == 3


# -- errors are exit 2 ----------------------------------------------------------------------

def _bad(tmp_path, name, content):
    path = tmp_path / name
    path.write_text(content, encoding="utf-8")
    return str(path)


@pytest.mark.parametrize("content", [
    "not json",
    "[]",
    '{"schema": 2, "entries": []}',
    '{"schema": 1}',
    '{"schema": 1, "entries": [{"id": "x"}]}',
    '{"schema": 1, "entries": ["x"]}',
])
def test_a_bad_baseline_file_is_a_usage_error(capsys, monkeypatch, tmp_path, content):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    code, _, _ = run(capsys, monkeypatch, "--dir", root, "--baseline",
                     _bad(tmp_path, "b.json", content))
    assert code == 2


def test_a_missing_baseline_file_is_a_usage_error(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    assert run(capsys, monkeypatch, "--dir", root, "--baseline", str(tmp_path / "nope.json"))[0] == 2


def test_a_usage_error_with_json_is_one_document(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "-o", "json",
                       "--baseline", str(tmp_path / "nope.json"))
    assert code == 2 and doc(out)["exit_code"] == 2


def test_an_unwritable_baseline_path_is_a_usage_error(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    code, _, _ = run(capsys, monkeypatch, "--dir", root, "--write-baseline",
                     str(tmp_path / "missing-dir" / "b.json"))
    assert code == 2


def test_baseline_with_text_or_a_file_is_refused(capsys, monkeypatch, tmp_path):
    path = _bad(tmp_path, "b.json", '{"schema": 1, "entries": []}')
    target = tmp_path / "x.md"
    target.write_text(MARKER["high"], encoding="utf-8")
    assert run(capsys, monkeypatch, "--text", "hello", "--baseline", path)[0] == 2
    assert run(capsys, monkeypatch, "--file", str(target), "--baseline", path)[0] == 2
    assert run(capsys, monkeypatch, "--text", "hello", "--write-baseline", str(tmp_path / "w.json"))[0] == 2


def test_baseline_with_stdin_is_refused(capsys, monkeypatch, tmp_path):
    path = _bad(tmp_path, "b.json", '{"schema": 1, "entries": []}')
    assert run(capsys, monkeypatch, "--stdin", "--baseline", path)[0] == 2


def test_new_options_with_deep_are_refused(capsys, monkeypatch, tmp_path):
    path = _bad(tmp_path, "b.json", '{"schema": 1, "entries": []}')
    target = tmp_path / "x.wav"
    target.write_bytes(b"RIFF")
    assert run(capsys, monkeypatch, "--file", str(target), "--deep", "--baseline", path)[0] == 2
    assert run(capsys, monkeypatch, "--file", str(target), "--deep", "--fail-on", "high")[0] == 2


def test_accept_critical_needs_a_baseline(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["critical"]})
    assert run(capsys, monkeypatch, "--dir", root, "--accept-critical", RULE_ID["critical"])[0] == 2


def test_baseline_and_write_baseline_together_are_refused(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    path = _bad(tmp_path, "b.json", '{"schema": 1, "entries": []}')
    assert run(capsys, monkeypatch, "--dir", root, "--baseline", path,
               "--write-baseline", str(tmp_path / "w.json"))[0] == 2


# -- the module on its own ------------------------------------------------------------------

def test_classify_matches_on_rule_path_and_content():
    base = bl.Baseline([{"id": "R", "file": "a", "file_sha256": "h", "severity": "low"}])
    finds = [
        {"id": "R", "file": "a", "file_sha256": "h", "severity": "low"},
        {"id": "R", "file": "a", "file_sha256": "other", "severity": "low"},
        {"id": "R", "file": "b", "file_sha256": "h", "severity": "low"},
        {"id": "Q", "file": "a", "file_sha256": "h", "severity": "low"},
    ]
    assert bl.classify(finds, base)[0] == [True, False, False, False]
    assert bl.classify(finds, None) == ([False] * 4, 0)


def test_classify_reports_stale_entries():
    base = bl.Baseline([{"id": "R", "file": "a", "file_sha256": "h", "severity": "low"},
                        {"id": "R", "file": "gone", "file_sha256": "h", "severity": "low"}])
    known, stale = bl.classify([{"id": "R", "file": "a", "file_sha256": "h", "severity": "low"}], base)
    assert known == [True] and stale == 1


def test_an_unaccepted_critical_entry_is_not_stale():
    base = bl.Baseline([{"id": "R", "file": "a", "file_sha256": "h", "severity": "critical"}])
    find = [{"id": "R", "file": "a", "file_sha256": "h", "severity": "critical"}]
    assert bl.classify(find, base) == ([False], 0)
    assert bl.classify(find, base, ["R"]) == ([True], 0)


def test_posix_path_uses_forward_slashes():
    assert bl.posix_path(os.path.join("a", "b", "c.md")) == "a/b/c.md"


# -- every emitted finding is judged, and counted, the same way ----------------------------

def _twin_engine(monkeypatch, extra_rules):
    """Swap in an engine whose rules are the stub's plus `extra_rules`."""
    rules = STUB + extra_rules

    class Twin(SunglassesEngine):
        def __init__(self, *args, **kwargs):
            super().__init__(patterns=rules, mechanisms=False)

    monkeypatch.setattr(cli, "SunglassesEngine", Twin)


def _twin_rule(rule_id, severity, keyword):
    return {"id": rule_id, "name": f"twin {rule_id}", "category": "prompt_injection",
            "severity": severity, "channel": "message file tool_output".split(),
            "keywords": [keyword], "description": "test rule"}


def test_a_finding_absorbed_into_another_is_still_judged_like_the_rest(
        capsys, monkeypatch, tmp_path):
    # Two rules fire on the same words: the human view keeps one, JSON and SARIF emit both.
    _twin_engine(monkeypatch, [_twin_rule("GLS-T-TWIN", "low", MARKER["high"])])
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    path = tmp_path / "base.json"
    code, out, _ = write_baseline(capsys, monkeypatch, root, path, "-o", "json")
    emitted = [f for r in doc(out)["file_results"] for f in r["findings"]]
    assert len(emitted) == 2
    assert len(json.loads(path.read_text(encoding="utf-8"))["entries"]) == 2

    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path), "-o", "json")
    d = doc(out)
    assert code == 0
    assert d["known_findings"] == 2 and d["new_findings"] == 0 and d["baseline_stale"] == 0
    assert [f["known"] for r in d["file_results"] for f in r["findings"]] == [True, True]

    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path), "-o", "sarif")
    results = doc(out)["runs"][0]["results"]
    assert len(results) == 2 and all("suppressions" in r for r in results)


def test_a_listed_entry_that_matches_an_emitted_finding_is_never_stale(
        capsys, monkeypatch, tmp_path):
    _twin_engine(monkeypatch, [_twin_rule("GLS-T-TWIN", "low", MARKER["high"])])
    root = tree(tmp_path, {"a.md": MARKER["high"], "b.md": MARKER["medium"]})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    _, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path), "-o", "json")
    assert doc(out)["baseline_stale"] == 0


def test_a_known_sibling_never_marks_an_unaccepted_critical_with_the_same_id_known(
        capsys, monkeypatch, tmp_path):
    # The engine keeps one finding per rule id, so the shape is injected at the seam: a second
    # finding with the same id, in the same file, one severity up. The baseline lists the id
    # once; it must cover the low finding and leave the critical one new.
    original = SunglassesEngine.scan_file

    def with_a_critical_sibling(self, *args, **kwargs):
        result = original(self, *args, **kwargs)
        if result.findings:
            result.findings.append(dict(result.findings[0], severity="critical",
                                        matched_text="a different span"))
        return result

    monkeypatch.setattr(SunglassesEngine, "scan_file", with_a_critical_sibling)
    root = tree(tmp_path, {"a.md": MARKER["low"]})
    path = tmp_path / "base.json"
    write_baseline(capsys, monkeypatch, root, path)
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path), "-o", "json")
    d = doc(out)
    assert code == 1
    marks = {f["severity"]: f["known"] for r in d["file_results"] for f in r["findings"]}
    assert marks == {"low": True, "critical": False}
    assert d["known_findings"] == 1 and d["new_findings"] == 1
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path), "-o", "sarif")
    suppressed = ["suppressions" in r for r in doc(out)["runs"][0]["results"]]
    assert sorted(suppressed) == [False, True]
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path))
    # The screen prints one line per file and rule id; it carries the worst status behind it.
    assert code == 1 and "KNOWN" not in out


# -- one file, one piece of text: the same --fail-on markings --------------------------------

def test_a_single_file_marks_findings_below_the_level(capsys, monkeypatch, tmp_path):
    path = tmp_path / "x.md"
    path.write_text(f"{MARKER['low']} and {MARKER['high']}", encoding="utf-8")
    code, out, _ = run(capsys, monkeypatch, "--file", str(path), "--fail-on", "high", "--json")
    d = doc(out)
    assert code == 1 and d["fail_on"] == "high"
    marks = {f["id"]: f.get("below_fail_on", False) for f in d["findings"]}
    assert marks == {RULE_ID["low"]: True, RULE_ID["high"]: False}


@pytest.mark.parametrize("how", ["text", "stdin"])
def test_text_and_stdin_mark_findings_below_the_level(capsys, monkeypatch, how):
    if how == "stdin":
        import io
        monkeypatch.setattr(sys, "stdin", io.StringIO(f"x {MARKER['low']}"))
        argv = ["--stdin"]
    else:
        argv = ["--text", f"x {MARKER['low']}"]
    code, out, _ = run(capsys, monkeypatch, *argv, "--fail-on", "high", "--json")
    d = doc(out)
    assert code == 0 and d["fail_on"] == "high"
    assert [f.get("below_fail_on") for f in d["findings"]] == [True]


def test_a_single_input_document_is_unchanged_without_fail_on(capsys, monkeypatch, tmp_path):
    path = tmp_path / "x.md"
    path.write_text(MARKER["low"], encoding="utf-8")
    _, out, _ = run(capsys, monkeypatch, "--file", str(path), "--json")
    d = doc(out)
    assert "fail_on" not in d and all("below_fail_on" not in f for f in d["findings"])


def test_a_single_file_names_the_level_on_the_human_screen(capsys, monkeypatch, tmp_path):
    path = tmp_path / "x.md"
    path.write_text(MARKER["low"], encoding="utf-8")
    code, out, _ = run(capsys, monkeypatch, "--file", str(path), "--fail-on", "high")
    assert code == 0 and "Fails on:" in out and "1 finding(s) below it" in out


# -- a baseline that is not an ordinary, well-formed file is refused -------------------------

def test_a_baseline_that_is_a_fifo_is_refused_without_blocking(capsys, monkeypatch, tmp_path):
    if not hasattr(os, "mkfifo"):
        pytest.skip("no named pipes here")
    fifo = tmp_path / "pipe.json"
    os.mkfifo(str(fifo))
    with pytest.raises(bl.BaselineError):
        bl.load(str(fifo))
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    assert run(capsys, monkeypatch, "--dir", root, "--baseline", str(fifo))[0] == 2


def test_a_baseline_that_is_a_directory_is_refused(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    assert run(capsys, monkeypatch, "--dir", root, "--baseline", str(tmp_path))[0] == 2


def test_an_oversized_baseline_is_refused(capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(bl, "MAX_BYTES", 64)
    path = _bad(tmp_path, "big.json", '{"schema": 1, "entries": [], "pad": "' + "x" * 200 + '"}')
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    code, out, err = run(capsys, monkeypatch, "--dir", root, "--baseline", path)
    assert code == 2 and "larger than" in err


SHA = "a" * 64


@pytest.mark.parametrize("content", [
    '{"schema": true, "entries": []}',
    '{"schema": 1.0, "entries": []}',
    '{"schema": "1", "entries": []}',
    '{"schema": [1], "entries": []}',
    f'{{"schema": 1, "entries": [{{"id": "R", "file": "../a.md", "file_sha256": "{SHA}"}}]}}',
    f'{{"schema": 1, "entries": [{{"id": "R", "file": "/etc/a.md", "file_sha256": "{SHA}"}}]}}',
    f'{{"schema": 1, "entries": [{{"id": "R", "file": "a//b.md", "file_sha256": "{SHA}"}}]}}',
    f'{{"schema": 1, "entries": [{{"id": "R", "file": "./a.md", "file_sha256": "{SHA}"}}]}}',
    f'{{"schema": 1, "entries": [{{"id": "R", "file": "a/./b.md", "file_sha256": "{SHA}"}}]}}',
    f'{{"schema": 1, "entries": [{{"id": "R", "file": "a\\\\b.md", "file_sha256": "{SHA}"}}]}}',
    f'{{"schema": 1, "entries": [{{"id": "R", "file": "a/", "file_sha256": "{SHA}"}}]}}',
    '{"schema": 1, "entries": [{"id": "R", "file": "a.md", "file_sha256": "abc"}]}',
    f'{{"schema": 1, "entries": [{{"id": "R", "file": "a.md", "file_sha256": "{"A" * 64}"}}]}}',
    f'{{"schema": 1, "entries": [{{"id": "R", "file": "a.md", "file_sha256": "{"g" * 64}"}}]}}',
    f'{{"schema": 1, "entries": [{{"id": "R", "file": "a.md", "file_sha256": "{SHA}x"}}]}}',
])
def test_a_malformed_baseline_is_refused_before_any_scan(capsys, monkeypatch, tmp_path, content):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "-o", "json",
                       "--baseline", _bad(tmp_path, "b.json", content))
    assert code == 2 and doc(out)["scanned"] is False


def test_a_well_formed_baseline_with_duplicate_entries_is_accepted(tmp_path):
    entry = f'{{"id": "R", "file": "sub/a.md", "file_sha256": "{SHA}"}}'
    path = _bad(tmp_path, "b.json", f'{{"schema": 1, "entries": [{entry}, {entry}]}}')
    assert bl.load(path).matches("R", "sub/a.md", SHA)


# -- empty option values are refused, not read as absent -------------------------------------

@pytest.mark.parametrize("flag", ["--baseline", "--write-baseline"])
def test_an_empty_baseline_path_is_a_usage_error(capsys, monkeypatch, tmp_path, flag):
    root = tree(tmp_path, {"a.md": "clean"})
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "-o", "json", flag, "")
    assert code == 2 and doc(out)["scanned"] is False


def test_an_empty_accept_critical_value_is_a_usage_error(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": "clean"})
    path = _bad(tmp_path, "b.json", '{"schema": 1, "entries": []}')
    assert run(capsys, monkeypatch, "--dir", root, "--baseline", path,
               "--accept-critical", "")[0] == 2


def test_an_explicit_fail_on_any_is_still_refused_with_deep(capsys, monkeypatch, tmp_path):
    target = tmp_path / "x.wav"
    target.write_bytes(b"RIFF")
    assert run(capsys, monkeypatch, "--file", str(target), "--deep", "--fail-on", "any")[0] == 2


# -- the write destination is judged before the scan, and again before the move --------------

def _scan_count(monkeypatch):
    calls = []
    original = SunglassesEngine.scan_file

    def counting(self, *args, **kwargs):
        calls.append(1)
        return original(self, *args, **kwargs)

    monkeypatch.setattr(SunglassesEngine, "scan_file", counting)
    return calls


def test_a_symlink_as_the_baseline_destination_is_refused_before_scanning(
        capsys, monkeypatch, tmp_path):
    if not hasattr(os, "symlink"):
        pytest.skip("no symlinks here")
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    target = tmp_path / "real.json"
    target.write_text("keep", encoding="utf-8")
    link = tmp_path / "link.json"
    os.symlink(str(target), str(link))
    calls = _scan_count(monkeypatch)
    code, out, _ = write_baseline(capsys, monkeypatch, root, link, "-o", "json")
    assert code == 2 and doc(out)["scanned"] is False and not calls
    assert link.is_symlink() and target.read_text(encoding="utf-8") == "keep"


def test_a_directory_as_the_baseline_destination_is_refused_before_scanning(
        capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    calls = _scan_count(monkeypatch)
    code, _, _ = write_baseline(capsys, monkeypatch, root, tmp_path)
    assert code == 2 and not calls
    code, _, _ = write_baseline(capsys, monkeypatch, root, root)
    assert code == 2 and not calls


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() == 0,
                    reason="a superuser can write anywhere")
def test_an_unwritable_folder_is_refused_before_scanning(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    locked = tmp_path / "locked"
    locked.mkdir()
    locked.chmod(0o500)
    try:
        calls = _scan_count(monkeypatch)
        code, _, _ = write_baseline(capsys, monkeypatch, root, locked / "b.json")
        assert code == 2 and not calls
    finally:
        locked.chmod(0o700)


def test_write_refuses_a_destination_that_became_a_symlink_before_the_move(tmp_path):
    if not hasattr(os, "symlink"):
        pytest.skip("no symlinks here")
    target = tmp_path / "real.json"
    target.write_text("keep", encoding="utf-8")
    link = tmp_path / "link.json"
    os.symlink(str(target), str(link))
    with pytest.raises(bl.BaselineError):
        bl.write(str(link), [], "0")
    assert link.is_symlink() and target.read_text(encoding="utf-8") == "keep"
    assert not [p for p in os.listdir(tmp_path) if p.startswith(".baseline-")]


def test_writing_over_an_existing_regular_baseline_still_works(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    path = tmp_path / "base.json"
    path.write_text("old", encoding="utf-8")
    assert write_baseline(capsys, monkeypatch, root, path)[0] == 0
    assert json.loads(path.read_text(encoding="utf-8"))["schema"] == 1


def test_a_baseline_written_inside_the_tree_is_scanned_next_time(capsys, monkeypatch, tmp_path):
    # Documented behaviour, pinned: the file lands in the scan root, so the next scan reads it.
    root = tree(tmp_path, {"a.md": MARKER["high"]})
    inside = os.path.join(root, "base.json")
    assert write_baseline(capsys, monkeypatch, root, inside)[0] == 0
    _, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", inside, "-o", "json")
    assert doc(out)["files_scanned"] == 2


def test_canonical_path_check_matches_what_posix_path_writes():
    assert bl._canonical_path("a/b/c.md") and bl._canonical_path("a.md")
    for bad in ("", ".", "..", "a/", "/a", "a//b", "a/../b", "a\\b", "a\x00b", None, 5):
        assert not bl._canonical_path(bad), bad


# -- the writer and the loader share one contract --------------------------------------------

def _leftovers(folder):
    return [p for p in os.listdir(folder) if p.startswith(".baseline-")]


@pytest.mark.parametrize("name", ["with space.md", "colon:name.md", "café/über ☃.md", "a'b\"c.md"])
def test_names_the_writer_accepts_are_read_back_as_known(capsys, monkeypatch, tmp_path, name):
    root = tree(tmp_path, {name: MARKER["high"]})
    path = tmp_path / "base.json"
    assert write_baseline(capsys, monkeypatch, root, path)[0] == 0
    code, out, _ = run(capsys, monkeypatch, "--dir", root, "--baseline", str(path), "-o", "json")
    assert code == 0
    d = doc(out)
    assert d["known_findings"] == 1 and d["new_findings"] == 0
    assert [f["known"] for r in d["file_results"] for f in r["findings"]] == [True]


@pytest.mark.skipif(os.sep != "/", reason="a backslash is only an ordinary filename character on POSIX")
def test_a_backslash_filename_is_refused_and_the_old_baseline_is_kept(capsys, monkeypatch, tmp_path):
    root = tree(tmp_path, {"a\\b.md": MARKER["high"]})
    path = tmp_path / "base.json"
    path.write_text("old", encoding="utf-8")
    code, out, _ = write_baseline(capsys, monkeypatch, root, path)
    assert code == 1                        # the scan found something; the refusal does not hide it
    assert "Baseline NOT written" in out and "nothing was written" in out
    assert path.read_text(encoding="utf-8") == "old"
    assert not _leftovers(tmp_path)


def test_an_oversize_baseline_is_refused_and_the_old_one_is_kept(tmp_path, monkeypatch):
    path = tmp_path / "base.json"
    path.write_text("old", encoding="utf-8")
    monkeypatch.setattr(bl, "MAX_BYTES", 2000)
    findings = [{"id": "GLS-T-HIGH", "file": f"dir/file-{i:05d}.md", "file_sha256": "a" * 64,
                 "severity": "high"} for i in range(200)]
    with pytest.raises(bl.BaselineError, match="larger than"):
        bl.write(str(path), findings, "0")
    assert path.read_text(encoding="utf-8") == "old"
    assert not _leftovers(tmp_path)


def test_a_file_at_the_size_limit_boundary_loads_what_write_produced(tmp_path, monkeypatch):
    findings = [{"id": "GLS-T-HIGH", "file": f"f{i}.md", "file_sha256": "b" * 64,
                 "severity": "high"} for i in range(40)]
    probe = tmp_path / "probe.json"
    bl.write(str(probe), findings, "0")
    size = len(probe.read_bytes())
    monkeypatch.setattr(bl, "MAX_BYTES", size)
    exact = tmp_path / "exact.json"
    assert bl.write(str(exact), findings, "0") == 40
    assert len(bl.load(str(exact))) == 40
    monkeypatch.setattr(bl, "MAX_BYTES", size - 1)
    with pytest.raises(bl.BaselineError):
        bl.write(str(tmp_path / "short.json"), findings, "0")
    assert not (tmp_path / "short.json").exists()


@pytest.mark.parametrize("file", ["ok.md", "a/b.md", "", ".", "..", "a/", "/a", "a//b", "a/../b",
                                  "a\\b", "a\x00b", "sp ace/ü.md"])
def test_whatever_write_accepts_load_accepts(tmp_path, file):
    path = tmp_path / "base.json"
    finding = {"id": "GLS-T-LOW", "file": file, "file_sha256": "c" * 64, "severity": "low"}
    try:
        bl.write(str(path), [finding], "0")
    except bl.BaselineError:
        assert not path.exists() and not _leftovers(tmp_path)
        return
    assert len(bl.load(str(path))) == 1


def test_the_bytes_that_land_on_disk_are_the_bytes_that_were_measured(tmp_path, monkeypatch):
    """A platform that translates newlines in text mode must not push the file over the cap."""
    findings = [{"id": "GLS-T-HIGH", "file": f"f{i}.md", "file_sha256": "b" * 64,
                 "severity": "high"} for i in range(40)]
    probe = tmp_path / "probe.json"
    bl.write(str(probe), findings, "0")
    size = len(probe.read_bytes())
    real = os.fdopen

    def translating(fd, mode="r", *args, **kwargs):
        if "b" not in mode:
            kwargs["newline"] = "\r\n"
        return real(fd, mode, *args, **kwargs)

    monkeypatch.setattr(bl.os, "fdopen", translating)
    monkeypatch.setattr(bl, "MAX_BYTES", size)
    path = tmp_path / "exact.json"
    assert bl.write(str(path), findings, "0") == 40
    assert len(path.read_bytes()) <= bl.MAX_BYTES and b"\r" not in path.read_bytes()
    assert len(bl.load(str(path))) == 40


# -- a refusal after the scan keeps the findings and the exit precedence ----------------------

posix_only = pytest.mark.skipif(os.sep != "/", reason="a backslash is only an ordinary filename character on POSIX")


def _refused_write(capsys, monkeypatch, tmp_path, *extra):
    root = tree(tmp_path, {"a\\b.md": MARKER["high"], "c.md": MARKER["low"]})
    path = tmp_path / "base.json"
    path.write_text("old", encoding="utf-8")
    result = write_baseline(capsys, monkeypatch, root, path, *extra)
    assert path.read_text(encoding="utf-8") == "old" and not _leftovers(tmp_path)
    return result


@posix_only
def test_a_refused_write_still_reports_every_finding_in_json(capsys, monkeypatch, tmp_path):
    code, out, _ = _refused_write(capsys, monkeypatch, tmp_path, "-o", "json")
    d = doc(out)
    assert code == 1 and d["exit_code"] == 1
    assert sorted(f["id"] for r in d["file_results"] for f in r["findings"]) == [RULE_ID["high"], RULE_ID["low"]]
    assert "cannot be recorded" in d["baseline_write_error"]
    assert d["known_findings"] == 0 and d["new_findings"] == 2


@posix_only
def test_a_refused_write_still_reports_every_finding_in_sarif(capsys, monkeypatch, tmp_path):
    code, out, _ = _refused_write(capsys, monkeypatch, tmp_path, "-o", "sarif")
    d = doc(out)
    assert code == 1 and len(d["runs"]) == 1
    assert len(d["runs"][0]["results"]) == 2
    assert "cannot be recorded" in d["runs"][0]["properties"]["baselineWriteError"]


@posix_only
def test_a_refused_write_still_reports_every_finding_on_the_human_screen(capsys, monkeypatch, tmp_path):
    code, out, _ = _refused_write(capsys, monkeypatch, tmp_path)
    assert code == 1
    assert "Baseline NOT written" in out and "stub high" in out and "stub low" in out


@posix_only
def test_a_refused_write_below_the_level_exits_two_and_is_not_clean(capsys, monkeypatch, tmp_path):
    code, out, _ = _refused_write(capsys, monkeypatch, tmp_path, "-o", "json", "--fail-on", "critical")
    d = doc(out)
    assert code == 2 and d["exit_code"] == 2
    assert d["is_clean"] is False and "baseline_write_error" in d
    assert len([f for r in d["file_results"] for f in r["findings"]]) == 2


def test_a_refused_write_keeps_an_incomplete_scan_at_three(capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(bl, "MAX_BYTES", 10)
    root = tree(tmp_path, {"a.md": "one", "b.md": "two"})
    code, out, _ = write_baseline(capsys, monkeypatch, root, tmp_path / "b.json", "--max-files", "1", "-o", "json")
    d = doc(out)
    assert code == 3 and d["exit_code"] == 3 and "larger than" in d["baseline_write_error"]
    assert not (tmp_path / "b.json").exists()


def test_a_refused_write_on_a_clean_scan_is_exit_two(capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(bl, "MAX_BYTES", 10)
    root = tree(tmp_path, {"a.md": "one"})
    code, out, _ = write_baseline(capsys, monkeypatch, root, tmp_path / "b.json", "-o", "json")
    d = doc(out)
    assert code == 2 and d["exit_code"] == 2 and d["is_clean"] is False
