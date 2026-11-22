"""The exit code of a scan in which a rule reached its time limit (README, Exit codes).

A rule that did not finish is a finding at that rule's severity, so the exit code follows the contract every finding
follows: `1` with no option, `3` when `--fail-on` is above that severity or a baseline covers the finding and no other
finding gives `1`, and `1`
for a critical finding that no `--accept-critical` names. The slow rule is a Python stub that spends CPU; no slow
expression text stands in this file. Nothing asserts on seconds.
"""
import json
import sys

import pytest

from sunglasses import _time_limit
from test_time_limit import (ORDINARY, _burn, _burn_until_interrupted, _engine, _rule, _run_cli, _stub_engine_class,
                             _tree_scan, needs_timer)

LIMIT = ["--rule-time-limit", "0.05"]
TEXT_WITH_HIT = "zzfind-slow zzfind-late"                  # the stub rule ends, and another rule finds a medium hit


def _door(monkeypatch, capsys, tmp_path, door, extra=(), severity="high"):
    """One scan of an ordinary text in which the stub rule reaches its limit, through one door; returns the exit code and output."""
    if door == "dir":
        code, out = _tree_scan(monkeypatch, capsys, tmp_path, ["a.txt", "slow.txt"], *extra, severity=severity)
        return code, out
    stub = _stub_engine_class(_burn_until_interrupted(), severity)
    if door == "file":
        path = tmp_path / "note.txt"
        path.write_text(ORDINARY)
        argv = ["--file", str(path), "--file-deadline", "0"] + LIMIT + list(extra)
    else:
        argv = ["--text", ORDINARY] + LIMIT + list(extra)
    code, out, _err = _run_cli(monkeypatch, capsys, argv, stub)
    return code, out


DOORS = ["text", "file", "dir"]


@needs_timer
@pytest.mark.parametrize("door", DOORS)
def test_a_rule_that_reaches_its_limit_exits_1_with_no_option(monkeypatch, capsys, tmp_path, door):
    code, out = _door(monkeypatch, capsys, tmp_path, door)
    assert code == 1, out
    assert "did not finish within its time limit" in out


@needs_timer
@pytest.mark.parametrize("door", DOORS)
def test_a_fail_on_level_above_the_severity_of_the_rule_that_ended_exits_3(monkeypatch, capsys, tmp_path, door):
    code, out = _door(monkeypatch, capsys, tmp_path, door, ["--fail-on", "critical"])
    assert code == 3, out
    code, out = _door(monkeypatch, capsys, tmp_path, door, ["--fail-on", "high"])
    assert code == 1, out                                # the level the rule's own severity reaches keeps the exit 1


@needs_timer
def test_a_baseline_that_lists_the_finding_exits_3_and_the_decision_stays_block(monkeypatch, capsys, tmp_path):
    base = tmp_path / "baseline.json"
    tree = tmp_path / "tree"
    tree.mkdir()
    code, out = _tree_scan(monkeypatch, capsys, tree, ["a.txt", "slow.txt"], "--write-baseline", str(base))
    assert code == 3 and base.exists(), out              # the run that writes the list judges against the list it wrote
    capsys.readouterr()
    code, out = _tree_scan(monkeypatch, capsys, tree, ["a.txt", "slow.txt"], "--baseline", str(base))
    assert code == 3, out
    assert "Decision:        BLOCK" in out and "INCOMPLETE SCAN — a rule did not finish within its time limit" in out
    capsys.readouterr()
    code, out = _tree_scan(monkeypatch, capsys, tree, ["a.txt", "slow.txt"], "--baseline", str(base), "--json")
    assert code == 3
    document = json.loads(out)
    assert document["decision"] == "block" and document["inspection_complete"] is False


@needs_timer
def test_a_critical_finding_of_this_kind_is_not_listed_by_a_baseline_unless_its_rule_is_accepted(monkeypatch, capsys, tmp_path):
    base = tmp_path / "baseline.json"
    tree = tmp_path / "tree"
    tree.mkdir()
    code, out = _tree_scan(monkeypatch, capsys, tree, ["a.txt", "slow.txt"], "--write-baseline", str(base), severity="critical")
    assert code == 1, out
    capsys.readouterr()
    code, out = _tree_scan(monkeypatch, capsys, tree, ["a.txt", "slow.txt"], "--baseline", str(base), severity="critical")
    assert code == 1, out
    capsys.readouterr()
    code, out = _tree_scan(monkeypatch, capsys, tree, ["a.txt", "slow.txt"], "--baseline", str(base),
                           "--accept-critical", _time_limit.LIMIT_ID, severity="critical")
    assert code == 3, out


@needs_timer
def test_a_file_whose_ended_rules_include_a_critical_one_exits_1_under_fail_on_critical(monkeypatch, capsys, tmp_path):
    code, out = _door(monkeypatch, capsys, tmp_path, "file", ["--fail-on", "critical"], severity="critical")
    assert code == 1, out


def test_the_help_default_of_the_rule_limit_is_the_constant_the_command_line_uses(monkeypatch, capsys):
    from sunglasses import cli
    monkeypatch.setattr(sys, "argv", ["sunglasses", "scan", "--help"])
    with pytest.raises(SystemExit):
        cli.main()
    help_text = " ".join(capsys.readouterr().out.split())
    assert f"(default: {_time_limit.DEFAULT_RULE_S:g})" in help_text.rsplit("--rule-time-limit", 1)[1].split("--jobs", 1)[0]
    assert cli._check_rule_time_limit(type("Args", (), {"rule_time_limit": None})()) == _time_limit.DEFAULT_RULE_S


@needs_timer
def test_a_scan_wide_end_on_the_text_door_exits_with_the_code_pinned_here(monkeypatch, capsys):
    from sunglasses import cli

    class Stub(_engine.__globals__["SunglassesEngine"]):
        def __init__(self, *args, **kwargs):
            rules = ([_rule("T-FIRST", "medium", "zzfind-early")]
                     + [_rule(f"T-MID{i}", "low", "zzfind-slow") for i in range(8)]
                     + [_rule("T-LAST", "critical", "zzfind-late")])
            super().__init__(patterns=rules, mechanisms=False)
            burn = _burn(0.03)
            for pattern, compiled in self._regex_patterns:
                if pattern["id"].startswith("T-MID"):
                    compiled[:] = [(m, _SlowOf(rx, burn), g) for m, rx, g in compiled]
    Stub.DOCUMENTED_CHANNELS = Stub.__mro__[1].DOCUMENTED_CHANNELS
    monkeypatch.setattr(_time_limit, "DEFAULT_SCAN_S", 0.1)
    text = "zzfind-early zzfind-slow zzfind-late"
    code, out, _err = _run_cli(monkeypatch, capsys, ["--text", text, "--rule-time-limit", "5"], Stub)
    assert "the scan used up its time limit" in out.lower() or "scan did not finish within its time limit" in out.lower(), out
    assert code == 1


class _SlowOf:
    def __init__(self, real, spend):
        self._real, self._spend = real, spend

    def search(self, *args):
        self._spend()
        return self._real.search(*args)

    def match(self, *args):
        self._spend()
        return self._real.match(*args)


@needs_timer
def test_an_ended_rule_under_fail_on_beside_a_finding_at_that_level_exits_1(monkeypatch, capsys):
    stub = _stub_engine_class(_burn_until_interrupted(), "low")
    code, out, _err = _run_cli(monkeypatch, capsys, ["--text", ORDINARY] + LIMIT + ["--fail-on", "medium"], stub)
    assert code == 3, out                                # the ended rule alone is under the level
    stub = _stub_engine_class(_burn_until_interrupted(), "low")
    code, out, _err = _run_cli(monkeypatch, capsys, ["--text", TEXT_WITH_HIT] + LIMIT + ["--fail-on", "medium"], stub)
    assert code == 1, out                                # a finding at the level beside it gives 1
    assert "did not finish within its time limit" in out


@needs_timer
def test_a_baseline_that_covers_the_ended_rule_beside_a_finding_it_does_not_cover_exits_1(monkeypatch, capsys, tmp_path):
    base = tmp_path / "baseline.json"
    tree = tmp_path / "tree"
    tree.mkdir()
    code, out = _tree_scan(monkeypatch, capsys, tree, ["slow.txt"], "--write-baseline", str(base))
    assert code == 3 and base.exists(), out
    capsys.readouterr()
    code, out = _tree_scan(monkeypatch, capsys, tree, ["slow.txt"], "--baseline", str(base))
    assert code == 3, out                                # the list covers the ended rule: nothing else gives 1
    capsys.readouterr()
    code, out = _tree_scan(monkeypatch, capsys, tree, ["slow.txt"], "--baseline", str(base), texts={"slow.txt": TEXT_WITH_HIT})
    assert code == 1, out                                # a finding the list does not cover gives 1
