"""The clauses of T10 that `tests/test_proxy_doctor.py` does not reach, written
from the rows before the module exists.

Three of them matter more than the rest.

R3 states TWO things about a failing wrapper and the first spec only pinned one.
The aggregate LINE is ROUTE_UNVERIFIED, because a route that failed is not a
verified one, and the PROCESS exit is 1, because R3 says a launched route FAIL
is exit 1 and a self-test FAIL is exit 1 regardless. Exit 3 is the code for
doubt, and a route we launched and watched fail is not doubt, it is a finding.
Collapsing the two would either hide the failure behind a doubt code or claim
the inventory was fine when it was not.

R1's controls are an instrument check, so a control that PASSES invalidates the
run it belongs to. The first spec pinned the two named controls. R1 names a
third, the skipped invocation, and this file pins the rule that covers all of
them: every control that ran must have FAILED.

And the reader has to actually call the parts. On 2026-09-13 a review of this
same lane found five components built and a reader that invoked none of them,
which is a suite that proves its helpers work and its product does nothing. The
last test here exists only to make that failure impossible to repeat.
"""
import json

import pytest

doctor = pytest.importorskip("sunglasses.proxy.doctor",
                             reason="the doctor is the slice being specified")


def _entry(state, passed=True, name="fs", source="project"):
    return doctor.Entry(name=name, source=source, state=state, passed=passed)


# ── T10.R3: the aggregate line and the process exit are two answers ───────

def test_a_failing_route_is_exit_1_while_the_line_still_reads_unverified():
    outcome = doctor.aggregate(sources_readable=True,
                               entries=[_entry(doctor.WRAPPED, passed=False)])
    assert outcome.aggregate == "ROUTE_UNVERIFIED"
    assert outcome.exit_code == 3, "the aggregate's own code is the doubt code"
    assert doctor.process_exit_code(outcome, self_test_ok=True) == 1, \
        "R3: any launched route FAIL is exit 1"


def test_a_failed_self_test_is_exit_1_however_clean_the_inventory_is():
    """R3 says 'regardless', and it means it. A doctor whose own instrument
    failed has no standing to report that everything else passed."""
    outcome = doctor.aggregate(sources_readable=True,
                               entries=[_entry(doctor.WRAPPED, passed=True)])
    assert outcome.exit_code == 0
    assert doctor.process_exit_code(outcome, self_test_ok=False) == 1


def test_doubt_alone_stays_exit_3_and_a_clean_run_stays_exit_0():
    doubt = doctor.aggregate(sources_readable=True, entries=[_entry(doctor.DIRECT)])
    assert doctor.process_exit_code(doubt, self_test_ok=True) == 3
    clean = doctor.aggregate(sources_readable=True,
                             entries=[_entry(doctor.WRAPPED, passed=True)])
    assert doctor.process_exit_code(clean, self_test_ok=True) == 0


# ── T10.R1: a control that passes invalidates the run it belongs to ───────

def test_every_control_that_ran_must_have_failed_including_the_third():
    """R1 names three controls. The rule is not about which three, it is that a
    control is a detector that must trip, so any control reporting PASS means
    the instrument agreed with something that always says the same thing."""
    assert doctor.SKIPPED_INVOCATION_CONTROL == "skipped_invocation"
    assert doctor.self_test_valid(controls={
        "constant_allow": "FAIL", "constant_deny": "FAIL",
        doctor.SKIPPED_INVOCATION_CONTROL: "FAIL"}) is True
    assert doctor.self_test_valid(controls={
        "constant_allow": "FAIL", "constant_deny": "FAIL",
        doctor.SKIPPED_INVOCATION_CONTROL: "PASS"}) is False


def test_a_control_reporting_anything_other_than_fail_is_not_a_pass():
    """Neither an error nor a skip is a failed control. Both mean the control
    did not demonstrate that the detector can trip."""
    for value in ("PASS", "ERROR", "SKIPPED", "", None):
        assert doctor.self_test_valid(controls={
            "constant_allow": value, "constant_deny": "FAIL"}) is False


# ── T10.R2: the reader reads every source and hides nothing ───────────────

def test_an_unparseable_source_is_reported_unreadable_not_treated_as_empty(tmp_path):
    """The most expensive sentence this tool can say is 'verified' about a file
    it could not open, so an unparseable config produces doubt, never silence."""
    bad = tmp_path / ".mcp.json"
    bad.write_text("{not json")
    entries, unreadable = doctor.read_sources(sources=[("project", bad)])
    assert entries == []
    assert str(bad) in unreadable
    outcome = doctor.aggregate(sources_readable=not unreadable, entries=entries,
                               unreadable=unreadable)
    assert outcome.aggregate == "ROUTE_UNVERIFIED"
    assert str(bad) in json.dumps(outcome.inventory)


def test_each_entry_carries_the_source_it_came_from(tmp_path):
    """Two servers named fs in two files are two different facts, and an
    operator fixing one needs to be told which file to open."""
    project = tmp_path / ".mcp.json"
    project.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx"}}}))
    user = tmp_path / ".claude.json"
    user.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx"}}}))
    entries, unreadable = doctor.read_sources(
        sources=[("project", project), ("user", user)])
    assert unreadable == []
    assert sorted(e.source for e in entries) == ["project", "user"]


def test_the_reader_classifies_through_classify_not_by_its_own_opinion(tmp_path):
    """R2 in the reader, not only in the helper. A wrapper naming a different
    artifact is UNVERIFIED, and that has to be true of what the reader
    produces, not merely of a function the reader could have called."""
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {
        "ours": {"command": "/ours/python", "args": ["-m", "sunglasses.proxy",
                                                     "--", "npx", "server"]},
        "theirs": {"command": "/other/python", "args": ["-m", "sunglasses.proxy"]},
        "bare": {"command": "npx", "args": ["server"]}}}))
    entries, _ = doctor.read_sources(
        sources=[("project", config)],
        artifact="/ours/python", artifact_sha="a" * 64,
        hash_of=lambda path: "a" * 64)
    states = {e.name: e.state for e in entries}
    assert states == {"ours": doctor.WRAPPED,
                      "theirs": doctor.UNVERIFIED,
                      "bare": doctor.DIRECT}


# ── the round-4 guard: the reader must invoke the parts ───────────────────

def test_run_invokes_the_self_test_and_launches_every_wrapped_route(tmp_path):
    """Built five components and the reader called none of them, 2026-09-13.
    This test fails if `run` ever reports an aggregate without having run the
    self-test and launched each wrapped entry, which is the only way the
    report's words correspond to work that happened."""
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {
        "a": {"command": "/ours/python", "args": ["-m", "sunglasses.proxy"]},
        "b": {"command": "/ours/python", "args": ["-m", "sunglasses.proxy"]},
        "direct": {"command": "npx"}}}))
    launched = []
    self_tested = []

    def launcher(entry):
        launched.append(entry.name)
        return True, dict.fromkeys(doctor.SELF_TEST_CHECKS, "PASS")

    def self_test():
        self_tested.append(True)
        return True, dict.fromkeys(doctor.REQUIRED_CONTROLS, "FAIL")

    report = doctor.run(sources=[("project", config)],
                        artifact="/ours/python", artifact_sha="a" * 64,
                        hash_of=lambda path: "a" * 64,
                        self_test=self_test, launcher=launcher)
    assert self_tested == [True], "the self-test was not run"
    assert sorted(launched) == ["a", "b"], "a wrapped route was never launched"
    assert len(report.outcome.per_wrapper) == 2
    assert report.outcome.aggregate == "ROUTE_UNVERIFIED", "direct entry is doubt"
    assert report.exit_code == 3


def test_run_reports_exit_1_when_a_launched_route_fails(tmp_path):
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {
        "a": {"command": "/ours/python", "args": ["-m", "sunglasses.proxy"]}}}))

    report = doctor.run(
        sources=[("project", config)],
        artifact="/ours/python", artifact_sha="a" * 64,
        hash_of=lambda path: "a" * 64,
        self_test=lambda: (True, dict.fromkeys(doctor.REQUIRED_CONTROLS, "FAIL")),
        launcher=lambda entry: (False, {"s1_forward_byte_equal": "FAIL"}))
    assert report.outcome.aggregate == "ROUTE_UNVERIFIED"
    assert report.exit_code == 1


def test_run_never_prints_upstream_stderr(tmp_path):
    """R3's last sentence. Upstream stderr in a doctor report is a channel from
    an unmediated server straight into an operator's terminal."""
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {
        "a": {"command": "/ours/python", "args": ["-m", "sunglasses.proxy"]}}}))
    report = doctor.run(
        sources=[("project", config)],
        artifact="/ours/python", artifact_sha="a" * 64,
        hash_of=lambda path: "a" * 64,
        self_test=lambda: (True, dict.fromkeys(doctor.REQUIRED_CONTROLS, "FAIL")),
        launcher=lambda entry: (False, {"stderr": "SECRET upstream text"}))
    rendered = json.dumps(doctor.render(report))
    assert "SECRET upstream text" not in rendered
