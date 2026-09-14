"""The adapter drives a real session, or it refuses. No third outcome.

`plan()` answers whether a schedule COULD be driven. Nothing executed it, so the
whole generation 2 set was a coverage claim with no run behind it, which is the
shape of defect this harness has produced twice already: a capability present in
the configuration and absent from the run.

These drive the control route through real pipes and real processes, with no
model call anywhere, and check the evidence rather than the exit status.
"""
import hashlib
import json
import pathlib
import shutil
import sys
import uuid

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import runner                                                  # noqa: E402
from gen2 import adapter, artifacts, execute                   # noqa: E402

PRIVATE_TMP = pathlib.Path("/private/tmp")


def _case(scenario_id, variant_name):
    entry = next(e for e in runner.load_manifest()["scenarios"]
                 if e["id"] == scenario_id)
    variant = next(v for v in runner.scenario_of(entry)["variants"]
                   if v["name"] == variant_name)
    return entry, variant


@pytest.fixture
def run_root():
    root = PRIVATE_TMP / f"gen2-exec-{uuid.uuid4().hex[:10]}"
    yield root
    shutil.rmtree(root, ignore_errors=True)


def test_a_control_session_runs_and_returns_the_declared_terminal(run_root):
    """G2-13.error_message, end to end, on no_mediation.

    The scenario puts the injection in `error.message`, so the terminal reply IS
    the hostile frame and the control route is supposed to deliver it unchanged.
    Asserting equality with the declared frame is the point: a run that returned
    something plausible instead would be the harness answering for the upstream.
    """
    entry, variant = _case("G2-13", "error_message")
    run = execute.run(entry, variant, route="no_mediation", run_root=run_root)

    declared = json.loads(
        (run.run_dir / variant["upstream_output"]).read_bytes().splitlines()[0])
    assert run.terminal == declared
    assert run.primary_id == declared["id"]


def test_the_wire_is_recorded_as_bytes_on_both_sides(run_root):
    """Evidence, not a summary of evidence."""
    entry, variant = _case("G2-13", "error_message")
    run = execute.run(entry, variant, route="no_mediation", run_root=run_root)

    client = (run.run_dir / "client.wire.jsonl").read_bytes()
    upstream = (run.run_dir / "upstream.wire.jsonl").read_bytes()
    assert client == run.client_wire and upstream == run.upstream_wire
    # The scripted request is in there verbatim, terminator included.
    sent = (run.run_dir / variant["requests"]).read_bytes()
    assert sent in client, client
    assert upstream.endswith(b"\n")


def test_the_upstream_frames_are_checked_against_the_declaration(run_root):
    """A replayed upstream that answered something else must not read as a run.

    The declared frames are the scenario. If what came back is not what the
    seed declares, the row is about this harness, and it says so rather than
    producing a terminal reply for a grader to score.
    """
    entry, variant = _case("G2-13", "error_message")
    run = execute.run(entry, variant, route="no_mediation", run_root=run_root)
    assert run.upstream_as_declared is True

    tampered = run.run_dir / variant["upstream_output"]
    frame = json.loads(tampered.read_bytes().splitlines()[0])
    frame["error"]["message"] = "a different answer entirely"
    tampered.write_bytes(json.dumps(frame).encode() + b"\n")

    with pytest.raises(execute.UpstreamNotAsDeclared):
        execute.run(entry, variant, route="no_mediation",
                    run_root=run_root, materialise=False)


def test_a_route_this_adapter_cannot_drive_is_refused_by_name(run_root):
    entry, variant = _case("G2-13", "error_message")
    with pytest.raises(execute.UnsupportedRoute) as exc:
        execute.run(entry, variant, route="proxy_strict", run_root=run_root)
    assert "proxy_strict" in str(exc.value)


def test_an_undrivable_schedule_is_refused_before_a_process_starts(run_root):
    """plan() first. Half a schedule produces evidence, which is the whole point."""
    # A REAL generation 2 variant. The first version of this named G2-08, which
    # is generation 1 and has no materialised directory at all, so it raised
    # from the artifacts loader and the refusal this test is about never ran.
    entry, variant = _case("G2-14", "upstream_log")
    with pytest.raises(adapter.UnimplementedOperation):
        execute.run(entry, variant, route="no_mediation", run_root=run_root)
    assert not run_root.exists(), "a refused variant must not leave a run behind"


def test_a_terminal_that_never_arrives_is_a_timeout_not_a_success(run_root, monkeypatch,
                                                                 tmp_path):
    """A declared reply that does not turn up in time is an absence, not a result.

    Driven against a replay that answers the handshake and then stalls past the
    deadline, which is what a hung or dying upstream looks like from here. It
    has sent nothing the seed does not declare, so calling it an undeclared
    stream would point at the wrong thing; it is short, and short is a timeout.

    Two earlier versions of this test proved nothing. One emptied the run root's
    upstream file, and the replay's own "no further declared frame" refusal
    carries the client's id, so it arrived looking exactly like a terminal. The
    other altered the declared id, which made the terminal unexpected and the
    guard correctly silent.
    """
    entry, variant = _case("G2-13", "error_message")
    handshake = (artifacts.of_record(entry, variant).path
                 / "initialize.response.jsonl").read_bytes().splitlines()[0]
    stall = tmp_path / "stalling_replay.py"
    stall.write_text(
        "import sys, time\n"
        "sys.stdin.buffer.readline()\n"
        f"sys.stdout.buffer.write({handshake!r} + b'\\n')\n"
        "sys.stdout.buffer.flush()\n"
        "time.sleep(30)\n")
    monkeypatch.setattr(execute, "REPLAY", stall)

    with pytest.raises(execute.TerminalNeverArrived) as exc:
        execute.run(entry, variant, route="no_mediation", run_root=run_root,
                    timeout_ms=400)
    assert "1 of 2 declared frames" in str(exc.value), str(exc.value)


def test_every_drivable_variant_runs_on_the_control_route(run_root):
    """The whole drivable set, through real pipes, in one sweep.

    A driver proved on one variant is a driver proved on one variant. This is
    the difference between saying the adapter can execute and having watched it
    execute, and it is where a fixture whose shape nobody anticipated shows up.

    Zero model calls. Nothing here reaches the network or an API.
    """
    drivable, ran = [], []
    for entry in runner.load_manifest()["scenarios"]:
        for variant in runner.scenario_of(entry)["variants"]:
            if "routes" not in variant or "no_mediation" not in variant["routes"]:
                continue
            try:
                adapter.plan(artifacts.of_record(entry, variant).schedule)
            except (adapter.UnimplementedOperation, adapter.NoStepsToDrive):
                continue
            drivable.append(f"{entry['id']}.{variant['name']}")
            root = run_root / f"{entry['id']}.{variant['name']}"
            run = execute.run(entry, variant, route="no_mediation", run_root=root)
            ran.append({
                "id": f"{entry['id']}.{variant['name']}",
                "terminal": run.terminal is not None,
                "expected": run.terminal_expected,
                "as_declared": run.upstream_as_declared,
                "client_bytes": len(run.client_wire),
            })

    assert drivable, "nothing was drivable, which is not a passing state"
    # Terminal presence has to MATCH the declaration, not be universally true.
    # G2-20.unsolicited_response answers an id nobody asked for and never
    # answers the primary one, and that absence is the scenario.
    assert all(r["terminal"] == r["expected"] and r["as_declared"] for r in ran), ran
    assert all(r["client_bytes"] > 0 for r in ran), ran
    # 19 is measured, by the same sweep that corrected 297 to 340 in the step
    # contract. If ASTRA's delivery changes this changes with it, loudly.
    assert len(ran) == 19, [r["id"] for r in ran]


def test_a_scenario_whose_own_request_is_an_initialize_is_not_eaten_by_the_handshake(run_root):
    """G2-13.initialize_text puts the injection in the initialize RESULT.

    The replay answered any `initialize` with the session handshake, so this
    scenario's own request, id 1306, got the setup response and the declared
    frame carrying the injection was never served. The surface the variant
    exists to test went unexercised while the run looked ordinary.

    Correlation is by id, which the fixtures already provide on both sides, and
    not by method. The one thing a method test cannot distinguish is two calls
    of the same method, which is exactly this scenario.
    """
    entry, variant = _case("G2-13", "initialize_text")
    run = execute.run(entry, variant, route="no_mediation", run_root=run_root)

    declared = json.loads(
        (artifacts.of_record(entry, variant).path
         / variant["upstream_output"]).read_bytes().splitlines()[0])
    assert run.terminal == declared
    assert "instructions" in run.terminal["result"], run.terminal


def test_a_scenario_that_declares_no_reply_for_its_primary_id_is_not_a_timeout(run_root):
    """G2-20.unsolicited_response is an upstream answering an id nobody asked for.

    Request 2003 goes out, the declared frame comes back as 82003, and the
    primary request is never answered. That is the scenario, not a failure to
    drive it, and the absence is the observation.

    The guard read the outcome and could not tell the two apart, so it called a
    correctly executed scenario a harness fault. Whether a terminal is expected
    is in the declaration, and that is where it is read from.
    """
    entry, variant = _case("G2-20", "unsolicited_response")
    run = execute.run(entry, variant, route="no_mediation", run_root=run_root)

    assert run.terminal_expected is False
    assert run.terminal is None
    assert run.upstream_as_declared is True
    record = json.loads((run.run_dir / "execution.json").read_text())
    assert record["terminal_expected"] is False and record["terminal_arrived"] is False


def test_the_upstream_serves_the_files_the_SCHEDULE_names(run_root):
    """G2-23.frame_exact declares `override.upstream.raw`, not its own upstream file.

    The executor served `variant["upstream_output"]` for every variant, and the
    declared check compared the wire against that same file, so both halves
    agreed and both were wrong. Three of the nineteen ran a different experiment
    and reported green.

    This one is the worst of the three. The override is 4,194,304 bytes, exactly
    the wire frame limit, which IS the scenario, and a 244 byte file was served
    in its place. The frame boundary the variant exists to sit on was never
    approached.
    """
    entry, variant = _case("G2-23", "frame_exact")
    record = artifacts.of_record(entry, variant)
    override = (record.path / "override.upstream.raw").read_bytes()
    assert len(override) == 4 * 1024 * 1024, "the fixture is the frame limit itself"

    run = execute.run(entry, variant, route="no_mediation", run_root=run_root,
                      timeout_ms=20000)
    assert len(run.upstream_wire) > 4 * 1024 * 1024, len(run.upstream_wire)
    assert run.upstream_wire.endswith(override.rstrip(b"\n") + b"\n")


def test_an_upstream_with_no_declared_step_serves_nothing(run_root):
    """G2-21.client_malformed_tail declares no upstream send at all.

    Its two steps are both client origin, a malformed prefix and a clean tail,
    and the question is what the receiver does with the tail. Serving its
    `upstream_output` anyway put a frame on the wire the schedule never asked
    for, which is the harness adding to the scenario.
    """
    entry, variant = _case("G2-21", "client_malformed_tail")
    run = execute.run(entry, variant, route="no_mediation", run_root=run_root)
    handshake = (artifacts.of_record(entry, variant).path
                 / "initialize.response.jsonl").read_bytes()
    assert run.upstream_wire == handshake, run.upstream_wire[:300]
    assert run.terminal_expected is False
