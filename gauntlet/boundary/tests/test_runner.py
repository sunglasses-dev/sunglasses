"""The runner, and the control that gives every other row its meaning.

The no-mediation control is not a formality. Without it "the payload was blocked"
and "the payload never arrived" produce the same empty destination, and a whole
scenario grid can read as a success because nothing ever ran.
"""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import runner                                              # noqa: E402
from client.observe import InstrumentedClient, Mode        # noqa: E402
from destination.sink import Destination                   # noqa: E402
from proxy.passthrough import Passthrough                  # noqa: E402
from runner import Ledger, LedgerRequired, Timeline        # noqa: E402

PAYLOAD = b'{"jsonrpc":"2.0","id":"c-1","result":{"content":"SYNTHETIC-CANARY-01"}}'


def _stub_transcript(path, content):
    path.write_text(json.dumps({"type": "assistant", "message": {"content": [
        {"type": "tool_result", "content": content}]}}) + "\n")
    return path


# ── the package is consumed as delivered ───────────────────────────────────

def test_the_manifest_is_read_not_rebuilt():
    manifest = runner.load_manifest()
    assert manifest["scenario_count"] == 12 and manifest["variant_count"] == 21
    ids = [e["id"] for e in manifest["scenarios"]]
    assert ids == sorted(ids) and len(ids) == 12


def test_every_scenario_directory_has_its_variants():
    total = sum(len(runner.scenario_of(e)["variants"])
                for e in runner.load_manifest()["scenarios"])
    assert total == runner.load_manifest()["variant_count"]


# ── one ordered timeline per scenario ──────────────────────────────────────

def test_a_timeline_is_one_run_id_and_a_monotonic_seq(tmp_path):
    entry = runner.load_manifest()["scenarios"][8]          # G2-09
    variant = runner.scenario_of(entry)["variants"][0]
    timeline = runner.run_variant(entry, variant, outdir=tmp_path)
    rows = [json.loads(l) for l in timeline.write(tmp_path).read_text().splitlines()]
    assert len({r["run_id"] for r in rows}) == 1
    assert [r["seq"] for r in rows] == list(range(len(rows)))
    assert {r["layer"] for r in rows} >= {"runner", "destination"}
    assert rows[0]["kind"] == "SCENARIO_OPENED" and rows[-1]["kind"] == "SCENARIO_CLOSED"


# ── THE CONTROL ────────────────────────────────────────────────────────────

def test_the_no_mediation_control_shows_the_payload_reaching_the_model(tmp_path):
    """Nothing mediates, so the model is shown exactly what upstream sent.

    This row is what makes a withheld row meaningful. If the control does not
    deliver, the harness is not wired up and every "blocked" result in the grid
    is an artefact.
    """
    transcript = _stub_transcript(tmp_path / "t.jsonl", PAYLOAD.decode())
    client = InstrumentedClient(tmp_path, mode=Mode.REPLAY)
    observation = InstrumentedClient.compare(
        client.replay("CONTROL", "no_mediation", transcript), PAYLOAD)
    assert observation.identical is True, "the control did not deliver the payload"
    assert b"SYNTHETIC-CANARY-01" in observation.tool_result_bytes


def test_a_mediated_run_differs_from_the_control_on_the_same_payload(tmp_path):
    """The contrast, on one payload, so the difference is the MEDIATION."""
    proxy = Passthrough(deadline_ms=150, watchdog_ms=3000)
    outcome = proxy.submit(
        "result", request_id="c-1", payload=PAYLOAD.decode(),
        scanner=lambda _p, _c: [sys.executable, "-c",
                                "import sys,time;sys.stdin.buffer.read()\n"
                                "while True: time.sleep(0.05)"]).result(timeout=2.0)
    withheld = json.dumps(outcome.replacement, separators=(",", ":")).encode()
    transcript = _stub_transcript(tmp_path / "t.jsonl", withheld.decode())
    client = InstrumentedClient(tmp_path, mode=Mode.REPLAY)
    observation = InstrumentedClient.compare(
        client.replay("G2-09", "result", transcript), withheld)
    assert observation.identical is True, "the model was not shown what the proxy sent"
    assert b"SYNTHETIC-CANARY-01" not in observation.tool_result_bytes, (
        "the withheld replacement carried the payload it withheld")
    assert observation.tool_result_bytes != PAYLOAD


def test_the_destination_distinguishes_blocked_from_never_ran(tmp_path):
    """Three empty receipts, and only one of them is a result.

    This test used to know two states, never ran and heard nothing. The exam
    found the third one sitting between them and being reported as the second:
    an observer that ran, was never asked to look at the transport under test,
    and therefore heard nothing it could have heard. `nothing_arrived` now
    requires a calibration and a collection behind it, and the middle case says
    `observation_incomplete` instead of quietly reading as a clean block.
    """
    never = Destination(drop_dir=tmp_path / "a").receipt()

    with Destination(drop_dir=tmp_path / "b") as unasked:
        unobserved = unasked.receipt()

    with Destination(drop_dir=tmp_path / "c") as watched:
        watched.calibrate("before")
        watched.collect_drops()
        watched.calibrate("after")
        observed = watched.receipt()

    assert never["listened"] is False and never["nothing_arrived"] is False
    assert unobserved["listened"] is True, "it did run"
    assert unobserved["nothing_arrived"] is False, (
        "an observer that was never asked to look at the file transport "
        "reported that nothing arrived, which is the false negative the exam "
        "could not read either way")
    assert unobserved["observation_incomplete"] is True
    assert observed["listened"] is True and observed["nothing_arrived"] is True
    assert observed["observation_complete"] is True


# ── the ledger a live batch cannot proceed without ─────────────────────────

def test_live_without_a_ledger_is_refused(tmp_path):
    entry = runner.load_manifest()["scenarios"][0]
    variant = runner.scenario_of(entry)["variants"][0]
    with pytest.raises(LedgerRequired):
        runner.run_variant(entry, variant, outdir=tmp_path, live=True, ledger=None)


def test_the_ledger_is_durable_across_processes(tmp_path):
    """A budget kept in memory disappears with a crash and the count restarts."""
    path = tmp_path / "calls.jsonl"
    first = Ledger(path, budget=3)
    first.charge("G2-01", "result")
    first.charge("G2-02", "result")
    assert Ledger(path, budget=3).spent == 2, (
        "a second process read the ledger as empty; the ceiling would restart")
    assert Ledger(path, budget=3).remaining() == 1


def test_the_ledger_refuses_past_the_ceiling_and_says_the_count(tmp_path):
    ledger = Ledger(tmp_path / "calls.jsonl", budget=1)
    ledger.charge("G2-01", "result")
    with pytest.raises(Exception) as refused:
        ledger.charge("G2-02", "result")
    assert "budget of 1" in str(refused.value)
    assert "not this run's decision" in str(refused.value)


def test_a_charge_is_written_before_the_call_would_be_made(tmp_path):
    """So a crashed run still leaves the count it spent."""
    path = tmp_path / "calls.jsonl"
    ledger = Ledger(path, budget=2)
    ledger.charge("G2-01", "result", note="about to call")
    rows = [json.loads(l) for l in path.read_text().splitlines()]
    assert rows and rows[0]["scenario_id"] == "G2-01"


def test_replay_makes_no_live_calls_at_all(tmp_path):
    code = runner.main(["--outdir", str(tmp_path), "--only", "G2-09"])
    assert code == 0
    client = InstrumentedClient(tmp_path, mode=Mode.REPLAY)
    assert client.calls_made == 0
    assert not (tmp_path / "calls.jsonl").exists()
