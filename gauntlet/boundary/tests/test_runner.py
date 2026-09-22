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
from runner import (                                       # noqa: E402
    Ledger, LedgerRequired, SpendNotAuthorised, Timeline,
)

PAYLOAD = b'{"jsonrpc":"2.0","id":"c-1","result":{"content":"SYNTHETIC-CANARY-01"}}'


def _stub_transcript(path, content):
    path.write_text(json.dumps({"type": "assistant", "message": {"content": [
        {"type": "tool_result", "content": content}]}}) + "\n")
    return path


# ── the package is consumed as delivered ───────────────────────────────────

def test_the_manifest_is_read_not_rebuilt():
    """SELF CONSISTENT, not a remembered pair of numbers.

    This used to assert 12 scenarios and 21 variants. Those were true of the
    package as first delivered and they are a statement about one delivery
    rather than about the loader, so the arrival of G2-13 onwards would fail
    this test for being correct. What has to hold is that the manifest's own
    counts describe what is actually on disk, which is the thing that catches a
    seed added to the directory and not to the manifest, or the reverse.
    """
    manifest = runner.load_manifest()
    ids = [e["id"] for e in manifest["scenarios"]]
    assert ids == sorted(ids), f"the manifest is not in id order: {ids}"
    assert len(ids) == len(set(ids)), "a scenario id appears twice"
    assert manifest["scenario_count"] == len(ids), (
        f"the manifest claims {manifest['scenario_count']} scenarios and lists "
        f"{len(ids)}")
    assert ids, "the package is empty"


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


# ── the ledger, which is the only thing between a run and an overspend ─────

def test_an_unreadable_ledger_line_refuses_instead_of_skipping_it(tmp_path):
    """The old loop did `continue`, which BUYS a call.

    A truncated write, a partial flush or two writers interleaving produces a
    line that will not parse, and skipping it under-counts by exactly the
    mechanism the class comment calls the dangerous direction. Not readable is
    not the same as not a charge.
    """
    path = tmp_path / "calls.jsonl"
    ledger = Ledger(path, budget=2)
    ledger.charge("G2-01", "main")
    with path.open("a") as fh:
        fh.write('{"charge": true, "charge_i\n')          # truncated
    with pytest.raises(runner.LedgerUnreadable):
        Ledger(path, budget=2)


def test_an_ambiguous_charge_field_is_refused(tmp_path):
    """Only the literal true is a charge. `"true"`, 1 and null are not."""
    path = tmp_path / "calls.jsonl"
    for value in ('"true"', "1", "null", "false"):
        path.write_text('{"charge": %s, "charge_id": "abc"}\n' % value)
        with pytest.raises(runner.LedgerUnreadable):
            Ledger(path, budget=5)


def test_a_repeated_charge_id_is_refused(tmp_path):
    path = tmp_path / "calls.jsonl"
    path.write_text('{"charge": true, "charge_id": "dup"}\n'
                    '{"charge": true, "charge_id": "dup"}\n')
    with pytest.raises(runner.LedgerUnreadable):
        Ledger(path, budget=5)


def test_the_budget_holds_against_a_second_process(tmp_path):
    """Two runners each read `spent`, each see room, and the budget buys one
    more call than it authorised, with neither receipt showing a fault.

    The count is re-read from disk inside an exclusive lock, so the number an
    instance remembers cannot be what authorises a call.
    """
    path = tmp_path / "calls.jsonl"
    first, second = Ledger(path, budget=1), Ledger(path, budget=1)
    first.charge("G2-01", "main")
    with pytest.raises(SpendNotAuthorised):
        second.charge("G2-02", "main")
    assert len(Ledger(path, budget=1)._charges()) == 1


def test_a_charge_is_tied_to_what_it_produced(tmp_path):
    """A charge written before a call and never answered is a call whose result
    nobody can find, and the exam had rows in exactly that state."""
    path = tmp_path / "calls.jsonl"
    ledger = Ledger(path, budget=3)
    paid = ledger.charge("G2-01", "main")
    orphan = ledger.charge("G2-02", "main")
    ledger.settle(paid, artifact="live/G2-01.main.proxy_strict/row.json",
                  outcome="SETTLED")
    unsettled = ledger.unsettled()
    assert [row["charge_id"] for row in unsettled] == [orphan], unsettled
    assert Ledger(path, budget=3).spent == 2, "a terminal row was counted as a charge"


def test_the_matrix_drives_every_variant_not_only_the_first():
    """`variants[0]` reported on a scenario having exercised a third of it.

    A scenario's variants are different experiments, not restatements of one.
    G2-06's three are a description mutation, a schema mutation and a benign
    drift, and only one of those can be run first. Driven as source, because the
    matrix cannot be executed here without live calls.
    """
    import ast
    import pathlib as _pathlib

    source = (_pathlib.Path(__file__).resolve().parents[1] / "batch.py").read_text()
    assert 'scenario["variants"][0]' not in source, (
        "the batch still drives only the first variant of each scenario")

    tree = ast.parse(source)
    main = next(node for node in ast.walk(tree)
                if isinstance(node, ast.FunctionDef) and node.name == "main")
    # run_one is reached from a loop over the variant list, not from an index.
    subscripts = [node for node in ast.walk(main) if isinstance(node, ast.Subscript)
                  and isinstance(node.value, ast.Subscript)]
    assert not subscripts, ast.dump(subscripts[0]) if subscripts else ""


def test_a_scenario_with_several_variants_is_actually_several_experiments():
    """The claim the test above depends on, checked against the package."""
    manifest = runner.load_manifest()
    several = {}
    for entry in manifest["scenarios"]:
        names = [v["name"] for v in runner.scenario_of(entry)["variants"]]
        if len(names) > 1:
            several[entry["id"]] = names
    assert several, "no scenario has more than one variant, so this matters less"
    assert "G2-06" in several and len(several["G2-06"]) == 3, several.get("G2-06")
    for scenario_id, names in several.items():
        assert len(set(names)) == len(names), f"{scenario_id} repeats a variant name"


# ── the package now holds two generations of seed ──────────────────────────
# G2-01..G2-12 are the original Gate 2 delivery. G2-13..G2-28 arrived with
# ASTRA's Gate 3 design review and describe themselves differently: `routes`
# rather than `route`, a `schedule_file` of operations rather than an inline
# `schedule`, a `payload_ref` into another seed's payload rather than a `payload`
# of their own, and a `mutation_must_reject` naming the change that has to turn
# the fixture red. Seven variant keys are common to both.
#
# These tests hold what is true of EVERY seed whatever its generation, so the
# package can grow again without them failing for being correct, and they name
# the second generation's own requirement separately.

def _generation(scenario_id):
    return "g3" if scenario_id >= "G2-13" else "g2"


def test_every_scenario_in_the_manifest_is_actually_on_disk():
    """A half copied delivery is the failure this catches.

    The manifest is the index and the directories are the thing; a seed listed
    but not copied, or copied but not listed, is how a package quietly runs 27
    of its 28 seeds.
    """
    missing = []
    for entry in runner.load_manifest()["scenarios"]:
        folder = runner.PACKAGE / entry["directory"]
        for required in ("scenario.json", "expected.json"):
            if not (folder / required).is_file():
                missing.append(f"{entry['id']}/{required}")
    assert missing == [], missing


def test_every_variant_names_itself_and_its_scenario_agrees():
    unreadable = []
    for entry in runner.load_manifest()["scenarios"]:
        scenario = runner.scenario_of(entry)
        assert scenario["id"] == entry["id"], (scenario["id"], entry["id"])
        names = [variant.get("name") for variant in scenario["variants"]]
        if not all(names):
            unreadable.append(f"{entry['id']}: a variant with no name")
        if len(set(names)) != len(names):
            unreadable.append(f"{entry['id']}: a repeated variant name in {names}")
    assert unreadable == [], unreadable


def test_the_second_generation_declares_its_own_routes_and_the_first_does_not():
    """Where the route comes from is a real difference between the two shapes.

    The first version of this test asserted that EVERY variant names a route,
    which is untrue of the original package and was untrue before the new seeds
    arrived: G2-01 through G2-12 carry no route at all, and the harness derives
    `proxy_strict` plus a control for the seeds in CONTROL_SEEDS. The new seeds
    declare `routes` themselves, including `no_mediation`. Asserting the new
    shape over the old one would have failed a package that was correct, so the
    difference is written down here rather than smoothed over.
    """
    derived, declared = [], {}
    for entry in runner.load_manifest()["scenarios"]:
        for variant in runner.scenario_of(entry)["variants"]:
            tag = f"{entry['id']}.{variant['name']}"
            if _generation(entry["id"]) == "g3":
                routes = variant.get("routes")
                assert routes, f"{tag} declares no routes"
                assert isinstance(routes, list) and all(routes), tag
                declared[tag] = routes
            elif variant.get("routes"):
                derived.append(tag)
    assert derived == [], (
        f"first generation variants are not supposed to declare routes: {derived}")
    assert declared, "no second generation seed declared a route"


def test_every_second_generation_seed_carries_its_rejecting_mutation():
    """The requirement that makes these fixtures worth running.

    A fixture with no mutation that turns it red cannot be distinguished from a
    fixture that passes because nothing is checking. ASTRA shipped one per
    variant and this is where it is held.
    """
    without = []
    for entry in runner.load_manifest()["scenarios"]:
        if _generation(entry["id"]) != "g3":
            continue
        for variant in runner.scenario_of(entry)["variants"]:
            if not variant.get("mutation_must_reject"):
                without.append(f"{entry['id']}.{variant['name']}")
    assert without == [], without


def test_a_payload_reference_points_at_a_file_that_is_there_with_those_bytes():
    """The new seeds reuse the old seeds' payloads by hash rather than copying
    them, so a drifted or missing source is a silent change of stimulus.

    THROUGH THE RESOLVER, not around it. This read `ref["path"]` directly and so
    asserted something nobody requires: that the literal path in the seed is on
    disk. One of the five references names a private temporary tree that was
    reaped months ago, which made this test red over a file whose bytes are
    present, intact, and hash to exactly what the seed declares. The rule that
    matters is the resolver's, and it is the rule every consumer uses, so this
    asserts that one and nothing else.
    """
    broken = []
    for entry in runner.load_manifest()["scenarios"]:
        for variant in runner.scenario_of(entry)["variants"]:
            if not variant.get("payload_ref"):
                continue
            try:
                runner.resolve_payload_ref(variant)
            except (FileNotFoundError, ValueError) as exc:
                broken.append(f"{entry['id']}.{variant['name']}: {exc}")
    assert broken == [], broken


def test_the_two_payload_resolvers_agree_on_every_reference():
    """`runner` resolves references for the harness and `gen2.materialize`
    resolves them for the materialiser. Two rules for one question is how the
    harness comes to read one stimulus and the artifacts get built from another,
    which is the exact failure `materialize.assert_same_seed` exists to catch
    one layer up. So they are pinned to each other here.
    """
    from gen2 import materialize

    disagreed = []
    for entry in runner.load_manifest()["scenarios"]:
        for variant in runner.scenario_of(entry)["variants"]:
            ref = variant.get("payload_ref")
            if not ref:
                continue
            where = f"{entry['id']}.{variant['name']}"
            mine = runner._durable(pathlib.Path(ref["path"]))
            theirs = materialize.resolved_payload_path(ref, where=where)
            if mine != theirs:
                disagreed.append(f"{where}: runner {mine}, materialise {theirs}")
    assert disagreed == [], disagreed


def test_the_payload_resolver_checks_the_hash_and_not_just_the_path(tmp_path):
    """A resolver that trusts the path turns the saving into the hazard.

    The new seeds reuse earlier payloads by reference so one stimulus lives in
    one place. That is only safe if every resolution verifies the digest, since
    a drifted source would otherwise change the stimulus for every seed pointing
    at it, silently and everywhere at once.
    """
    import hashlib

    body = b"AKIAGATE2SYNTHETIC001"
    source = tmp_path / "payload.txt"
    source.write_bytes(body)
    variant = {"name": "v", "payload_ref": {
        "path": str(source), "sha256": hashlib.sha256(body).hexdigest()}}
    assert runner.resolve_payload_ref(variant) == body

    source.write_bytes(body + b"X")
    with pytest.raises(ValueError) as drifted:
        runner.resolve_payload_ref(variant)
    assert "drifted" in str(drifted.value)

    source.unlink()
    with pytest.raises(FileNotFoundError):
        runner.resolve_payload_ref(variant)
    with pytest.raises(KeyError):
        runner.resolve_payload_ref({"name": "no ref"})


def test_every_referenced_payload_in_the_package_resolves_today():
    resolved = 0
    for entry in runner.load_manifest()["scenarios"]:
        for variant in runner.scenario_of(entry)["variants"]:
            if variant.get("payload_ref"):
                assert runner.resolve_payload_ref(variant)
                resolved += 1
    assert resolved, "no seed used a payload_ref, so the resolver is untested here"
