"""The dispatcher has to SELECT the fault, not merely be configured with one.

ASTRA's vendored test reads the configuration and checks the modes are named in
it. That is the right thing for him to check and it is not enough on its own: a
dispatcher that names three modes in its argv and then runs an ordinary scan
every time would pass it, and every G2-08/09/11 row would go on measuring an
unfaulted session exactly as before. A green configuration test over an inert
capability is the shape of defect this whole repair is about.

So these drive the dispatcher.
"""
import hashlib
import json
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import batch                                                  # noqa: E402
from proxy import fault_dispatch                              # noqa: E402

HELD = "the document this scenario declares a fault for\n"
OTHER = "a different document in the same session\n"


def _run_dir(tmp_path, kind, payload=HELD, target="scanner_worker"):
    """The materialiser writes the payload as `payload.txt`, whatever the seed calls it.

    The first version of this helper wrote `result.payload.txt`, the name the
    VARIANT declares, and `run_one` keyed its record off that name too. Both
    agreed and both were wrong: materialisation writes the same bytes as
    `payload.txt`, so the record was never written for a single real row and
    ASTRA measured 0 fault records and 0 fault-worker starts across all six
    configurations while this file was green. A fixture assembled from my
    assumption proves the assumption.
    """
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "payload.txt").write_text(payload)
    (run_dir / "materialised.fault.json").write_text(json.dumps({
        "scenario_id": "G2-09", "variant": "result",
        "fault": {"kind": kind, "direction": "result", "target": target},
        "payload": "payload.txt",
        "payload_sha256": hashlib.sha256(payload.encode()).hexdigest(),
    }))
    return run_dir


@pytest.mark.parametrize("kind,mode", [("exception", "exception"),
                                       ("hang", "hang"),
                                       ("barrier_hold", "barrier")])
def test_the_declared_fault_is_selected_for_the_declared_payload(tmp_path, kind, mode):
    """`barrier_hold` in the scenario, `barrier` on the worker's command line."""
    assert fault_dispatch.declared_fault(_run_dir(tmp_path, kind), HELD) == mode


def test_a_different_document_in_the_same_session_is_not_faulted(tmp_path):
    """The control, and the reason matching is by digest rather than by order.

    G2-11 holds one request under a barrier and requires a second request, id
    112, to complete normally in the same session. A dispatcher that faulted the
    first message it saw would fault whichever one the pump happened to hand it
    first, and the pump deliberately does not preserve order.
    """
    assert fault_dispatch.declared_fault(_run_dir(tmp_path, "hang"), OTHER) is None


def test_a_run_with_no_declared_fault_scans(tmp_path):
    run_dir = tmp_path / "plain"
    run_dir.mkdir()
    assert fault_dispatch.declared_fault(run_dir, HELD) is None


def test_an_unreadable_fault_record_scans_rather_than_guessing(tmp_path):
    """Injecting a fault nobody asked for is worse than missing one that was.

    A row that was faulted by accident still produces a verdict, and the verdict
    looks like a candidate defect.
    """
    run_dir = tmp_path / "broken"
    run_dir.mkdir()
    (run_dir / "materialised.fault.json").write_text("{not json")
    assert fault_dispatch.declared_fault(run_dir, HELD) is None


def test_the_dispatcher_actually_runs_the_faulted_worker(tmp_path):
    """End to end through the real package worker, not just the decision.

    `exception` because it is the one that terminates by itself: a non-zero exit
    from the package's own fault_worker is the observable proof that the mode
    reached it.
    """
    run_dir = _run_dir(tmp_path, "exception")
    completed = subprocess.run(
        [sys.executable, str(pathlib.Path(fault_dispatch.__file__)),
         "--run-dir", str(run_dir), "--channel", "api_response"],
        input=HELD.encode(), capture_output=True)

    assert completed.returncode != 0, "the exception fault did not reach the worker"
    assert b"GATE2 synthetic scanner exception" in completed.stderr, completed.stderr[-400:]
    assert (run_dir / "fault.exception.started").is_file(), (
        "the worker never recorded that it started")


def test_an_ordinary_scan_is_not_reported_as_a_fault(tmp_path):
    """The other half of the control: no fault record, no fault."""
    run_dir = tmp_path / "clean"
    run_dir.mkdir()
    completed = subprocess.run(
        [sys.executable, str(pathlib.Path(fault_dispatch.__file__)),
         "--run-dir", str(run_dir), "--channel", "api_response"],
        input=HELD.encode(), capture_output=True)

    assert b"GATE2 synthetic scanner exception" not in completed.stderr
    assert not (run_dir / "fault.exception.started").exists()


def test_every_fault_scenario_writes_its_record_through_the_real_batch_path(tmp_path):
    """THROUGH run_one, not through a run directory I assembled.

    This is the test that was missing. The ones above drive `declared_fault`
    against a directory built by hand, and a hand-built directory can agree with
    a wrong assumption forever. ASTRA measured what the actual batch path does:
    0 fault records, 0 fault-worker starts, six configurations.
    """
    import shutil
    import uuid
    import runner
    from destination.sink import Destination

    written = {}
    for scenario_id in ("G2-08", "G2-09", "G2-11"):
        entry = next(e for e in runner.load_manifest()["scenarios"]
                     if e["id"] == scenario_id)
        for name in ("request", "result"):
            variant = next(v for v in runner.scenario_of(entry)["variants"]
                           if v["name"] == name)
            root = pathlib.Path("/private/tmp") / f"faultrec-{uuid.uuid4().hex[:10]}"
            start = Destination.start
            Destination.start = lambda self: "file:///dev/null"
            try:
                row = batch.run_one(
                    entry, variant, outdir=root, route="proxy_strict",
                    engine_root=pathlib.Path.home() / "sunglasses-dev" / "glasses",
                    upstream_argv=[sys.executable], ledger=None,
                    dry_run=True, call_no=0)
                record = pathlib.Path(row["run_dir"]) / "materialised.fault.json"
                written[f"{scenario_id}.{name}"] = (
                    json.loads(record.read_text())["fault"]["kind"]
                    if record.is_file() else None)
            finally:
                Destination.start = start
                shutil.rmtree(root, ignore_errors=True)

    assert written == {
        "G2-08.request": "exception", "G2-08.result": "exception",
        "G2-09.request": "hang", "G2-09.result": "hang",
        "G2-11.request": "barrier_hold", "G2-11.result": "barrier_hold",
    }, written


URL = "http://127.0.0.1:18762/collect"


def test_a_message_merely_quoting_the_declared_payload_is_not_faulted(tmp_path):
    """Exactness. The held text IS the declared bytes or there is no fault.

    A dispatcher matching on containment would fault any message that quotes the
    document, and the quoting message is a different experiment.
    """
    run_dir = _run_dir(tmp_path, "exception")
    assert fault_dispatch.declared_fault(run_dir, "quoting: " + HELD) is None


def test_the_record_pins_the_bytes_the_proxy_will_actually_hold(tmp_path):
    """THE DIGEST IS OF THE INSPECTION INPUT, not of the declared payload file.

    `G2-08.request` puts the 21-byte secret in `body` and a URL in `url`, and the
    proxy inspects every string leaf of the arguments and hands the scanner all
    of them joined, 52 bytes. Pinning the payload file's digest therefore only
    ever matched the result direction, where the payload happens to BE the whole
    inspection input, and all three request rows ran an ordinary scan and
    reported PROHIBITED_SECRET while the fault worker never started.

    Both spellings are kept in the record: `payload_sha256` is what the
    dispatcher matches, `payload_file_sha256` attests the document the run
    materialised.
    """
    import shutil
    import uuid
    import runner
    from destination.sink import Destination
    from proxy import passthrough

    seen = {}
    for scenario_id in ("G2-08", "G2-09", "G2-11"):
        entry = next(e for e in runner.load_manifest()["scenarios"]
                     if e["id"] == scenario_id)
        for name in ("request", "result"):
            variant = next(v for v in runner.scenario_of(entry)["variants"]
                           if v["name"] == name)
            root = pathlib.Path("/private/tmp") / f"faultpin-{uuid.uuid4().hex[:10]}"
            start = Destination.start
            Destination.start = lambda self: "file:///dev/null"
            try:
                row = batch.run_one(
                    entry, variant, outdir=root, route="proxy_strict",
                    engine_root=pathlib.Path.home() / "sunglasses-dev" / "glasses",
                    upstream_argv=[sys.executable], ledger=None,
                    dry_run=True, call_no=0)
                run_dir = pathlib.Path(row["run_dir"])
                record = json.loads((run_dir / "materialised.fault.json").read_text())
                message = json.loads((run_dir / "request.json").read_text())
                if name == "result":
                    message = json.loads(
                        (run_dir / "upstream.jsonl").read_bytes().splitlines()[0])
                held = "\n".join(v for _, v in passthrough.inspection_input(message, name))
                seen[f"{scenario_id}.{name}"] = (
                    record["payload_sha256"] == hashlib.sha256(held.encode()).hexdigest(),
                    record["payload_file_sha256"] == hashlib.sha256(
                        (run_dir / record["payload"]).read_bytes()).hexdigest(),
                )
            finally:
                Destination.start = start
                shutil.rmtree(root, ignore_errors=True)

    assert all(pinned and attested for pinned, attested in seen.values()), seen


def test_every_fault_scenario_writes_its_record_through_the_real_batch_path(tmp_path):
    """THROUGH run_one, not through a run directory I assembled.

    This is the test that was missing. The ones above drive `declared_fault`
    against a directory built by hand, and a hand-built directory can agree with
    a wrong assumption forever. ASTRA measured what the actual batch path does:
    0 fault records, 0 fault-worker starts, six configurations.
    """
    import shutil
    import uuid
    import runner
    from destination.sink import Destination

    written = {}
    for scenario_id in ("G2-08", "G2-09", "G2-11"):
        entry = next(e for e in runner.load_manifest()["scenarios"]
                     if e["id"] == scenario_id)
        for name in ("request", "result"):
            variant = next(v for v in runner.scenario_of(entry)["variants"]
                           if v["name"] == name)
            root = pathlib.Path("/private/tmp") / f"faultrec-{uuid.uuid4().hex[:10]}"
            start = Destination.start
            Destination.start = lambda self: "file:///dev/null"
            try:
                row = batch.run_one(
                    entry, variant, outdir=root, route="proxy_strict",
                    engine_root=pathlib.Path.home() / "sunglasses-dev" / "glasses",
                    upstream_argv=[sys.executable], ledger=None,
                    dry_run=True, call_no=0)
                record = pathlib.Path(row["run_dir"]) / "materialised.fault.json"
                written[f"{scenario_id}.{name}"] = (
                    json.loads(record.read_text())["fault"]["kind"]
                    if record.is_file() else None)
            finally:
                Destination.start = start
                shutil.rmtree(root, ignore_errors=True)

    assert written == {
        "G2-08.request": "exception", "G2-08.result": "exception",
        "G2-09.request": "hang", "G2-09.result": "hang",
        "G2-11.request": "barrier_hold", "G2-11.result": "barrier_hold",
    }, written


URL = "http://127.0.0.1:18762/collect"


def test_the_declared_payload_must_be_a_whole_leaf_not_a_substring(tmp_path):
    """Exactness, on the only boundary the scanner's stdin preserves.

    Leaves arrive joined by newlines, so a leaf is a complete run between them.
    A payload found mid-leaf is a different document that happens to contain
    these bytes, and faulting it would be the resemblance mistake.
    """
    run_dir = _run_dir(tmp_path, "hang", payload=HELD.rstrip("\n"))
    assert fault_dispatch.declared_fault(run_dir, "quoting " + HELD.rstrip("\n")) is None


def test_a_record_disagreeing_with_the_materialised_bytes_is_refused(tmp_path):
    """A record pinning bytes this session will not hold selects nothing.

    The dispatcher decides on the record alone, so the record is the thing that
    has to be right, and a run directory whose pin does not describe its own
    inspection input was assembled by something other than materialisation.
    """
    run_dir = _run_dir(tmp_path, "exception")
    # The file still holds bytes the message CARRIES, so the leaf match would
    # succeed on its own. Only the pinned digest separates these two states, and
    # the first version of this test rewrote the file to something the message
    # does not carry, which made it pass with the digest check deleted.
    record = json.loads((run_dir / "materialised.fault.json").read_text())
    record["payload_sha256"] = hashlib.sha256(b"a digest for other bytes").hexdigest()
    (run_dir / "materialised.fault.json").write_text(json.dumps(record))
    assert fault_dispatch.declared_fault(run_dir, HELD) is None




# ── DECLARED BUT NOT INJECTABLE ─────────────────────────────────────────────
# The delivery declares SIX kinds in the vocabulary this dispatcher reads
# (`variant["fault"]["kind"]`). Three are selectable and three are G2-10's
# malformed-result kinds, which reach this branch. The dispatcher used to
# answer both "no fault declared" and "a fault I cannot inject" with an
# ordinary scan, and the row still produced a verdict.
#
# The thirteen `arm_fault` STEP kinds in the second generation schedules are a
# different vocabulary with the same field name. The adapter refuses those; they
# never reach this file. Conflating the two is how this list first got written
# out of names that cannot appear here.

# MEASURED ACROSS THE DELIVERY, and the result changed this row twice.
#
# Every fault targeting `scanner_worker` is already selectable — G2-08's
# exception, G2-09's hang, G2-11's barrier_hold. Every kind that is NOT
# selectable targets something else: G2-10 aims `invalid_json` and
# `invalid_result_shape` at `upstream_stdout` and `malformed_hook_output` at
# `hook_stdout`. So there is no gap in the scanner lane at all, and refusing
# G2-10 would kill three scenarios in which the scanner is supposed to run
# normally while something else misbehaves.
#
# I had this wrong and the batch path proved it: before the target check,
# `declared_kind` reported `invalid_result_shape` and `malformed_hook_output`
# for real run directories built by `run_one`, so the refusal I added to stop a
# wrong verdict would itself have produced two. The suite did not catch it —
# the batch-path row above covers G2-08, G2-09 and G2-11 and not G2-10.
UNINJECTABLE = ["some_future_scanner_fault", "worker_emits_nothing"]

NOT_OURS = [("invalid_json", "upstream_stdout"),
            ("invalid_result_shape", "upstream_stdout"),
            ("malformed_hook_output", "hook_stdout")]


@pytest.mark.parametrize("kind,target", NOT_OURS)
def test_a_fault_aimed_elsewhere_is_not_this_dispatchers_refusal(tmp_path, kind, target):
    """G2-10's three. The scanner runs NORMALLY; the upstream or the hook is
    what misbehaves. A refusal here is a false kill of a working scenario."""
    run_dir = _run_dir(tmp_path, kind, target=target)
    assert fault_dispatch.declared_fault(run_dir, HELD) is None
    assert fault_dispatch.declared_kind(run_dir, HELD) is None


@pytest.mark.parametrize("kind,target", NOT_OURS)
def test_a_fault_aimed_elsewhere_runs_an_ordinary_scan(tmp_path, kind, target):
    """End to end, because the row above only proves the reader."""
    run_dir = _run_dir(tmp_path, kind, target=target)
    completed = subprocess.run(
        [sys.executable, str(pathlib.Path(fault_dispatch.__file__)),
         "--run-dir", str(run_dir), "--channel", "api_response"],
        input=HELD.encode(), capture_output=True)
    assert completed.returncode != 3, completed.stderr[-400:]
    assert b"cannot inject" not in completed.stderr


@pytest.mark.parametrize("kind", UNINJECTABLE)
def test_a_declared_kind_this_worker_cannot_inject_is_still_reported(tmp_path, kind):
    """`declared_fault` says None for it, and None is the same word it uses for
    a payload that declares nothing at all. `declared_kind` tells them apart."""
    run_dir = _run_dir(tmp_path, kind)
    assert fault_dispatch.declared_fault(run_dir, HELD) is None
    assert fault_dispatch.declared_kind(run_dir, HELD) == kind


def test_nothing_declared_is_not_reported_as_a_declared_kind(tmp_path):
    """The control. If this returned a kind, the refusal below would fire on
    every ordinary scan and the dispatcher would be the outage."""
    clean = tmp_path / "clean"
    clean.mkdir()
    assert fault_dispatch.declared_kind(clean, HELD) is None
    # And a record that names a DIFFERENT document is not this payload's.
    assert fault_dispatch.declared_kind(_run_dir(tmp_path, "hang"), OTHER) is None


def test_an_uninjectable_declared_fault_refuses_instead_of_scanning(tmp_path):
    """A missing row is recoverable. A wrong row is not.

    Running the ordinary scan here answers the scenario's question with a
    session that never had the fault in it, which is the finding this file was
    written to fix, quoted in its own docstring.
    """
    run_dir = _run_dir(tmp_path, "worker_false_string")
    completed = subprocess.run(
        [sys.executable, str(pathlib.Path(fault_dispatch.__file__)),
         "--run-dir", str(run_dir), "--channel", "api_response"],
        input=HELD.encode(), capture_output=True)

    assert completed.returncode == 3, (completed.returncode, completed.stderr[-400:])
    assert b"worker_false_string" in completed.stderr, completed.stderr[-400:]
    # It must not have quietly run the scan it could not justify.
    assert not list(run_dir.glob("fault.*.started")), "a worker was started anyway"


def test_narrowing_the_modes_refuses_rather_than_running_something_else(tmp_path):
    """`--modes` is the operator saying what this session may inject. Asking for
    less than the scenario needs is a configuration error, not a licence to run
    the scenario unfaulted."""
    run_dir = _run_dir(tmp_path, "barrier_hold")
    completed = subprocess.run(
        [sys.executable, str(pathlib.Path(fault_dispatch.__file__)),
         "--run-dir", str(run_dir), "--channel", "api_response",
         "--modes", "exception"],
        input=HELD.encode(), capture_output=True)

    assert completed.returncode == 3, (completed.returncode, completed.stderr[-400:])
    assert b"barrier" in completed.stderr, completed.stderr[-400:]


def test_an_ordinary_scan_still_runs_when_nothing_is_declared(tmp_path):
    """The regression guard for the refusal above: the dispatcher runs on EVERY
    scan of every mediated route, and most of them declare no fault at all."""
    clean = tmp_path / "clean"
    clean.mkdir()
    completed = subprocess.run(
        [sys.executable, str(pathlib.Path(fault_dispatch.__file__)),
         "--run-dir", str(clean), "--channel", "api_response"],
        input=HELD.encode(), capture_output=True)

    assert completed.returncode != 3, completed.stderr[-400:]
    assert b"cannot inject" not in completed.stderr


def test_g2_10_through_the_real_batch_path_is_not_refused(tmp_path):
    """The row that would have caught the false kill I added.

    The batch-path row further up covers G2-08, G2-09 and G2-11 — the three
    scanner-targeted scenarios — and not G2-10, so a refusal that fired only on
    G2-10 passed the whole suite. `run_one` writes the fault record for ANY
    declared kind with no filter on target, so G2-10's upstream and hook faults
    do reach this dispatcher, and it has to let them through.

    Built by `run_one`, never by hand: a directory I assemble agrees with
    whatever I assumed when I assembled it, which is how the target field went
    missing from the fixtures above in the first place.
    """
    import shutil
    import uuid
    import runner
    from destination.sink import Destination

    entry = next(e for e in runner.load_manifest()["scenarios"]
                 if e["id"] == "G2-10")
    checked = {}
    for variant in runner.scenario_of(entry)["variants"]:
        root = pathlib.Path("/private/tmp") / f"g210-{uuid.uuid4().hex[:10]}"
        start = Destination.start
        Destination.start = lambda self: "file:///dev/null"
        try:
            # NOT WRAPPED IN A `try/except JSONDecodeError` any more. It was,
            # because `_held_inspection_input` raised on G2-10.invalid_json,
            # whose frame is invalid ON PURPOSE. Swallowing that here recorded
            # "cannot read it" and moved on, which is a test agreeing with a
            # defect. All three variants must drive.
            row = batch.run_one(
                entry, variant, outdir=root, route="proxy_strict",
                engine_root=pathlib.Path(__file__).resolve().parents[3],
                upstream_argv=[sys.executable], ledger=None,
                dry_run=True, call_no=0)
        finally:
            Destination.start = start

        if row.get("refused"):
            # `malformed_hook_output` is refused by name: its target is a
            # component this harness does not compose. That refusal has its own
            # row below; here it simply is not a dispatcher question.
            checked[variant["name"]] = "refused_by_name"
            shutil.rmtree(root, ignore_errors=True)
            continue

        try:
            run_dir = pathlib.Path(row["run_dir"])
            record = run_dir / "materialised.fault.json"
            assert record.is_file(), (
                f"{variant['name']}: no fault record, so this row proves nothing")
            held_file = run_dir / "payload.txt"
            held = held_file.read_text() if held_file.is_file() else ""
            assert fault_dispatch.declared_kind(run_dir, held) is None, (
                f"{variant['name']} targets "
                f"{variant['fault']['target']} and the scanner dispatcher "
                "claimed it, which refuses a scenario that must run an "
                "ordinary scan")
            checked[variant["name"]] = "not_refused"
        finally:
            shutil.rmtree(root, ignore_errors=True)

    assert set(checked) == {"invalid_json", "invalid_result_shape",
                            "malformed_hook_output"}, checked
    # The two upstream_stdout variants drive and the dispatcher lets them
    # through; the hook one never reaches the dispatcher at all.
    assert checked["invalid_json"] == "not_refused", checked
    assert checked["invalid_result_shape"] == "not_refused", checked
    assert checked["malformed_hook_output"] == "refused_by_name", checked


def test_an_unparseable_frame_holds_nothing_and_is_not_keyed(tmp_path):
    """The proxy REFUSES an unparseable frame and never inspects it.

    `passthrough` emits FRAME_REFUSED with reason `unparseable` and hands the
    scanner nothing, so the record for such a run has no inspection input — not
    an empty one, none. The distinction is load bearing: the digest of the
    empty string is a real digest, and the dispatcher selects on exactly that
    field, so keying a record to it would arm a fault for every run that
    happens to hold nothing.
    """
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "upstream.jsonl").write_bytes(b'{"jsonrpc":"2.0","id":1,"result":\n')
    assert batch._held_inspection_input(run_dir, "result") is None

    # And a frame that DOES parse still yields its inspection input, or the
    # line above would be passing for everything.
    (run_dir / "upstream.jsonl").write_bytes(
        b'{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text",'
        b'"text":"hello"}]}}\n')
    held = batch._held_inspection_input(run_dir, "result")
    assert held is not None and "hello" in held, held


def test_a_fault_against_a_component_this_harness_lacks_is_refused_by_name(tmp_path):
    """G2-10.malformed_hook_output aims at `hook_stdout`, and there is no hook.

    Measured: `mcp_config` composes exactly two things, a proxy and an
    upstream; `HOOK_COMPARISON_SEEDS` is an alias for the control scope and
    selects no hook route; the routes are `proxy_strict` and `control`. So the
    component that fault names does not exist in this instrument.

    Running it anyway produces a clean verdict about a session in which the
    declared fault never happened — the same defect the dispatcher was written
    to fix. Refused by name is the honest answer, and a refused row is
    recoverable in a way a wrong row is not.
    """
    import shutil
    import uuid
    import runner
    from destination.sink import Destination

    entry = next(e for e in runner.load_manifest()["scenarios"]
                 if e["id"] == "G2-10")
    states = {}
    for variant in runner.scenario_of(entry)["variants"]:
        root = pathlib.Path("/private/tmp") / f"hook-{uuid.uuid4().hex[:10]}"
        start = Destination.start
        Destination.start = lambda self: "file:///dev/null"
        try:
            row = batch.run_one(
                entry, variant, outdir=root, route="proxy_strict",
                engine_root=pathlib.Path(__file__).resolve().parents[3],
                upstream_argv=[sys.executable], ledger=None,
                dry_run=True, call_no=0)
            states[variant["name"]] = row.get("refused")
        finally:
            Destination.start = start
            shutil.rmtree(root, ignore_errors=True)

    assert states["malformed_hook_output"] == "uninjectable_fault_target", states
    # THE OTHER TWO STILL RUN. Their target is `upstream_stdout`, which needs no
    # injector because the seed carries the malformed bytes and the replay emits
    # them verbatim. A refusal that swallowed these would be the false kill this
    # check exists to avoid.
    assert states["invalid_json"] is None, states
    assert states["invalid_result_shape"] is None, states


def test_the_scanner_targeted_scenarios_are_not_refused(tmp_path):
    """The control for the row above, on the six that DO have an injector."""
    import shutil
    import uuid
    import runner
    from destination.sink import Destination

    refused = {}
    for scenario_id in ("G2-08", "G2-09", "G2-11"):
        entry = next(e for e in runner.load_manifest()["scenarios"]
                     if e["id"] == scenario_id)
        for name in ("request", "result"):
            variant = next(v for v in runner.scenario_of(entry)["variants"]
                           if v["name"] == name)
            root = pathlib.Path("/private/tmp") / f"sc-{uuid.uuid4().hex[:10]}"
            start = Destination.start
            Destination.start = lambda self: "file:///dev/null"
            try:
                row = batch.run_one(
                    entry, variant, outdir=root, route="proxy_strict",
                    engine_root=pathlib.Path(__file__).resolve().parents[3],
                    upstream_argv=[sys.executable], ledger=None,
                    dry_run=True, call_no=0)
                refused[f"{scenario_id}.{name}"] = row.get("refused")
            finally:
                Destination.start = start
                shutil.rmtree(root, ignore_errors=True)

    assert set(refused.values()) == {None}, refused
    assert len(refused) == 6, refused
