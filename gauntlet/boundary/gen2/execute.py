"""Drive one generation 2 variant through real pipes, or refuse it whole.

`plan()` answers whether a schedule COULD be driven. Nothing executed it, so the
generation 2 set was a coverage claim with no run behind it. That is the same
shape as the fault dispatcher written into every configuration and never
selected, and as the second route that was configured and not allowed: a
capability present in the config and absent from the run, with a green row on
top of it.

So this runs the steps. Real process, real pipes, no model call anywhere, and
every refusal names what it could not do.

Only `no_mediation` for now, the S0 control. It is the route that establishes
what a session looks like with nothing in the middle, which is the thing every
mediated row is compared against, and it is the one that needs no proxy to be
correct first.
"""
from __future__ import annotations

import collections
import dataclasses
import json
import pathlib
import subprocess
import sys
import time

from . import adapter, artifacts, materialize

HERE = pathlib.Path(__file__).resolve().parent
REPLAY = HERE / "upstream_replay.py"
SUPPORTED_ROUTES = frozenset({"no_mediation", "proxy_strict"})
BOUNDARY = HERE.parent
PACKAGE = pathlib.Path.home() / ".claude" / "state" / "warroom" / "GATE2_SCENARIOS"
FAULT_WORKER = PACKAGE / "fault_worker.py"
PACKAGE_INSPECTION_BYTE_BUDGET = 262144

# What the mediator says it DID about a held message. Both are dispositions: one
# says it inspected and decided, the other says it found nothing it inspects in
# that frame, which for a carriers scenario is the measurement rather than a
# failure to take one.
TERMINAL_KINDS = ("SETTLED", "NO_INSPECTABLE_CONTENT")


class UnsupportedRoute(Exception):
    """A route this adapter cannot drive. Named, never approximated."""


class UpstreamNotAsDeclared(Exception):
    """What came back is not what the seed declares, so there is no row here."""


class DeclaredFileMissing(Exception):
    """A file the schedule names is in neither the run root nor the delivery."""


class TerminalNeverArrived(Exception):
    """The primary request was never answered. Not an empty result, an absence."""


@dataclasses.dataclass
class Run:
    run_dir: pathlib.Path
    steps: list[dict]
    client_wire: bytes
    upstream_wire: bytes
    terminal: dict | None
    primary_id: object
    upstream_as_declared: bool
    terminal_expected: bool
    disposition: str | None = None
    assertions: list = dataclasses.field(default_factory=list)


def _frames(path: pathlib.Path) -> list[bytes]:
    return [line for line in pathlib.Path(path).read_bytes().splitlines() if line.strip()]


def _primary_id(run_dir: pathlib.Path, id_from: str):
    """The id the schedule says is primary, read from the file it names.

    The step carries `id_from` rather than the id itself, so reading it from
    anywhere else, the first frame seen on the wire for instance, would be this
    adapter deciding which request was primary.
    """
    for raw in _frames(run_dir / id_from):
        message = json.loads(raw)
        if message.get("id") is not None:
            return message["id"]
    return None


def _disposition(receipts: pathlib.Path, primary_id) -> str | None:
    """What the mediator DID about the primary result, in its own vocabulary.

    Not "did it settle". G2-13 is a carriers scenario: it puts the injection in
    `error.message`, in a resource, in a display field, in the initialize result,
    places a mediator may or may not look. Requiring a settlement here would
    assume the answer to the question the scenario asks, and a row that asserts
    its own expectation measures nothing.

    So the run records the mediator's own terminal event for that request and
    lets the grader decide what it means. `NO_INSPECTABLE_CONTENT` on a carrier
    is a measurement about the product, not a defect in this harness.
    """
    if not receipts.is_file():
        return None
    last = None
    for line in receipts.read_bytes().splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        # BY REQUEST ID, not by direction. `SETTLED` carries no direction field
        # at all, so filtering on one silently dropped every settlement and left
        # rows looking as though the mediator had said nothing about them. The
        # id is what ties an event to this request, and the handshake's own
        # disposition is a different id.
        if event.get("kind") not in TERMINAL_KINDS:
            continue
        if event.get("request_id") == primary_id:
            last = event.get("kind")
    return last


def _messages(raw: bytes) -> list:
    """Every readable JSON-RPC frame in a captured stream."""
    out = []
    for line in raw.splitlines():
        if not line.strip():
            continue
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _check_correlation(client_sent, upstream_answered) -> dict:
    """Nothing answers a notification, and nothing borrows a pending id.

    Two halves of one rule. A notification has no id, so a frame that claims to
    answer one is answering something that cannot be answered; and a frame
    carrying an id the client is still waiting on, while being a REQUEST rather
    than a reply, has taken that id for a different conversation. G2-15's
    upstream does exactly the second, with `sampling/createMessage` on the
    client's pending 1501.
    """
    pending = {m["id"] for m in client_sent
               if m.get("id") is not None and m.get("method")}
    borrowed = sorted({m["id"] for m in upstream_answered
                       if m.get("id") in pending and m.get("method")})
    # A reply to a notification would have to carry an id nobody requested.
    requested = {m.get("id") for m in client_sent if m.get("id") is not None}
    unrequested = sorted({m["id"] for m in upstream_answered
                          if m.get("id") is not None and not m.get("method")
                          and m["id"] not in requested})
    return {"held": not borrowed and not unrequested,
            "borrowed_ids": borrowed, "unrequested_reply_ids": unrequested}


def _count_copies(reference: list, delivered: list) -> int:
    """How many of the referenced frames reached the upstream, by exact equality."""
    return sum(1 for r in reference if r in delivered)


def _error_for(messages: list, wanted) -> dict | None:
    for m in messages:
        if m.get("id") == wanted and m.get("error") is not None:
            return m
    return None


def _receipts_of_kind(receipts: pathlib.Path, kind: str) -> list[dict]:
    """Every receipt of `kind`, in order, uncorrelated.

    `_event_for` answers "did THIS id see this event" and is right for the
    correlated steps. `release_any_old_workers` asks about ANY worker, so it
    needs the whole stream — using the correlated reader would silently answer
    a narrower question under the wider op's name.

    A missing receipts file yields an empty list, never an error: on the control
    route there is no mediator and so no receipts, and that is the definition of
    the control rather than a failure to observe.
    """
    if not receipts.is_file():
        return []
    out = []
    for line in receipts.read_bytes().splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("kind") == kind:
            out.append(event)
    return out


def _forwarded_upstream(receipts: pathlib.Path) -> list:
    """The frames the mediator actually sent upstream, from its own receipts.

    `client_wire` is what this adapter wrote into the mediator's stdin and
    `upstream_wire` is what came back out of its stdout toward the client.
    Neither is egress: the upstream is a CHILD of the mediator, so nothing this
    adapter holds ever saw the forwarded bytes. `passthrough.py` records them,
    with `replaced` set when what went out is not what came in, and that record
    is the only place the question has an answer.
    """
    return [message for entry in _receipts_of_kind(receipts, "RPC_EGRESS")
            if entry.get("direction") == "request"
            for message in _messages((entry.get("raw") or "").encode())]


def _event_for(receipts: pathlib.Path, kind: str, wanted) -> dict | None:
    """The first receipt of `kind` correlated to `wanted`, or None.

    TYPE AWARE BY DESIGN. JSON-RPC treats 4 and "4" as different correlation
    ids, they render identically in a receipt, and Python would call 1 equal to
    True and 4 equal to 4.0. The mediator records `request_id_type` beside the
    id precisely so a reader does not have to guess, so the type name is
    compared as well as the value and a receipt that merely looks like the one
    asked for does not answer for it.

    Absence is a finding, never an error. On the control route there is no
    mediator and so no receipts file at all, and a control that emits no proxy
    event is the definition of the control rather than a failure to observe one.
    """
    if not receipts.is_file():
        return None
    for line in receipts.read_bytes().splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("kind") != kind:
            continue
        if event.get("request_id") != wanted:
            continue
        if event.get("request_id_type") != type(wanted).__name__:
            continue
        return event
    return None


def _mediator_ingress(receipts: pathlib.Path) -> list[bytes]:
    """The result frames the mediator saw arrive from the upstream, in order."""
    if not receipts.is_file():
        return []
    frames = []
    for line in receipts.read_bytes().splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("kind") == "RPC_INGRESS" and event.get("direction") == "result":
            frames.append((event.get("raw") or "").rstrip("\n").encode())
    return [f for f in frames if f]


def run(entry: dict, variant: dict, *, route: str, run_root: pathlib.Path,
        materialise: bool = True, timeout_ms: int = 3000,
        materialised: pathlib.Path | None = None,
        engine_root: pathlib.Path | None = None) -> Run:
    """Execute one variant on one route and hand back what was observed."""
    if route not in SUPPORTED_ROUTES:
        raise UnsupportedRoute(
            f"{route}: this adapter drives {sorted(SUPPORTED_ROUTES)} only. "
            "A route it approximates is a different experiment reported under "
            "this scenario's name.")

    run_root = pathlib.Path(run_root)
    # PLAN BEFORE ANYTHING EXISTS. A refused variant must not leave a run
    # directory behind, because a directory is the first thing a reader treats
    # as evidence that something ran.
    # THE SCHEDULE OF RECORD, always, whether or not this call materialises.
    # The materialiser writes a file of the same name into the run root that
    # carries `required_steps` and no `profile_steps` at all, so reading the run
    # root gave an empty plan and drove a session with no request in it. Two
    # different documents under one name, and only one of them is the delivery.
    record = artifacts.of_record(entry, variant, materialised=materialised)
    steps = adapter.plan(record.schedule)

    def declared(name: str) -> pathlib.Path:
        """A file the schedule names, from the run first and the delivery second.

        ASTRA's materialiser writes most of a variant's artifacts into the run
        root and not all of them: `pending-clean.response.jsonl` is named by
        G2-14's schedule, is listed in the delivery, and never appears in the
        run. The run's copy wins where it exists, because that is the file this
        session actually used; the delivery answers for the rest, because it is
        the declaration. A name in neither is refused rather than skipped, since
        a skipped send is a session missing a frame nobody will notice.
        """
        run_copy = run_root / name
        if run_copy.is_file():
            return run_copy
        delivered = record.path / name
        if delivered.is_file():
            return delivered
        raise DeclaredFileMissing(
            f"{entry['id']}.{variant['name']}: the schedule names {name!r} and it "
            f"is in neither the run root nor the delivered artifacts.")

    if materialise:
        materialize.materialize(entry, variant, run_root=run_root)

    # THE FILES THE SCHEDULE NAMES, in schedule order. Serving
    # `variant["upstream_output"]` for every variant ran a different experiment
    # for three of the nineteen and reported green, because the declared check
    # compared the wire against that same wrong file and the two halves agreed.
    # G2-23.frame_exact was the worst: it declares a 4,194,304 byte override,
    # exactly the wire frame limit, which is the whole scenario, and a 244 byte
    # file went out in its place.
    upstream_paths = [step["path"] for step in steps
                      if step["op"] == "send_file" and step["origin"] == "upstream"]
    upstream_file = run_root / "upstream.declared.jsonl"
    upstream_file.write_bytes(b"".join(
        declared(name).read_bytes().rstrip(b"\n") + b"\n"
        for name in upstream_paths) if upstream_paths else b"")
    # Checked against the DELIVERY's copies of those same named files. Reading
    # both from the run root would compare the run to itself.
    declared_frames = [frame for name in upstream_paths
                       for frame in _frames(record.path / name)]

    upstream_argv = [sys.executable, str(REPLAY),
                     "--handshake", str(declared("initialize.response.jsonl")),
                     "--stream", str(upstream_file)]
    if route == "proxy_strict":
        # THE MEDIATOR IN FRONT OF THE SAME UPSTREAM. The client's frames and
        # the declared answers do not change between the routes; what changes is
        # that this one has something in the middle, which is the entire
        # experiment. Same scanner the package ships, same byte budget it
        # declares.
        # THE MODE THE SCHEDULE ARMS. Chosen here because the scanner command is
        # fixed for the whole session, and that is faithful only because every
        # delivered schedule that arms a fault arms BEFORE its first send. A
        # mid-session arm would need a different mechanism; none asks for one.
        #
        # `require_fresh_barrier` against `scanner_worker` means the worker must
        # HOLD rather than answer, so the request it is scanning stays pending
        # while the rest of the schedule runs. The release file is named and
        # deliberately never created: G2-20.duplicate_pending has no
        # `release_fault_barrier` step, so the hold is meant to outlive the run
        # and the worker is reaped at teardown.
        armed = next((st for st in steps if st.get("op") == "arm_fault"), None)
        mode = "barrier" if (armed
                             and armed.get("target") == "scanner_worker"
                             and armed.get("require_fresh_barrier")) else "scan"
        scanner = f"{sys.executable} {FAULT_WORKER} {mode}"
        if mode == "barrier":
            scanner += f" --release {run_root / 'fault.release'}"
        if engine_root:
            scanner += f" --engine-root {engine_root}"
        argv = [sys.executable, str(BOUNDARY / "proxy" / "passthrough.py"),
                "--deadline-ms", str(timeout_ms),
                "--byte-budget", str(PACKAGE_INSPECTION_BYTE_BUDGET),
                "--receipts", str(run_root / "proxy.receipts.jsonl"),
                "--scanner", scanner, "--"] + upstream_argv
    else:
        argv = upstream_argv
    server = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)

    client_wire = bytearray()

    def send(raw: bytes) -> None:
        client_wire.extend(raw)
        server.stdin.write(raw)
        server.stdin.flush()

    # THE HANDSHAKE THE SEED DECLARES, not one this adapter composed. Its
    # `required_steps` names all three files, and the notification goes after
    # the response, which is the ordering the document spells out.
    for frame in _frames(declared("initialize.request.jsonl")):
        send(frame + b"\n")
    for frame in _frames(declared("initialized.notification.jsonl")):
        send(frame + b"\n")

    primary_id = None
    for step in steps:
        if step["op"] == "send_file":
            if step["origin"] == "client":
                for frame in _frames(declared(step["path"])):
                    send(frame + b"\n")
            # `origin: upstream` is the frames the server is to answer with, and
            # it is seeded from that same file. It is CHECKED below rather than
            # treated as satisfied by the configuration, because a step that
            # runs as a no-op is how a capability comes to be inert.
        elif step["op"] == "await_primary_terminal":
            primary_id = _primary_id(run_root, step["id_from"])
            timeout_ms = step.get("timeout_ms", timeout_ms)

    server.stdin.close()
    deadline = time.monotonic() + timeout_ms / 1000
    upstream_wire = bytearray()
    terminal = None
    while time.monotonic() < deadline:
        line = server.stdout.readline()
        if not line:
            break
        upstream_wire.extend(line)
        try:
            message = json.loads(line)
        except ValueError:
            continue
        if primary_id is not None and message.get("id") == primary_id:
            terminal = message
            break
    try:
        server.wait(timeout=2)
    except subprocess.TimeoutExpired:                          # pragma: no cover
        server.kill()

    (run_root / "client.wire.jsonl").write_bytes(bytes(client_wire))
    (run_root / "upstream.wire.jsonl").write_bytes(bytes(upstream_wire))

    # THE ASSERTION STEPS, executed and RECORDED. None of them raises. On the
    # control route `assert_zero_upstream_copies` is expected not to hold,
    # because the control is defined by having nothing in the middle, and a step
    # that threw would turn that finding into an error the grader never sees.
    # An exception means this harness could not carry the step out; a recorded
    # `held: false` means it did and the answer was no.
    sent = _messages(bytes(client_wire))
    received = _messages(bytes(upstream_wire))
    assertions = []
    for step in steps:
        op = step["op"]
        if op == "assert_no_rpc_response_to_notification_or_borrowed_id":
            assertions.append({"op": op, **_check_correlation(sent, received)})
        elif op == "assert_zero_upstream_copies":
            # AGAINST WHAT THE UPSTREAM GOT, which differs by route.
            #
            # This counted the reference against `sent` on both routes. On the
            # control that is exactly right: with nothing in the middle the
            # client's stdin IS the upstream's stdin, so every frame sent
            # arrived. On the mediated route it answers a different question
            # under the same name, and it cannot answer this one: the reference
            # file is the file the schedule just sent, so it is always a subset
            # of the client wire and the step can never hold. Two runs of
            # G2-16.wire_name, one where the scanner threw and the mediator
            # failed closed and one where it found the secret, printed the same
            # `copies: 1` while the mediator's receipts recorded
            # `forwarded: false` both times.
            reference = _messages(declared(step["path"]).read_bytes())
            arrived = (_forwarded_upstream(run_root / "proxy.receipts.jsonl")
                       if route == "proxy_strict" else sent)
            copies = _count_copies(reference, arrived)
            assertions.append({"op": op, "path": step["path"], "copies": copies,
                               "held": copies == 0, "basis": route})
        elif op == "release_fault_barrier":
            # THE FILE THE WORKER IS WAITING ON. `fault_worker.py barrier` spins
            # until this path exists, and `arm_fault` above named it, so the
            # release is a one-line fact rather than a signal to guess at.
            #
            # RECORDED AS WHETHER THE BARRIER WAS ACTUALLY THERE. Creating the
            # file unconditionally and calling it released would be true of a
            # session that never armed one, which is the vacuous pass this file
            # has now been bitten by twice.
            release = run_root / "fault.release"
            armed_barrier = any(
                st.get("op") == "arm_fault"
                and st.get("target") == "scanner_worker"
                and st.get("require_fresh_barrier")
                for st in steps)
            if armed_barrier:
                release.touch()
            assertions.append({
                "op": op, "path": release.name,
                "armed": armed_barrier,
                "released": release.is_file(),
                "held": armed_barrier and release.is_file(),
                "why": None if armed_barrier else (
                    "no barrier was armed in this schedule, so there was "
                    "nothing to release")})

        elif op == "arm_fault":
            # RECORDED, not re-done. The mode was chosen before the session
            # started; this row says what was armed so a reader of the
            # assertions sees it instead of inferring it from the argv.
            assertions.append({
                "op": op, "kind": step.get("kind"), "target": step.get("target"),
                "require_fresh_barrier": step.get("require_fresh_barrier"),
                "scanner_mode": "barrier" if (
                    step.get("target") == "scanner_worker"
                    and step.get("require_fresh_barrier")) else "scan",
                "held": True})

        elif op == "assert_no_second_forward_and_no_pending_overwrite":
            # A second request carrying an id that is STILL PENDING must not be
            # forwarded, and must not replace the pending entry the first one
            # owns. Counted from the mediator's own egress: the product refuses
            # the duplicate outright, so at most ONE egress may carry any id.
            receipts = run_root / "proxy.receipts.jsonl"
            per_id = collections.Counter(
                message.get("id") for message in _forwarded_upstream(receipts)
                if message.get("id") is not None)
            repeated = {i: n for i, n in per_id.items() if n > 1}
            refusals = [r.get("reason")
                        for r in _receipts_of_kind(receipts, "ADMISSION_REFUSED")]
            # A ZERO HAS TWO READINGS, and this op is where they look alike.
            # "no id was forwarded twice" is TRUE of a session that forwarded
            # nothing at all, and the first run of this row returned exactly
            # that: `forwarded_per_id: {}`, held true, subject absent.
            #
            # G2-20.duplicate_pending sends `arguments: {}`, so the mediator
            # records NO_INSPECTABLE_CONTENT, never holds, and never writes an
            # RPC_EGRESS. The scenario's precondition — a request still PENDING
            # when its twin arrives — does not occur here at all, so there is
            # nothing for the property to be true OF.
            #
            # Reported as no subject rather than as a pass. A green with no
            # subject is the defect this whole harness keeps finding in itself.
            subject = bool(per_id)
            assertions.append({
                "op": op,
                "forwarded_per_id": dict(per_id),
                "forwarded_twice": repeated,
                "admission_refusals": refusals,
                "subject": subject,
                "held": (not repeated) if subject else None,
                "why": None if subject else (
                    "the mediator recorded no forwarded request for any id, so "
                    "nothing was pending and this property has no subject in "
                    "this run")})

        elif op == "assert_secondary_and_reverse_complete_independently":
            # SCOPED TO DISTINCT IDS, and the scope IS the ruling. T8: `_owed`
            # is per id with a per-item origin, so items with DIFFERENT ids
            # complete independently — but a client id reused while pending is a
            # deliberate NO, torn down on purpose. An unconditional claim would
            # fail G2-15, a shape the product handles correctly.
            settled = _receipts_of_kind(run_root / "proxy.receipts.jsonl", "SETTLED")
            by_id = collections.Counter(
                row.get("request_id") for row in settled
                if row.get("request_id") is not None)
            reused = sorted(i for i, n in by_id.items() if n > 1)
            distinct = sorted(i for i, n in by_id.items() if n == 1)
            assertions.append({
                "op": op,
                "settled_per_id": dict(by_id),
                "distinct_ids": distinct,
                "reused_ids": reused,
                "scope": "distinct ids only; a reused pending id is a deliberate NO",
                # SAME THREE-WAY ANSWER as the row above. No settlement at all
                # is not a failure of independence, it is an absent subject, and
                # reporting it as `held: false` would send a reader looking for
                # a correlation bug that did not happen.
                "subject": bool(by_id),
                "held": (not reused) if by_id else None,
                "why": None if by_id else (
                    "the mediator settled nothing in this run, so there are no "
                    "completions for independence to be a property of")})

        elif op == "release_any_old_workers":
            # WHAT THE MEDIATOR RECORDS, not what this adapter hopes.
            # `passthrough.py` emits WORKER_OUTPUT with `accepted` and
            # `discarded_reason`; a worker whose output was thrown away carries
            # a reason and accepted=False. So "were the old workers released"
            # is answerable from the receipts, with no new machinery.
            #
            # NOT CORRELATED TO ONE ID, and that is the point of the op's name:
            # it asks about ANY worker still around, so the question is over the
            # whole receipt stream rather than one request. Correlating it would
            # answer a narrower question under this op's name.
            outputs = _receipts_of_kind(run_root / "proxy.receipts.jsonl",
                                        "WORKER_OUTPUT")
            discarded = [e for e in outputs if e.get("discarded_reason")]
            row = {"op": op,
                   "worker_outputs": len(outputs),
                   "discarded": len(discarded),
                   "reasons": sorted({e["discarded_reason"] for e in discarded}),
                   # ABSENCE IS REPORTED, NEVER PASSED OVER. Zero worker outputs
                   # means nothing ran to be released, which is a different fact
                   # from "everything was released" and must not read as one.
                   "observed": bool(outputs)}
            if step.get("require_discard"):
                row["require_discard"] = True
                row["satisfied"] = bool(discarded)
            assertions.append(row)

        elif op == "await_event":
            # CORRELATED BY THE FILE THE STEP NAMES, like every other id here.
            # `correlate_id_from` rather than `id_from`, and reading it from the
            # wire instead would be this adapter choosing which request the
            # event belongs to.
            wanted = _primary_id(run_root, step["correlate_id_from"])
            found = _event_for(run_root / "proxy.receipts.jsonl",
                               step["event"], wanted)
            assertions.append({
                "op": op, "event": step["event"],
                # The contract's default, recorded EXPLICITLY so the row says
                # which actor it was answered for rather than leaving a reader
                # to re-derive the omission rule.
                "actor": step.get("actor", "proxy"),
                "id": wanted, "held": found is not None,
                "deadline_ms": step["timeout_ms"],
                "seq": found.get("seq") if found is not None else None,
            })
        elif op in ("await_client_error", "await_error"):
            wanted = _primary_id(run_root, step["id_from"])
            # THE CONTRACT GIVES THESE NO PER STEP TIMEOUT, so the enclosing
            # deadline applies and the run records WHICH, because a wait with an
            # unrecorded bound is not a measurement anyone can repeat.
            where = received if op == "await_client_error" else sent
            found = _error_for(where, wanted)
            entry_row = {"op": op, "id": wanted, "held": found is not None,
                         "deadline_ms": timeout_ms}
            if op == "await_error":
                entry_row["recipient"] = step["recipient"]
            if found is not None:
                entry_row["code"] = (found.get("error") or {}).get("code")
            assertions.append(entry_row)

    # WHAT CAME BACK AGAINST WHAT THE SEED DECLARES. The handshake response is
    # part of the stream and is checked as such; everything after it has to be
    # the declared frames in the declared order.
    answered = [line for line in bytes(upstream_wire).splitlines() if line.strip()]
    handshake = _frames(declared("initialize.response.jsonl"))
    # WHERE THE UPSTREAM SPOKE, which is not the same place on the two routes.
    # On the control the client's wire IS the upstream's, so it is the thing to
    # compare. On strict the client's wire is the MEDIATOR'S OUTPUT, and
    # comparing that against the seed would call every correct withholding a
    # stream that is not the scenario. The mediator records what arrived from
    # the upstream, so that is what the declaration is checked against.
    complete = handshake + declared_frames
    if route == "proxy_strict":
        # The handshake reply crosses the mediator too, so it is in the ingress
        # and belongs in the expectation. Comparing against the declared frames
        # alone made a correct session look like one frame too long.
        answered = _mediator_ingress(run_root / "proxy.receipts.jsonl")
    as_declared = answered == complete
    # A PREFIX IS SHORT, NOT WRONG. An upstream that is slow or dies mid stream
    # has sent nothing the seed does not declare, it has simply not finished, and
    # reporting that as frames the seed does not declare points at the wrong
    # thing. Short and correct is a timeout; anything unexpected on the wire is
    # a stream that is not the scenario.
    truncated = answered == complete[:len(answered)]

    # IS A TERMINAL EXPECTED AT ALL. G2-20.unsolicited_response declares a reply
    # carrying an id nobody asked for and never answers the primary request:
    # that absence IS the scenario. A guard that read the outcome could not tell
    # it from a harness that failed to drive one, and called a correctly
    # executed scenario a fault. The declaration knows, so it is asked.
    # `primary_id is not None` FIRST. A schedule with no `await_primary_terminal`
    # has no primary request, and a declared notification carries no id, so
    # `frame.get("id") == None` matched and the run demanded a terminal for a
    # request that was never made. None equalling None is the whole bug.
    expected = primary_id is not None and any(
        json.loads(frame).get("id") == primary_id for frame in declared_frames)

    result = Run(run_dir=run_root, steps=steps, client_wire=bytes(client_wire),
                 upstream_wire=bytes(upstream_wire), terminal=terminal,
                 primary_id=primary_id, upstream_as_declared=as_declared,
                 terminal_expected=expected,
                 disposition=_disposition(run_root / "proxy.receipts.jsonl",
                                          primary_id),
                 assertions=assertions)
    (run_root / "execution.json").write_text(json.dumps({
        "scenario_id": entry["id"], "variant": variant["name"], "route": route,
        "steps": [step["op"] for step in steps],
        "primary_id": primary_id,
        "client_wire_bytes": len(client_wire),
        "upstream_wire_bytes": len(upstream_wire),
        "upstream_as_declared": as_declared,
        "terminal_expected": expected,
        "mediator_disposition": _disposition(
            run_root / "proxy.receipts.jsonl", primary_id),
        "terminal_arrived": terminal is not None,
        "assertions": assertions,
    }, indent=1) + "\n")

    if expected and terminal is None and truncated:
        raise TerminalNeverArrived(
            f"{entry['id']}.{variant['name']}: the seed declares a reply carrying "
            f"the primary id {primary_id!r} and none arrived within {timeout_ms}ms. "
            f"{len(answered)} of {len(complete)} declared frames came back. An "
            f"absent terminal is not an empty result.")
    if not as_declared:
        raise UpstreamNotAsDeclared(
            f"{entry['id']}.{variant['name']}: the upstream answered frames the "
            f"seed does not declare. There is no row here, only a report about "
            f"this harness.")
    if expected and terminal is None:
        raise TerminalNeverArrived(
            f"{entry['id']}.{variant['name']}: no reply carrying the primary id "
            f"{primary_id!r} within {timeout_ms}ms. An absent terminal is not an "
            f"empty result.")
    return result
