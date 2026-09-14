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
        (run_root / name).read_bytes().rstrip(b"\n") + b"\n"
        for name in upstream_paths) if upstream_paths else b"")
    # Checked against the DELIVERY's copies of those same named files. Reading
    # both from the run root would compare the run to itself.
    declared = [frame for name in upstream_paths
                for frame in _frames(record.path / name)]

    upstream_argv = [sys.executable, str(REPLAY),
                     "--handshake", str(run_root / "initialize.response.jsonl"),
                     "--stream", str(upstream_file)]
    if route == "proxy_strict":
        # THE MEDIATOR IN FRONT OF THE SAME UPSTREAM. The client's frames and
        # the declared answers do not change between the routes; what changes is
        # that this one has something in the middle, which is the entire
        # experiment. Same scanner the package ships, same byte budget it
        # declares.
        scanner = (f"{sys.executable} {FAULT_WORKER} scan "
                   f"--engine-root {engine_root}" if engine_root else
                   f"{sys.executable} {FAULT_WORKER} scan")
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
    for frame in _frames(run_root / "initialize.request.jsonl"):
        send(frame + b"\n")
    for frame in _frames(run_root / "initialized.notification.jsonl"):
        send(frame + b"\n")

    primary_id = None
    for step in steps:
        if step["op"] == "send_file":
            if step["origin"] == "client":
                for frame in _frames(run_root / step["path"]):
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

    # WHAT CAME BACK AGAINST WHAT THE SEED DECLARES. The handshake response is
    # part of the stream and is checked as such; everything after it has to be
    # the declared frames in the declared order.
    answered = [line for line in bytes(upstream_wire).splitlines() if line.strip()]
    handshake = _frames(record.path / "initialize.response.jsonl")
    # WHERE THE UPSTREAM SPOKE, which is not the same place on the two routes.
    # On the control the client's wire IS the upstream's, so it is the thing to
    # compare. On strict the client's wire is the MEDIATOR'S OUTPUT, and
    # comparing that against the seed would call every correct withholding a
    # stream that is not the scenario. The mediator records what arrived from
    # the upstream, so that is what the declaration is checked against.
    complete = handshake + declared
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
    expected = any(json.loads(frame).get("id") == primary_id for frame in declared)

    result = Run(run_dir=run_root, steps=steps, client_wire=bytes(client_wire),
                 upstream_wire=bytes(upstream_wire), terminal=terminal,
                 primary_id=primary_id, upstream_as_declared=as_declared,
                 terminal_expected=expected,
                 disposition=_disposition(run_root / "proxy.receipts.jsonl",
                                          primary_id))
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
