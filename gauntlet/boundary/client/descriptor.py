"""One stdio client turn, for the requests a model does not choose.

G2-06 declares `tools/list`. The batch driver can only ask a model to call a
tool, so the row terminated as INVALID_STIMULUS and the descriptor surface the
scenario exists to test was never requested. Defaulting it to `read_text_file`
was worse and is what this replaces: it silently ran a different experiment and
reported result content as if it were a descriptor result.

A descriptor request is not a model's decision. It is part of session setup, the
client asks for it, and the mediator is supposed to inspect what comes back. So
this issues it directly: initialize, initialized, then the scenario's own
request, reading replies off stdout until the id comes back.

Deliberately small. It does what the three G2-06 rows need and nothing else, and
it is not an MCP client: no capability negotiation beyond the handshake, no
retries, no session reuse.
"""
from __future__ import annotations

import json
import pathlib
import subprocess
import time

PROTOCOL_VERSION = "2024-11-05"


class DescriptorTurnFailed(Exception):
    """The turn did not complete, which is not the same as a scenario result."""


def _frame(message: dict) -> bytes:
    return (json.dumps(message, separators=(",", ":")) + "\n").encode()


def run_turn(server_argv, request: dict, *, timeout: float = 12.0,
             stderr_path: pathlib.Path | None = None,
             wire_path: pathlib.Path | None = None) -> dict:
    """Send the handshake and `request`, and return the reply with that id.

    Returns the parsed reply. Raises rather than returning something plausible:
    a turn that did not complete has no verdict in it, and a caller that got
    `None` back would have to invent what it meant.
    """
    wanted = request.get("id")
    payload = b"".join((
        _frame({"jsonrpc": "2.0", "id": "descriptor-init", "method": "initialize",
                "params": {"protocolVersion": PROTOCOL_VERSION, "capabilities": {},
                           "clientInfo": {"name": "gate2-descriptor", "version": "1"}}}),
        _frame({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}}),
        _frame(request),
    ))

    if wire_path is not None:
        # WHAT THIS HARNESS WROTE TO THE SERVER, byte for byte. On the control
        # route there is no mediator to attest the arrival, so without this the
        # row is ungradeable on the route it exists to be compared against. A
        # turn this harness issued is not a model's decision, so our own record
        # of what crossed is a record of an arrival and not a report about one.
        pathlib.Path(wire_path).write_bytes(payload)

    started = time.monotonic()
    completed = subprocess.run(list(server_argv), input=payload,
                               capture_output=True, timeout=timeout)
    if stderr_path is not None:
        pathlib.Path(stderr_path).write_bytes(completed.stderr)

    replies = []
    for line in completed.stdout.splitlines():
        if not line.strip():
            continue
        try:
            replies.append(json.loads(line))
        except ValueError:
            # A frame this client cannot read is recorded by being skipped here
            # and named below if the wanted id never arrives. Guessing at it
            # would be the resynchronisation the mediator refuses to do.
            continue

    for reply in replies:
        if reply.get("id") == wanted:
            return reply
    raise DescriptorTurnFailed(
        f"no reply carrying id {wanted!r} after {round(time.monotonic() - started, 2)}s; "
        f"{len(replies)} readable frame(s) came back. "
        f"stderr tail: {completed.stderr.decode('utf-8', 'replace')[-400:]}")


def _call_of(message: dict, method: str) -> dict | None:
    if message.get("method") != method:
        return None
    params = message.get("params") or {}
    return {"method": message.get("method"),
            "name": params.get("name"),
            "arguments": params.get("arguments") or {}}


def observed_at_ingress(receipts_path: pathlib.Path, method: str, *,
                        client_wire: pathlib.Path | None = None) -> dict | None:
    """The call as it crossed the boundary, from the mediator's own receipts.

    ATTESTED INGRESS RATHER THAN A TRANSCRIPT. The stimulus gate used to compare
    what a model reported doing after the fact; this is what actually arrived,
    recorded by the thing in the middle. For a descriptor request the two would
    agree, but the reason for preferring one over the other does not depend on
    the case where they agree.
    """
    path = pathlib.Path(receipts_path)
    if not path.is_file():
        # NO MEDIATOR, which is what the control route is. The harness's own
        # wire capture is the attestation there, and it is still a wire record
        # rather than a transcript: the point was never which process held the
        # pen, it was that a decision reported after the fact is not an arrival.
        return _from_client_wire(client_wire, method)
    for line in path.read_bytes().splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("kind") != "RPC_INGRESS" or event.get("direction") != "request":
            continue
        try:
            message = json.loads(event.get("raw") or "")
        except ValueError:
            continue
        call = _call_of(message, method)
        if call is not None:
            return call
    return _from_client_wire(client_wire, method)


def _from_client_wire(wire_path, method: str) -> dict | None:
    if wire_path is None or not pathlib.Path(wire_path).is_file():
        return None
    for line in pathlib.Path(wire_path).read_bytes().splitlines():
        if not line.strip():
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue
        call = _call_of(message, method)
        if call is not None:
            return call
    return None
