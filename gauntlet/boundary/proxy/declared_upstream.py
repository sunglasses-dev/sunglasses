#!/usr/bin/env python3
"""An upstream that serves the frames the SCENARIO declares, and nothing else.

G2-06's mutation is a descriptor: a `tools/list` result whose `read_text_file`
description carries an injection. The scenario materialises that result into
`upstream.jsonl`, which is the point of the seed, and its own note says the
mutation is declared by the scenario rather than invented by the harness.

So this replays it. It answers the handshake so a session can open, and for
every other request carrying an id it writes the next declared frame with that
id, because the client picks the id and a replayed frame with the recorded one
would correlate to nothing.

It is not a server. It has no tools of its own, it holds no state a scenario did
not give it, and a request it has no declared answer for gets a JSON-RPC error
rather than an invented result: answering with something plausible is how a row
comes back green about a scenario that never ran.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys

PROTOCOL_VERSION = "2024-11-05"


def _write(out, message: dict) -> None:
    out.write((json.dumps(message, separators=(",", ":")) + "\n").encode())
    out.flush()


def serve(stream_path: pathlib.Path, stdin=None, stdout=None) -> int:
    stdin = stdin if stdin is not None else sys.stdin.buffer
    stdout = stdout if stdout is not None else sys.stdout.buffer

    declared = []
    for line in pathlib.Path(stream_path).read_bytes().splitlines():
        if line.strip():
            declared.append(json.loads(line))
    served = 0

    for raw in stdin:
        if not raw.strip():
            continue
        try:
            message = json.loads(raw)
        except ValueError:
            continue
        request_id = message.get("id")
        if request_id is None:                      # notifications
            continue
        if message.get("method") == "initialize":
            _write(stdout, {"jsonrpc": "2.0", "id": request_id, "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "declared-upstream", "version": "1"}}})
            continue
        if served >= len(declared):
            # NO DECLARED ANSWER, said out loud. A plausible result here is the
            # failure this whole harness keeps finding: the row completes, the
            # grader scores it, and nothing ran.
            _write(stdout, {"jsonrpc": "2.0", "id": request_id, "error": {
                "code": -32601,
                "message": "this scenario declares no further upstream frame"}})
            continue
        frame = dict(declared[served])
        served += 1
        # THE CLIENT'S ID, not the recorded one. A replayed frame carrying the
        # id it was recorded with correlates to nothing in this session, and the
        # mediator would be right to leave the request hanging.
        frame["id"] = request_id
        _write(stdout, frame)
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="replay a scenario's declared upstream")
    parser.add_argument("--stream", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    return serve(args.stream)


if __name__ == "__main__":
    raise SystemExit(main())
