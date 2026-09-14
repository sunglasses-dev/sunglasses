#!/usr/bin/env python3
"""An upstream that answers with the frames the SCENARIO declares, verbatim.

The generation 2 fixtures are exact on both sides: the client frames and the
upstream frames are scripted, and their ids already correlate. So this replays
them as written and rewrites nothing. The generation 1 replay had to rewrite ids
because the client there chose its own; doing it here would edit the scenario.

A request it has no declared answer for gets a JSON-RPC error rather than an
invented result. Answering with something plausible is how a row comes back
green about a session that never happened, and this whole adapter exists because
that keeps occurring.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys


def _frames(path: pathlib.Path) -> list[bytes]:
    return [line for line in pathlib.Path(path).read_bytes().splitlines() if line.strip()]


def serve(handshake_path, stream_path, stdin=None, stdout=None) -> int:
    stdin = stdin if stdin is not None else sys.stdin.buffer
    stdout = stdout if stdout is not None else sys.stdout.buffer

    handshake = _frames(handshake_path) if handshake_path else []
    declared = _frames(stream_path)
    handshake_ids = [json.loads(frame).get("id") for frame in handshake]
    served = 0

    for raw in stdin:
        if not raw.strip():
            continue
        try:
            message = json.loads(raw)
        except ValueError:
            continue
        if message.get("id") is None:              # notifications get no reply
            continue
        if message.get("id") in handshake_ids:
            # BY ID, NOT BY METHOD. Answering any `initialize` with the session
            # handshake ate G2-13.initialize_text's own request, whose declared
            # result is where that scenario puts the injection, so the surface
            # it exists to test went unexercised while the run looked ordinary.
            # The one thing a method test cannot tell apart is two calls of the
            # same method, and the fixtures correlate by id on both sides.
            stdout.write(handshake[handshake_ids.index(message["id"])] + b"\n")
            stdout.flush()
            continue
        if served >= len(declared):
            stdout.write(json.dumps(
                {"jsonrpc": "2.0", "id": message["id"],
                 "error": {"code": -32601,
                           "message": "this scenario declares no further "
                                      "upstream frame"}}).encode() + b"\n")
            stdout.flush()
            continue
        # VERBATIM. The ids in these fixtures already correlate, so anything
        # this process changed would be a change to the scenario.
        stdout.write(declared[served] + b"\n")
        stdout.flush()
        served += 1
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="replay a gen2 declared upstream")
    parser.add_argument("--handshake", type=pathlib.Path)
    parser.add_argument("--stream", type=pathlib.Path, required=True)
    args = parser.parse_args(argv)
    return serve(args.handshake, args.stream)


if __name__ == "__main__":
    raise SystemExit(main())
