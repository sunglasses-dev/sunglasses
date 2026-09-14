#!/usr/bin/env python3
"""Record both directions of a stdio session and change nothing about it.

The direct route is defined by NOT passing the mediator, so there is no receipt
for it and nothing attests what crossed. The consumer side was repaired first
and the row still came back INVALID_STIMULUS, because the generated
configuration launched the native server unwrapped: the capture existed only in
an exam test that wrote the file itself. A test that produces the evidence it
then reads has proved the test.

So this is the producer. It sits in the configuration where the bare command
used to be, passes bytes through untouched in both directions, and appends every
frame to its capture files as it goes.

NOT A MEDIATOR. It parses nothing, holds nothing, answers nothing and delays
nothing. If it ever decided anything, the route would no longer be the
unmediated one the scenario is about.
"""
from __future__ import annotations

import argparse
import pathlib
import subprocess
import sys
import threading


def _pump(source, sink, capture: pathlib.Path) -> None:
    """Copy bytes, appending each chunk to the capture as it passes."""
    with capture.open("ab") as record:
        while True:
            chunk = source.readline()
            if not chunk:
                break
            record.write(chunk)
            record.flush()
            try:
                sink.write(chunk)
                sink.flush()
            except (BrokenPipeError, ValueError, OSError):
                break
    try:
        sink.close()
    except Exception:                                        # pragma: no cover
        pass


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="capture a direct stdio route")
    parser.add_argument("--ingress", type=pathlib.Path, required=True,
                        help="frames the client sends to the server")
    parser.add_argument("--egress", type=pathlib.Path, required=True,
                        help="frames the server sends back")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)

    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("no upstream command to run")
    args.ingress.parent.mkdir(parents=True, exist_ok=True)

    child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    threads = [
        threading.Thread(target=_pump, daemon=True,
                         args=(sys.stdin.buffer, child.stdin, args.ingress)),
        threading.Thread(target=_pump, daemon=True,
                         args=(child.stdout, sys.stdout.buffer, args.egress)),
    ]
    for thread in threads:
        thread.start()
    code = child.wait()
    for thread in threads:
        thread.join(timeout=2)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
