"""The child `worker_process` spawns: one payload in, one result line out.

At `sunglasses/_proxy_worker.py` because T4.R1 names that path. It sits beside
the package rather than inside `proxy/` so the thing being spawned is one file
with one job, and the underscore says what the name already implies: it is
spawned, not imported by anyone else.

Deliberately tiny. Everything it knows about the contract lives in
`inspection`, and everything it knows about bounds is that it has none: the
clock and the stdout limit are enforced by the parent, because a worker
enforcing its own deadline is a worker that can decide not to.

It prints EXACTLY ONE line and never anything else. The parent treats two lines
as a fault, so a stray print here is not cosmetic, it is a scan the proxy
cannot believe.
"""
from __future__ import annotations

import json
import os
import sys

from .proxy import inspection
from .proxy.worker_process import READY_FLAG


def _ready_fd(argv):
    """The pipe to announce readiness on. No arguments is a worker nobody is
    waiting on (`worker_process.run`); `--ready-fd N` with N an ASCII decimal
    descriptor is a spare; any other command line raises ValueError, never a
    guess at what the parent meant."""
    if not argv:
        return None
    if len(argv) == 2 and argv[0] == READY_FLAG and argv[1].isascii() \
            and argv[1].isdigit():
        return int(argv[1])
    raise ValueError("usage: _proxy_worker [--ready-fd N]")


def main(stdin=None, stdout=None, argv=None):
    stdin = stdin if stdin is not None else sys.stdin.buffer
    stdout = stdout if stdout is not None else sys.stdout.buffer
    # Parsed before the engine is built: a command line this child refuses
    # costs nothing, and exit 1 with no output is a fault the parent names.
    try:
        ready = _ready_fd(sys.argv[1:] if argv is None else argv)
    except ValueError:
        return 1
    # LOAD FIRST, THEN READ. The engine takes ~1.5 s to build, and loading it
    # after the request arrived charged that to the scan's deadline. A spare
    # started by `worker_process.ProcessScan` is told a pipe to announce
    # readiness on; it writes one byte there, never on stdout, whose contract
    # stays exactly one line.
    try:
        inspection.default_engine()
    except Exception:
        return 1
    if ready is not None:
        try:
            os.write(ready, b"R")
            os.close(ready)
        except (OSError, ValueError):
            return 1
    try:
        request = json.loads(stdin.read().decode("utf-8"))
        result = inspection.scan(
            request.get("params") or {},
            channel=request.get("channel") or "message",
            binding=request.get("binding") or {},
            content_bytes=request.get("content_bytes") or 0)
    except Exception:
        # No traceback, no message. The parent turns a silent or unreadable
        # child into a named fault, and anything printed here would be text
        # from a process that has been reading peer bytes.
        return 1
    stdout.write((json.dumps(result) + "\n").encode("utf-8"))
    stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
