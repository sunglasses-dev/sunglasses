"""`sunglasses proxy`, the process. One client on stdio, one server as a child.

Written against `tests/test_proxy_serve.py`, committed first.

Everything above this file is a decision. This is the plumbing that puts those
decisions between two real pipes, and plumbing is where mediation is actually
won or lost: a correct policy on a pipe that was never in the path protects
nothing.

Three things it has to get right.

The child is started in its OWN PROCESS GROUP and its handle is attached to the
session. T8.R12 says liveness has three answers and only the handle tells them
apart, and the group is what teardown kills. A child sharing our group is worse
than untidy: the kill aimed at the server lands on this process too.

Both directions run at once and only one of them is on this thread. The client
direction is the main loop, the upstream direction is a reader thread, because
a proxy that reads one pipe at a time deadlocks the first time a server answers
before the next request arrives.

And the exit is a teardown, not a return. The group is killed on the way out,
descendants included, or a proxy that exits cleanly leaves an unmediated server
still running and still holding the pipes it was installed in front of.
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import subprocess
import sys
import threading
import uuid

from . import approvals, framing, pump, receipts, route, supervisor

USAGE = ("usage: python -m sunglasses.proxy [--config PATH] "
         "[--state-root PATH] -- <server command> [args...]\n")

EXIT_OK = 0
EXIT_FAULT = 1
EXIT_USAGE = 2


def parse(argv):
    """Everything after the first bare `--` is the server's own command line.

    A separator rather than a quoted string, because a server command is an
    argv and flattening it into one argument makes the proxy guess at quoting
    the shell has already done correctly. Without the separator there is no way
    to tell our options from the server's, and guessing means running something
    the user did not write, so it is a usage error rather than a default.
    """
    argv = list(argv or [])
    if "--" not in argv:
        return None, {}
    split = argv.index("--")
    options, upstream = argv[:split], argv[split + 1:]
    parsed = {}
    index = 0
    while index < len(options):
        if options[index] in ("--config", "--state-root") and \
                index + 1 < len(options):
            parsed[options[index][2:]] = options[index + 1]
            index += 2
            continue
        index += 1
    return (upstream or None), parsed


def state_root(override=None):
    """Where receipts, approvals and install records live.

    An ARGUMENT, not an environment variable. This module ships in the wheel,
    and a variable that moves the receipt log and the approval store is a
    switch anything in the process tree could flip: approvals read from a
    directory an attacker controls are approvals an attacker writes.
    """
    if override:
        return pathlib.Path(override)
    return pathlib.Path.home() / ".sunglasses" / "proxy"


def build_route(*, session, log, upstream_argv, upstream_write, client_write,
                root=None):
    """The wiring, separated so it can be inspected without spawning anything.

    The approval store is the REAL one and not a bypass. T5.R2 refuses calls
    until a human has approved the snapshot, and that gate stays shut here even
    though it means no tools/call can be forwarded yet, because the list and
    activation flow (T2.R6/R7, T5.R3) is the next slice. A gate opened to make
    the artifact feel finished is the one change that would make the rest of
    this decorative.
    """
    store = approvals.Store(state_root(root),
                            server_id=_identity(upstream_argv))
    return route.Route(session=session, log=log,
                       upstream_write=upstream_write,
                       client_write=client_write, approvals=store)


def main(argv=None, stdin=None, stdout=None, stderr=None):
    stderr = stderr if stderr is not None else sys.stderr
    upstream_argv, options = parse(sys.argv[1:] if argv is None else argv)
    root = options.get("state-root")
    if not upstream_argv:
        stderr.write(USAGE)
        return EXIT_USAGE

    stdin = stdin if stdin is not None else sys.stdin.buffer
    stdout = stdout if stdout is not None else sys.stdout.buffer

    run_id = uuid.uuid4().hex
    log = receipts.Log(state_root(root), run_id=run_id, header={
        "session_id": run_id,
        "budget_version": "sg-proxy-budget/1",
        "catalog_version": "sg-proxy-catalog/1",
        "contract_version": "GATE3_CONTRACT_v5.1"})

    child = subprocess.Popen(
        upstream_argv,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True)

    session = pump.Session(strict=True)
    session.attach_upstream(child, pgid=_group_of(child))

    write_lock = threading.Lock()

    def to_client(raw):
        with write_lock:
            stdout.write(raw)
            stdout.flush()

    def to_upstream(raw):
        child.stdin.write(raw)
        child.stdin.flush()

    engine = build_route(session=session, log=log, upstream_argv=upstream_argv,
                         upstream_write=to_upstream, client_write=to_client,
                         root=root)

    reader = threading.Thread(target=_drain, args=(engine, child), daemon=True)
    reader.start()

    try:
        for raw in framing.bounded_lines(stdin, framing.MAX_FRAME_BYTES):
            engine.client_frame(raw)
            if session.closed_with():
                break
    finally:
        _close(child)
        reader.join(timeout=5)
        code = _exit_code(session, child)
        log.close()
        supervisor.stop_group(child.pid, handle=child)
    return code


def _drain(engine, child):
    try:
        engine.pump_upstream(child.stdout)
    except Exception:
        # The session records the fault. A traceback here is the one place
        # upstream-adjacent text could reach an operator's terminal, and
        # T10.R3's last sentence refuses that for the same reason.
        pass


def _close(child):
    try:
        child.stdin.close()
    except OSError:
        pass


def _exit_code(session, child):
    """T8.R14. A fault is nonzero always; an ordinary clean exit propagates."""
    if session.closed_with():
        return EXIT_FAULT
    code = child.poll()
    return EXIT_OK if code in (None, 0) else int(code)


def _identity(upstream_argv):
    """T1.R1, reduced to what this slice can honestly compute: the resolved
    command, its arguments and the working directory. The env allowlist belongs
    with the config work and is named here rather than quietly omitted."""
    material = "\x00".join([os.path.realpath(upstream_argv[0])]
                           + list(upstream_argv[1:]) + [os.getcwd()])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _group_of(child):
    try:
        return os.getpgid(child.pid)
    except OSError:
        return None
