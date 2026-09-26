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
import time

from . import (approvals, bounds, control, framing, inspection, pump,
               receipts, route, supervisor)

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


def install_records_home(override=None):
    """The tree `install.py` writes its records and locks under.

    DERIVED from `state_root()`, never chosen beside it. `install.py` builds
    `<home>/proxy/installs` and `<home>/proxy/locks`; the proxy builds captures,
    approvals and receipts under `state_root()`. Those have to be one tree.

    They were not. #204 was the same disagreement one layer down -- `approve`
    defaulted to the current directory, so it looked where nothing had been
    written and refused with a true statement about the wrong place. The flow
    was never broken, it was unreachable, and the half left standing was this
    one: install read `$SUNGLASSES_HOME` while the proxy read `Path.home()`.

    `$SUNGLASSES_HOME` deliberately does not reach here. It governs SCANNER
    state -- receipts, policy, pins -- and relocating those is what it is for. A
    variable that also moved the approval store would be a switch anything in
    the process tree could flip, and approvals read from a directory an attacker
    controls are approvals an attacker writes. install does not take a
    `--state-root` either: a path chosen once at config-write time is the same
    hole one layer up.
    """
    return state_root(override).parent


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
    identity = _identity(upstream_argv)
    store = approvals.Store(state_root(root), server_id=identity)
    # T2.R6's channel. Without it the route refuses a tools/list rather than
    # forwarding it, which is correct but useless: this is what lets the proxy
    # run its own list and therefore what lets a human ever approve a server.
    channel = control.Control(session=session, upstream_write=upstream_write)
    return route.Route(session=session, log=log,
                       upstream_write=upstream_write,
                       client_write=client_write, approvals=store,
                       control=channel, server_identity=identity)


def main(argv=None, stdin=None, stdout=None, stderr=None):
    stderr = stderr if stderr is not None else sys.stderr
    upstream_argv, options = parse(sys.argv[1:] if argv is None else argv)
    root = options.get("state-root")
    if not upstream_argv:
        stderr.write(USAGE)
        return EXIT_USAGE

    # R28. Build the pattern set NOW, before the first frame is read. Its first
    # use was the activation scan of the server's first tools/list page, which
    # runs inside snapshot.collect's list deadline: a cold build (~10 s of CPU)
    # on a busy machine ran the list past it, the activation came back
    # incomplete, and nothing was captured to approve. Warm before the clock,
    # never move the clock.
    inspection.default_engine()

    stdin = stdin if stdin is not None else sys.stdin.buffer
    stdout = stdout if stdout is not None else sys.stdout.buffer

    run_id = receipts.new_run_id()
    try:
        log = receipts.Log(state_root(root), run_id=run_id, header={
            "session_id": run_id,
            "budget_version": "sg-proxy-budget/1",
            "catalog_version": "sg-proxy-catalog/1",
            "contract_version": "GATE3_CONTRACT_v5.1"})
    except receipts.ReceiptIOError as failure:
        # T9.R4, ruling 24b(a). No receipt, no mediation: the server is never
        # started, and the user is told what is wrong and how to clear it.
        stderr.write(f"sunglasses proxy: the receipt log could not be opened, "
                     f"so nothing was started. {failure}\n")
        return 1

    child = subprocess.Popen(
        upstream_argv,
        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        start_new_session=True)

    session = pump.Session(strict=True)
    session.attach_upstream(child, pgid=_group_of(child))

    write_lock = threading.Lock()

    # AR13, T8.R9. When the current write to the client began, or None. A
    # client that stops reading makes this write block for ever on a full pipe,
    # and the mediator then holds a frame it cannot deliver and a server it
    # cannot drain. The watchdog reads this cell; it cannot be checked here,
    # because here is where we are stuck.
    writing_since = [None]

    to_client = client_writer(stdout, write_lock, writing_since)

    def to_upstream(raw):
        child.stdin.write(raw)
        child.stdin.flush()

    engine = build_route(session=session, log=log, upstream_argv=upstream_argv,
                         upstream_write=to_upstream, client_write=to_client,
                         root=root)

    # AR14. BOTH directions are threads, and the process ends when EITHER of
    # them does.
    #
    # The client loop used to run on the main thread, so a server that exited
    # left the proxy blocked on a client read that would never return: the
    # upstream was gone, the reader thread had finished, and the mediator sat
    # there mediating nothing until the client happened to close its end. A
    # server's exit status could not propagate because the process it should
    # propagate through was still running.
    #
    # There is nothing to mediate once either side is gone, so whichever
    # finishes first ends the session, and the teardown below runs exactly once
    # on the main thread.
    done = threading.Event()
    # AR14. Set once the teardown has run, so a caller that OWNS the process
    # can leave without waiting on a client reader that is blocked on a pipe
    # nobody will write to again. See `exit_process`.
    finished = _FINISHED
    finished.clear()
    reader = threading.Thread(target=_drain, args=(engine, child, done),
                              daemon=True)
    client = threading.Thread(
        target=_drain_client, args=(engine, session, stdin, done), daemon=True)
    watchdog = threading.Thread(
        target=_watchdog, args=(session, log, writing_since, done, child),
        daemon=True)
    reader.start()
    client.start()
    watchdog.start()

    try:
        done.wait()
    finally:
        _close(child)
        # AR13. A reader blocked writing to a client that has stopped reading
        # does not return, and waiting five more seconds for it is the
        # unbounded wait the stall deadline exists to END. Once that deadline
        # has fired the teardown is what "bounded" means, so the courtesy join
        # is cut to the kill grace; the thread is a daemon and the process
        # leaves without it.
        stalled = session.closed_with()
        reader.join(timeout=bounds.KILL_GRACE_MS / 1000
                    if stalled and stalled[0] == "SCAN_DEADLINE" else 5)
        code = _exit_code(session, child)
        finished.set()
        # T905. The log needs a terminal event or it does not verify, and it
        # did not have one: every receipt this command produced described a
        # session whose ending was never written down.
        _record_ending(log, session, code)
        log.close()
        supervisor.stop_group(child.pid, handle=child)
    return code



def _record_ending(log, session, code):
    """The terminal row, best effort. A log we can no longer write is already
    a stop the session has recorded, and failing to close the record is not a
    reason to raise on the way out."""
    try:
        closed = session.closed_with()
        log.event("SESSION_TORN_DOWN",
                  reason_code=closed[0] if closed else None,
                  rule=closed[1] if closed else None,
                  settled=True)
    except Exception:
        pass


# AR14. The client reader is a DAEMON thread blocked in a read on this
# process's own stdin. When `main` returns, interpreter shutdown tries to close
# that buffered reader, cannot take its lock, and aborts the process with
# "could not acquire lock ... at interpreter shutdown, possibly due to daemon
# threads" -- SIGABRT instead of the server's exit status, which is the very
# thing AR14 is about.
#
# So the teardown is complete BEFORE anyone leaves -- the child is closed, the
# reader joined, the log written and closed, the group stopped -- and the entry
# point that owns the process then leaves without running finalizers. That is
# `os._exit`, and it is confined to `exit_process` so `main` stays a function a
# test can call in-process without killing the test runner.
_FINISHED = threading.Event()


def exit_process(code):
    """Leave, from a caller that owns the process and nothing else."""
    # STDERR ONLY, AND DO NOT "FIX" THIS BY ADDING STDOUT BACK.
    #
    # stdout IS the client pipe. Flushing it here is a write to the client, and
    # the single case that reaches this line with anything buffered is the case
    # where the client has stopped reading -- which is the case this whole exit
    # path exists to escape. The flush then blocks for ever on a full pipe and
    # the BOUNDED teardown never ends: the proxy detects the stall, tears the
    # session down, and sits in its own exit. That was a real defect here, and
    # it looks exactly like a missing flush to anyone tidying up.
    #
    # There is nothing to lose by skipping it. Every frame the client is owed
    # was written AND flushed by `to_client`, under the write-stall clock, at
    # the moment it was released. Nothing is buffered here that anyone is
    # waiting for. `test_leaving_the_process_does_not_flush_the_client_pipe`
    # fails if stdout is flushed again.
    try:
        sys.stderr.flush()
    except Exception:
        pass
    if _FINISHED.is_set():
        os._exit(code if isinstance(code, int) else EXIT_FAULT)
    raise SystemExit(code)


def client_writer(stdout, write_lock, writing_since):
    """The one place bytes go to the client, with the stall clock around it.

    A module-level factory rather than a closure so the clock can be tested:
    as a closure inside `main` nothing could reach it, and a mutation that
    deleted the clock left the whole suite green while the write-stall deadline
    quietly measured nothing. The thing being timed is the write, so the timing
    has to live where the write is.
    """
    def to_client(raw):
        with write_lock:
            writing_since[0] = time.monotonic()
            try:
                stdout.write(raw)
                stdout.flush()
            finally:
                writing_since[0] = None
    return to_client


def _watchdog(session, log, writing_since, done, child, interval=0.1):
    """AR10, AR11 and AR13. The deadlines, on a thread that is never blocked.

    Every bound this checks was already written down in `bounds.py` and asked
    by nobody, so a server could hold a request for ever, stop halfway through
    a frame, or wait for a client that had stopped reading, and the proxy would
    wait exactly as long as it was asked to. A mediator that can be made to
    wait indefinitely can be taken out of the path by doing nothing at all,
    which is the cheapest attack there is.

    It runs on its own thread for the reason the checks exist: the reader is
    blocked in the read, and the writer is blocked in the write. Neither can
    time itself.
    """
    # A SAFETY THREAD THAT DIES QUIETLY IS WORSE THAN NO SAFETY THREAD. This one
    # was shipped with a missing import: it raised NameError on its first stall
    # check, the daemon thread vanished without a word, and every deadline in
    # this file silently stopped existing while the tests that do not exercise
    # them stayed green. So the loop names its own failure and ends the session
    # rather than leaving one that can be made to wait for ever.
    try:
        _sweep_until_done(session, log, writing_since, done, interval)
    except Exception as failure:                            # pragma: no cover
        try:
            log.event("WATCHDOG", reason_code="SCAN_EXCEPTION", rule="S3")
        except Exception:
            pass
        session._close("SCAN_EXCEPTION",
                       f"the watchdog stopped: {type(failure).__name__}",
                       rule="S3", kind="WATCHDOG_FAILED")
    # Whatever ended the loop, the session is over. RELEASE THE MAIN THREAD
    # FIRST and let it do the stopping: its teardown already closes the child
    # and stops the group, and doing it here as well put a second kill grace in
    # series ahead of a teardown that is supposed to be BOUNDED. The bound is
    # the property AR13 measures, so the path to it does not get to be
    # leisurely.
    done.set()


def _sweep_until_done(session, log, writing_since, done, interval):
    while not done.wait(interval):
        if session.closed_with():
            return
        if session.sweep_deadlines() is not None:
            return
        started = writing_since[0]
        if started is None:
            continue
        stalled = bounds.check_deadline(
            "write_stall", elapsed_ms=(time.monotonic() - started) * 1000)
        if stalled:
            # T9.R2. The stall is RECORDED before the teardown, because the
            # teardown is what makes it unobservable afterwards.
            try:
                log.event("WRITE_STALLED", reason_code=stalled.reason,
                          rule=stalled.rule)
            except Exception:
                pass
            session._close(stalled.reason, stalled.detail, rule=stalled.rule,
                           kind=stalled.kind)
            return


def _drain(engine, child, done):
    try:
        engine.pump_upstream(child.stdout)
    except Exception:
        # The session records the fault. A traceback here is the one place
        # upstream-adjacent text could reach an operator's terminal, and
        # T10.R3's last sentence refuses that for the same reason.
        pass
    finally:
        done.set()


def _drain_client(engine, session, stdin, done):
    tail = []
    try:
        for raw in framing.bounded_lines(stdin, framing.MAX_FRAME_BYTES, tail):
            engine.client_frame(raw)
            if session.closed_with():
                break
        # AR15. A client that stops mid-frame has not ended cleanly. The bytes
        # are never forwarded -- that is the reader's rule now -- and the
        # session says so rather than exiting zero on a truncated request.
        if tail and not session.closed_with():
            session._close("MALFORMED_CLIENT",
                           "the client stopped in the middle of a frame",
                           kind="FRAME_UNTERMINATED")
    except Exception:
        pass
    finally:
        done.set()


def _close(child):
    try:
        child.stdin.close()
    except OSError:
        pass


def _exit_code(session, child):
    """T8.R14. A fault is nonzero always; an ordinary clean exit propagates.

    AR14b. This read `child.poll()`, and poll answers None both for "still
    running" and for "exited, not reaped yet" -- and None was mapped to
    EXIT_OK. So an upstream that had already failed was reported as a clean run
    whenever the status had not been collected in time, which on an idle
    machine was 3 runs in 12. A non-blocking question cannot tell those two
    states apart, so it is the wrong question: the child's stdin is already
    closed by `_close` above, and a child that is going to exit has begun.

    The wait is BOUNDED by the same kill grace the teardown uses, and a timeout
    still means EXIT_OK. Unknown is not a fault -- the proxy may be leaving
    first, and inventing a nonzero code there would report a failure that did
    not happen. Only a code we actually have propagates.
    """
    if session.closed_with():
        return EXIT_FAULT
    try:
        code = child.wait(timeout=bounds.KILL_GRACE_MS / 1000)
    except subprocess.TimeoutExpired:
        code = None
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
