"""`sunglasses proxy`, the process. One client on stdio, one server as a child.

Written against `tests/test_proxy_serve.py`, committed first.

Everything above this file is a decision. This is the plumbing that puts those
decisions between two real pipes, and plumbing is where mediation is actually
won or lost: a correct policy on a pipe that was never in the path protects
nothing.

Three things it has to get right.

The child is started in its OWN PROCESS GROUP and its handle is attached to the
session. Contract row 8.12 says liveness has three answers and only the handle tells them
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
import shlex
import subprocess
import sys
import threading
import time

from . import (approvals, bounds, control, framing, inspection, pump,
               receipts, route, supervisor, worker_process)

USAGE = ("usage: python -m sunglasses.proxy [--config PATH] "
         "[--state-root PATH] [--worker inprocess|process] "
         "-- <server command> [args...]\n")

# OPT-IN, and the default is `inprocess`. `process` runs every scan in a child
# with a kill on deadline and a stdout bound; `inprocess` runs it in the serving
# process.
WORKER_MODES = ("inprocess", "process")

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
        if options[index] in ("--config", "--state-root", "--worker") and \
                index + 1 < len(options):
            parsed[options[index][2:]] = options[index + 1]
            index += 2
            continue
        if options[index].startswith("--worker="):
            parsed["worker"] = options[index].split("=", 1)[1]
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


def approval_notice(stderr, root=None, command_stem=None):
    """The one line a person needs when a server's tools are withheld.

    It is the same command `sunglasses proxy approve` documents, with the two
    ids already filled in, plus `--state-root` only when this proxy was given
    one (the command's own default is the proxy's default root, so a line
    without it would point at the wrong store). The ids are digests the route
    has already checked are alphanumeric.

    The root is anchored HERE to the proxy's own working directory, because
    the person pastes the command into a terminal that is somewhere else: a
    relative root would name a different, empty store. It is joined to the
    working directory and NOT normalised: `link/../store` goes through the
    symlink and then up from its target, which a lexical clean-up would turn
    into a different directory. It is then shell-quoted. Quoting does not make
    a path safe to print: a root with a control character (a newline splits
    the line, an escape byte rewrites the terminal) is chosen by whoever wrote
    the launch configuration, so such a root is never echoed; the line says so
    and leaves the flag to the person.
    """
    shown = os.path.join(os.getcwd(), str(root)) if root else None
    unsafe = shown is not None and not shown.isprintable()

    def notice(server_id, snapshot_sha256):
        if unsafe:
            where = (" (this proxy was started with a --state-root whose name has "
                     "control characters, so it is not printed: add the same "
                     "--state-root to the command)")
            tail = ""
        else:
            where = ""
            tail = f" --state-root {shlex.quote(shown)}" if shown else ""
        # An approval is bound to the folder the server is started from. Say which folder this
        # is on the same line, and (below) where an approval for the same command already
        # exists, so a run from the wrong folder reads as that and not as a server with no
        # tools. Our stderr only: the reply the agent gets is unchanged.
        here = os.getcwd()
        stderr.write(
            "sunglasses proxy: this server's tools are withheld until you approve "
            "them. At a terminal, run: sunglasses proxy approve "
            f"{server_id} --snapshot {snapshot_sha256}{tail} "
            f"(it shows the tools and asks before approving){where}; an approval is "
            f"bound to the folder the server is started from, and this run is in "
            f"{approvals.folder_text(here)}\n")
        elsewhere = approvals.other_folders(state_root(root), command_stem, here)
        if elsewhere:
            stderr.write(
                "sunglasses proxy: this server is already approved from "
                + ", ".join(elsewhere)
                + "; start it from there, or approve this run's capture with the command above\n")
        stderr.flush()
    return notice


def build_route(*, session, log, upstream_argv, upstream_write, client_write,
                root=None, worker=None, store=None, stderr=None):
    """The wiring, separated so it can be inspected without spawning anything.

    The approval store is the REAL one and not a bypass. Contract row 5.2 refuses calls
    until a human has approved the snapshot, and that gate stays shut here
    until a valid approval exists: the list and activation flow (contract rows
    2.6 and 2.7, contract row 5.3) runs through the control channel wired below,
    and a tools/call is forwarded only after it. A gate opened to make the
    artifact feel finished is the one change that would make the rest of this
    decorative.
    """
    identity = _identity(upstream_argv)
    stem = _command_stem(upstream_argv)
    if store is None:
        store = approvals.Store(state_root(root), server_id=identity, command_stem=stem)
    # contract row 2.6's channel. Without it the route refuses a tools/list rather than
    # forwarding it, which is correct but useless: this is what lets the proxy
    # run its own list and therefore what lets a human ever approve a server.
    channel = control.Control(session=session, upstream_write=upstream_write)
    # No `scan=` at all in the default mode, so Route keeps its own default and
    # the in-process path is not merely equivalent but the same call.
    extra = ({"scan": worker_process.ProcessScan()} if worker == "process"
             else {})
    try:
        return route.Route(session=session, log=log,
                           upstream_write=upstream_write,
                           client_write=client_write, approvals=store,
                           control=channel, server_identity=identity,
                           approval_notice=(approval_notice(stderr, root, stem)
                                            if stderr is not None else None),
                           **extra)
    except BaseException as error:
        # The spare is running already and the teardown that closes it only
        # runs once a session exists, so a Route that fails to build would
        # leave it behind (measured 9-25: reparented to pid 1, still loading).
        if extra:
            _close_spare(extra["scan"], error)
        raise


def _close_spare(scan, error):
    """Close the spare while `error` is on its way out, and never in its place.

    The error that is leaving says why the wiring failed. A close that raised
    through here would replace it with one that does not, so a close failure is
    caught and written onto `error` as a note, which a traceback prints on 3.11
    and later. On 3.9 and 3.10 there are no notes and the close failure is not
    shown; the wiring error still leaves unchanged. An interrupt during the
    close is not caught: the user stopping the process wins.
    """
    try:
        scan.close()
    except Exception as failure:  # noqa: BLE001
        if hasattr(error, "add_note"):
            error.add_note(f"closing the warm spare failed too: {failure!r}")


def main(argv=None, stdin=None, stdout=None, stderr=None):
    stderr = stderr if stderr is not None else sys.stderr
    upstream_argv, options = parse(sys.argv[1:] if argv is None else argv)
    root = options.get("state-root")
    worker = options.get("worker", "inprocess")
    # A misspelled mode must not quietly run the other one: `parse` skips what
    # it does not know, so the value is checked here, by name.
    if not upstream_argv or worker not in WORKER_MODES:
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
            "catalog_version": "sg-proxy-catalog/2",
            "contract_version": "GATE3_CONTRACT_v5.1"})
    except receipts.ReceiptIOError as failure:
        # No receipt, no mediation: the server is never
        # started, and the user is told what is wrong and how to clear it.
        stderr.write(f"sunglasses proxy: the receipt log could not be opened, "
                     f"so nothing was started. {receipts.printable(failure)}\n")
        return 1

    # The approval store is made BEFORE the server is started, for the same reason
    # as the log above: a file or a link where `approvals/` or `captures/` belongs
    # would raise out of `build_route` after the spawn, as a traceback, and leave a
    # server that ignores EOF running with nobody mediating it. After the log, so
    # the log's own refusal still comes first and this one is written down.
    try:
        store = approvals.Store(state_root(root),
                                server_id=_identity(upstream_argv))
    except (OSError, ValueError) as failure:
        where = getattr(failure, "filename", None) or state_root(root)
        what = ("capture store" if pathlib.Path(where).name == "captures"
                else "approval store")
        text, escaped = receipts.shown_path(where)
        stderr.write(f"sunglasses proxy: the {what} at {text} could "
                     f"not be made, so nothing was started "
                     f"({type(failure).__name__}). Fix it: make {text} a "
                     f"directory you own, chmod 700."
                     f"{receipts.ESCAPED_NOTE if escaped else ''}\n")
        _record_refusal(log, "STATE_IO_ERROR")
        return EXIT_FAULT

    try:
        child = subprocess.Popen(
            upstream_argv,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            start_new_session=True)
    except (OSError, ValueError) as failure:
        # The log is open and no server is running: say what failed, write the
        # refusal down, and end the run like the other refusals above. The
        # class and never the message, which can carry the command's own text.
        text, escaped = receipts.shown_path(upstream_argv[0])
        stderr.write(f"sunglasses proxy: the server could not be started, so "
                     f"nothing was started ({type(failure).__name__}). Fix it: "
                     f"make {text} a program you can run."
                     f"{receipts.ESCAPED_NOTE if escaped else ''}\n")
        _record_refusal(log, "CONFIG_IO_ERROR")
        return EXIT_FAULT
    # From here every way out stops the server's group. The teardown below runs
    # once the session threads have started, so a raise between the spawn and them
    # would orphan the child unless it is stopped here.
    try:
        session = pump.Session(strict=True)
        session.attach_upstream(child, pgid=_group_of(child))
    except BaseException as failure:
        _abandon(child, log, stderr, failure)
        if not isinstance(failure, Exception):
            raise
        return EXIT_FAULT

    write_lock = threading.Lock()

    # When the current write to the client began, or None. A
    # client that stops reading makes this write block for ever on a full pipe,
    # and the mediator then holds a frame it cannot deliver and a server it
    # cannot drain. The watchdog reads this cell; it cannot be checked here,
    # because here is where we are stuck.
    writing_since = [None]

    to_client = client_writer(stdout, write_lock, writing_since)

    def to_upstream(raw):
        child.stdin.write(raw)
        child.stdin.flush()

    try:
        engine = build_route(session=session, log=log,
                             upstream_argv=upstream_argv,
                             upstream_write=to_upstream, client_write=to_client,
                             root=root, worker=worker, store=store,
                             stderr=stderr)
    except BaseException as failure:
        _abandon(child, log, stderr, failure)
        if not isinstance(failure, Exception):
            raise
        return EXIT_FAULT

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
    try:
        reader.start()
        client.start()
        watchdog.start()
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
        # Ruling 64 (b): a thread that could not be started is not joined,
        # or the join's own RuntimeError would skip the stop below.
        if reader.ident is not None:
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
        # The warm spare, if any. `exit_process` leaves through `os._exit`, so
        # an atexit hook would never run and the spare would outlive us.
        close_scan = getattr(engine.scan, "close", None)
        if close_scan is not None:
            close_scan()
    return code



def _record_refusal(log, reason):
    """The terminal row for a run that ended before its session began, best
    effort, then the log closed. A refusal is written down like any ending."""
    try:
        log.event("SESSION_TORN_DOWN", reason_code=reason, rule="S3",
                  settled=True)
    except Exception:
        pass
    try:
        log.close()
    except Exception:
        pass


def _abandon(child, log, stderr, failure=None):
    """The server was started and the session was not: stop
    its group, then say so. Never a traceback from here (contract row 10.3)."""
    _close(child)
    supervisor.stop_group(child.pid, handle=child)
    _record_refusal(log, "INTERNAL_FAULT")
    if failure is not None:
        stderr.write(f"sunglasses proxy: the session could not be wired, so "
                     f"the server was stopped ({type(failure).__name__}).\n")


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
    """The deadlines, on a thread that is never blocked.

    Every bound this checks is written in `bounds.py` and this thread is what
    asks, so a server cannot hold a request for ever, stop halfway through a
    frame, or wait for a client that has stopped reading while the proxy waits
    exactly as long as it was asked to. A mediator that can be made to
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
            # The stall is RECORDED before the teardown, because the
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
    except Exception as failure:
        # A reader that dies ends the session BY NAME. A bare `pass` under a comment
        # saying the session records the fault would not record it: the teardown would
        # find no reason, write SESSION_TORN_DOWN with reason_code null, exit 0, and a
        # request already forwarded would never be answered.
        #
        # The detail is the CLASS and never the message. A traceback here is
        # the one place upstream-adjacent text could reach an operator's
        # terminal, and the rule against showing upstream text there refuses that; the message is
        # the same text by another route.
        try:
            engine.session._close(
                "SCAN_EXCEPTION",
                f"the upstream reader stopped: {type(failure).__name__}",
                rule="S3", kind="READER_FAILED")
        except Exception:
            pass
        # `read_upstream` pays what the close retained on its way out, and
        # that is the generator that just died. R66: an id read before the
        # close is answered.
        try:
            engine.pay_retained_refusals()
        except Exception:
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
    except Exception as failure:
        # The client side, and the same fault as `_drain`'s:
        # one kind, the direction in the detail, the class and not the message.
        # The debt is paid by the upstream reader, which is still running: the
        # close stops the server's group, its stdout ends, and `read_upstream`
        # pays what the close retained on its way out. Nothing this reader had
        # not already handed to the Route is forwarded, because it reads no
        # further.
        #
        # A frame that raised before admission is owed no
        # per-id refusal, so the close itself is said to the client, and it is
        # said FIRST. The close ends the server's group, the upstream reader
        # ends with it, and the process can be gone before this thread runs
        # another line: a write placed after `_close` never reached the client
        # A close in a log line only is the silent
        # `pass` again. Only when nothing closed first, so the frame never
        # names a cause that is not the session's.
        if session.closed_with() is None:
            try:
                engine.announce_close("SCAN_EXCEPTION", "S3")
            except Exception:
                pass
        try:
            session._close(
                "SCAN_EXCEPTION",
                f"the client reader stopped: {type(failure).__name__}",
                rule="S3", kind="READER_FAILED")
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
    """A fault is nonzero always; an ordinary clean exit propagates.

    `child.poll()` answers None for a child that has not finished exiting, and
    mapping None to EXIT_OK would report an upstream that was on its way to
    failing as a clean run. A non-blocking question cannot wait out an exit
    already under way, so it is the wrong question: the child's stdin is
    already closed by `_close` above, and a child that is going to exit has
    begun.

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


def _command_stem(upstream_argv):
    """`_identity` without the folder: the command and its arguments only."""
    material = "\x00".join([os.path.realpath(upstream_argv[0])] + list(upstream_argv[1:]))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _identity(upstream_argv):
    """Reduced to what this slice can honestly compute: the resolved
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
