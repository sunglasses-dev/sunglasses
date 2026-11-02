"""The doctor's per-route launch: start each wrapped route once and see whether it answers.

`doctor --launch-routes` builds a `RouteLauncher` and calls it once per WRAPPED entry.
A wrapped entry is `<python> -m sunglasses.proxy -- <the user's own server command>`, so
starting it starts the user's server. That is why this is asked for by name, and why
three things below are narrower than they could be.

* Only the user's own file (`~/.claude.json`). An entry in a project `.mcp.json` is never
  started, and one in a file named with `--config` only when the path is written as the
  user file's own (another path that links to it, or a `..`, is not): the classifier checks the marker and the start of
  the argument list, not what follows the `--`, so a file from a cloned repository can
  reach WRAPPED with any command after it.
* A scratch state root. `--state-root <private folder>` is put before the `--`, so the
  proxy writes its receipt, approvals and captures inside a folder this run removes.
  The command, arguments, environment, working folder and HOME are the user's own.
* One line per route, and only the program's file name. Arguments, environment, working
  folder, the route's output and any exception text are never printed.

What a verdict means. The frames sent are `initialize`, `notifications/initialized` and
`ping`, then stdin is closed; `tools/list` and `tools/call` are never sent, so nothing
here can make a tool run. PASS: `initialize` answered with a result (up to 19 s), the
`initialized` frame written, `ping` answered with a result inside the doctor's 2250 ms bound,
and after stdin closes the proxy exits 0 and every group seen below it is gone. FAIL:
`initialize` was answered and a later step was not (the `initialized` write included).
NOT_RUN: nothing was learned (not started, no `initialize` result in time), which could be
the user's server and not the proxy, so it is doubt and never a failure.

One clock. A route has `ROUTE_S` from spawn to the end of its cleanup, as one monotonic
deadline (`_deadline.Clock`). Every wait in this module takes its time from that clock, and
a test reads this file and `_deadline.py` and fails on any other way to wait: the wait for a
killed process to be reaped and the join of its output reader are paid out of the same 30 s.
The process list is read under it too: `ps` is stopped when the clock runs out, and the parse
of its rows, the /proc walk and the walk below the proxy check the clock between rows and
entries. A read that is cut short is unknown, never empty. One system call (a `listdir`, a
`read`, a write to a pipe) is not interrupted; the checks are between them. Until the
server's group has been seen, `PROXY_TEARDOWN_S` of the route is held back for the one thing
that can stop a server nobody has named: the proxy's own teardown after its input closes.

What it does not prove: it does not test the policy, and it cannot see bytes the way the
self-test can (there is no ingress file on a server that is not ours), so a loss shows as a
missing reply. The groups below the proxy are read from the process table in each step of
the wait for `initialize` and once after it (`ps`, or /proc where `ps` cannot be run; each
read ends at `READ_S` or at the route's deadline, checked between rows and entries) and every one
seen is kept and stopped on every way out. Where the table cannot be read before a start, no
route is started, because a server that cannot be stopped is not started. If it is lost while
a route runs, the proxy is given its own teardown (stdin closed, up to `PROXY_TEARDOWN_S`):
a proxy that leaves by itself has stopped its server. A proxy that has to be killed before
its server's group was seen leaves a server nobody can name: the route is not a PASS and
the run says a process may still be running.
"""
from __future__ import annotations

import os
import shutil
import signal
import sys
import tempfile
import threading
import time

from . import live_selftest as _live
from ._deadline import Clock
from .doctor import (DEADLINE_BOUND_MS, REASON_CAP, REASON_COULD_NOT_START,
                     REASON_NO_INITIALIZE, REASON_NOT_USER_FILE, REASON_OUT_OF_TIME,
                     REASON_UNSUPPORTED)

# No more than this many routes, and no more than this long in all.
MAX_ROUTES = 16
TOTAL_S = 120.0
# One route's whole allowance, from spawn to the end of its cleanup: one monotonic deadline.
ROUTE_S = 30.0
# Held back from that deadline for the work no wait covers: sending the kills and closing the
# pipes. Every wait, the reap of a killed process and the join of its output reader included,
# is cut to what is left of the route.
ROUTE_MARGIN_S = 0.5
# How often the server's groups are read while waiting for `initialize`, and the longest one
# read may take, the /proc walk included.
WATCH_STEP_S = 0.25
READ_S = 1.0
# The wait for `initialize` and for the ping; each is cut to what is left of the route.
INITIALIZE_S = 19.0
PING_WAIT_S = DEADLINE_BOUND_MS / 1000.0 + 0.25
# What the proxy needs to stop a server that ignores its closed input, from the proxy's own
# teardown (`serve.py`): the join of its reader thread (5 s), then `supervisor.stop_group`
# (SIGTERM, 2 s grace, SIGKILL), plus 1 s. A test reads both numbers from those modules, so a
# change there fails the test instead of quietly voiding this. The proxy is waited for this
# long when its server's group was never seen (the only way left to stop that server), and
# after the ping for the proxy's exit.
PROXY_TEARDOWN_S = 8.0
# The preflight read of the process list, before any route exists (it has a clock of its own),
# and the pause between two looks at a group that is going away.
PREFLIGHT_S = 3.0
NAP_S = 0.05

_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-@")


def _shown(text, limit=48) -> str:
    """A name safe to print: ASCII letters, digits and a few marks. The name comes from a
    file, and a terminal acts on escape sequences."""
    text = "".join(c if c in _NAME_CHARS else "?" for c in str(text)[:limit])
    return text or "?"


def _is_result(message) -> bool:
    return (isinstance(message, dict) and "error" not in message
            and "result" in message)


def _process_table(window):
    """{pid: (ppid, pgid)} from `ps`, or from /proc where `ps` cannot be run; None where
    neither can be read, which is not the same as an empty table.

    `window` is a `Clock`. The whole read ends with it: `ps` is killed when it runs out, and
    the parse of its rows and the /proc walk check it between rows and entries. A read
    that is cut short is None, never a partial table. One `listdir` or one `read` is a single
    system call and is not interrupted; the check is between entries."""
    if window.spent():
        return None
    done = window.run(["ps", "-A", "-o", "pid=,ppid=,pgid="], window.left(),
                      {"PATH": os.defpath})
    if done is not None and done[0] == 0:
        table = {}
        for line in done[1].splitlines():
            if window.spent():
                return None
            parts = line.split()
            if len(parts) == 3 and parts[0].isdigit() and parts[1].isdigit() \
                    and parts[2].isdigit():
                table[int(parts[0])] = (int(parts[1]), int(parts[2]))
        if table:
            return table
    if window.spent():
        return None
    try:
        table = {}
        for name in os.listdir("/proc"):
            if window.spent():
                return None
            if not name.isdigit():
                continue
            try:
                with open(f"/proc/{name}/stat", "rb") as handle:
                    raw = handle.read().decode("utf8", "replace")
            except OSError:
                continue
            # pid (comm) state ppid pgrp ...; comm may hold spaces and parentheses.
            rest = raw[raw.rindex(")") + 2:].split()
            table[int(name)] = (int(rest[1]), int(rest[2]))
        return table or None
    except (OSError, ValueError, IndexError):
        return None


def _descendant_groups(root_pid, window, table=None):
    """(groups, truncated): the process-group ids of every process below `root_pid`, and
    whether `window` (a `Clock`) ran out before the table was read or the walk ended.

    The proxy starts the user's server in a group of its own, so killing the proxy's group
    alone would leave that server running on Ctrl-C. Empty when nothing is below it or the
    table cannot be read; `_discovery_works()` is what says whether it can be. A walk that
    is cut short returns what it found and says so: what it found is real, what it did not
    reach is unknown.
    """
    table = _process_table(window) if table is None else table
    if table is None:
        return set(), window.spent()
    below = {}
    for pid, (ppid, pgid) in table.items():
        if window.spent():
            return set(), True
        below.setdefault(ppid, []).append((pid, pgid))
    groups, seen, todo = set(), {root_pid}, [root_pid]
    while todo:
        if window.spent():
            return groups, True
        for pid, pgid in below.get(todo.pop(), ()):
            if window.spent():
                return groups, True
            if pid not in seen:
                seen.add(pid)
                todo.append(pid)
                groups.add(pgid)
    return groups, False


def _any_alive(groups, clock) -> bool:
    """Whether a group in `groups` is alive. A group is looked at before the clock is, so one
    is always examined; a list that `clock` cuts short is "alive", because what was not looked
    at is not known to be gone."""
    unlooked = len(groups)
    for group in groups:
        unlooked -= 1
        if _live._group_alive(group) or (unlooked and clock.spent()):
            return True
    return False


def _kill_all(groups):
    """Kill each group in `groups`. It takes no clock because it waits for nothing: each
    kill is one signal, and a group that is not killed on time is a group left running."""
    for group in groups:
        _live._kill_group(group)


def _discovery_works() -> bool:
    """True only if this process can see itself in the process table. A launcher that
    cannot find the user's server's group cannot stop it, so it does not start one."""
    table = _process_table(Clock(PREFLIGHT_S))
    return bool(table) and os.getpid() in table


class RouteLauncher:
    """Callable `launcher(entry) -> (passed, checks)`, used as a context manager.

    `passed` is True, False, or None (nothing learned); on None the entry's `reason` is set
    to one of the codes in `doctor`. The context holds the private folder, the 120 s
    allowance and the signal handlers; it removes the folder and restores the handlers
    however it ends, and a Ctrl-C or TERM ends the run with the shell's code for it.
    """

    def __init__(self, announce=None):
        self._announce = announce or self._to_stderr
        self._tmp = None
        self._started = 0
        self._total = None
        self._previous = {}
        self._notes = {}
        self._supported = _live._supported() and _discovery_works()

    @staticmethod
    def _to_stderr(line):
        print(line, file=sys.stderr, flush=True)

    def __enter__(self):
        self._total = Clock(TOTAL_S)
        if self._supported:
            try:
                self._tmp = tempfile.mkdtemp(suffix="-sunglasses-doctor-routes")
                os.chmod(self._tmp, 0o700)
            except OSError:
                self._tmp = None
        if threading.current_thread() is threading.main_thread() and self._supported:
            for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
                self._previous[number] = signal.signal(number, _live._on_terminate)
        return self

    def __exit__(self, exc_type, exc, tb):
        for number, handler in self._previous.items():
            signal.signal(number, handler)
        self._previous = {}
        if self._tmp is not None:
            shutil.rmtree(self._tmp, ignore_errors=True)
            self._tmp = None
        if exc_type is not None and issubclass(exc_type, _live._Terminated):
            number = int(exc.args[0])
            word = "interrupted" if number == signal.SIGINT else "terminated"
            if self._notes.get("left_running"):
                print(f"sunglasses doctor: {word}; a route's process may still be running.",
                      file=sys.stderr)
            else:
                print(f"sunglasses doctor: {word}; the routes' processes and private "
                      "folder were cleaned up.", file=sys.stderr)
            raise SystemExit(128 + number)
        if exc_type is None and self._notes.get("left_running"):
            print("sunglasses doctor: a route's process may still be running: it could not "
                  "be shown to have stopped.", file=sys.stderr)
        return False

    def __call__(self, entry):
        def not_run(reason):
            entry.reason = reason
            return None, {}

        if not entry.user_file:
            return not_run(REASON_NOT_USER_FILE)
        if not self._supported:
            return not_run(REASON_UNSUPPORTED)
        if self._started >= MAX_ROUTES or self._total.left() < ROUTE_S:
            return not_run(REASON_CAP)
        built = self._build(entry.spec)
        if built is None or self._tmp is None:
            return not_run(REASON_COULD_NOT_START)
        self._started += 1
        argv, env, cwd, program = built
        root = os.path.join(self._tmp, f"route-{self._started}")
        try:
            os.mkdir(root, 0o700)
        except OSError:
            return not_run(REASON_COULD_NOT_START)
        argv = _with_state_root(argv, root)
        self._announce(f"will start: {_shown(entry.name)} ({_shown(entry.source)}) -> "
                       f"{_shown(program)}")
        clock = Clock(max(0.0, min(ROUTE_S, self._total.left()) - ROUTE_MARGIN_S))
        info = {}
        try:
            passed, checks, reason = _drive_route(argv, env, cwd, clock, self._notes, info)
        except _live._CouldNotStart:
            return not_run(REASON_COULD_NOT_START)
        if info.get("late_exit"):
            self._announce(f"{_shown(entry.name)}: server kept running after its input "
                           "closed; the proxy stopped it")
        if info.get("unseen_stopped"):
            self._announce(f"{_shown(entry.name)}: no server process was seen below the proxy; "
                           "the proxy stopped it when its input closed")
        if passed is None:
            return not_run(reason)
        return passed, checks

    @staticmethod
    def _build(spec):
        """(argv, env, cwd, program name) as the client would start the entry, or None
        where the entry cannot be started as written."""
        if not isinstance(spec, dict):
            return None
        command, args = spec.get("command"), spec.get("args")
        if not isinstance(command, str) or not isinstance(args, list) or "--" not in args:
            return None
        split = args.index("--")
        rest = args[split + 1:]
        if not rest or not all(isinstance(a, str) and "\x00" not in a for a in [command, *args]):
            return None
        # The package reads no environment wholesale, so the entry's own `env` is applied
        # by `env(1)` in front of the command, and the route inherits everything else.
        own = spec.get("env")
        pairs = []
        for key, value in (own.items() if isinstance(own, dict) else ()):
            if not (isinstance(key, str) and isinstance(value, str)):
                continue
            if not key or "=" in key or key.startswith("-") or "\x00" in key + value:
                return None
            pairs.append(f"{key}={value}")
        argv = [command, *args]
        if pairs:
            argv = ["/usr/bin/env", *pairs, *argv]
        cwd = spec.get("cwd")
        if cwd is not None and not (isinstance(cwd, str) and os.path.isdir(cwd)):
            return None
        return argv, None, cwd, os.path.basename(rest[0])


def _with_state_root(argv, state_root):
    """`--state-root <folder>` just before the first `--`, so it is the last one the
    proxy reads. Everything else in the command is untouched."""
    split = argv.index("--")
    return argv[:split] + ["--state-root", state_root] + argv[split:]


class _Route:
    """One spawned route and the groups to stop when it ends.

    `groups` only grows: every group seen below the proxy while the route runs is kept,
    so losing the process list later does not lose the server. `truncated` is whether the
    latest read of the process list ran out of time before it was complete.
    """

    def __init__(self, argv, env, cwd, clock):
        self.peer = _live._Peer(argv, env, cwd, clock)
        self.groups = set()
        self.truncated = False
        # True when the proxy left by itself after its input closed while no group below it
        # had been seen: the proxy's own teardown is what stopped that server.
        self.proxy_stopped_unseen = False

    def watch(self, clock):
        """Read the groups below the proxy. The read ends at `READ_S` or with `clock`."""
        found, self.truncated = _descendant_groups(self.peer.proc.pid, clock.sub(READ_S))
        self.groups |= found

    def alive(self, clock) -> bool:
        return _any_alive(self.groups, clock)

    def stop(self, clock) -> bool:
        """Every way out ends here: the proxy's group, and the groups below it. True only
        if every group that could hold the server is known to be stopped. A server whose
        group was seen, by a read that reached the end, is killed by group. One whose group
        was never seen (or whose read was cut short) can only be stopped by the proxy's own
        teardown, so the proxy is given its input closed and `PROXY_TEARDOWN_S` (inside what
        is left of the route) to leave by itself: a proxy that does has stopped its server.
        A proxy that has to be killed before that leaves a server nobody can name, and that
        is not reported as stopped."""
        proxy = self.peer.proc.pid
        running = self.peer.proc.poll() is None
        if running:
            self.watch(clock)
        proxy_stopped_it = False
        if running and (not self.groups or self.truncated):
            self.peer.close_stdin()
            code = self.peer.wait(clock.take(PROXY_TEARDOWN_S))
            # A proxy that ran to its end ran its teardown; one that a signal ended (a
            # negative code) did not.
            proxy_stopped_it = code is not None and code >= 0
            self.proxy_stopped_unseen = proxy_stopped_it and not self.groups
        self.peer.kill(clock)
        groups = self.groups | {proxy}
        _kill_all(self.groups)
        gone = clock.sub(_live.GROUP_GONE_S)
        while not gone.spent() and _any_alive(groups, gone):
            gone.sleep(NAP_S)
        if _any_alive(groups, gone):
            return False
        return (bool(self.groups) and not self.truncated) or not running or proxy_stopped_it


def _await_initialize(route, clock):
    """The reply to `initialize`, or None. The groups below the proxy are read in every
    step of the wait, so the server is known before it has answered. The wait is the
    smaller of `INITIALIZE_S` and what is left of the route after the time held back for
    the proxy's teardown, and every read in it ends with the wait."""
    peer = route.peer
    window = clock.sub(INITIALIZE_S, PROXY_TEARDOWN_S)
    while True:
        route.watch(window)
        if window.spent():
            return None
        init, _ = peer.reply(1, window.take(WATCH_STEP_S))
        if init is not None:
            route.watch(clock)
            return init
        if peer.proc.poll() is not None:
            return None


def _drive_route(argv, env, cwd, clock, notes=None, info=None):
    """(passed, checks, reason): True or False with the checks, or None with the code.

    `clock` is the route's one deadline, from spawn to the end of its cleanup. Each wait
    is the smaller of its own bound and what is left, with the groups' going held back
    (`GROUP_GONE_S`) once the server's group has been seen. So a route never runs past it,
    and an answered `initialize` followed by a failed step is a FAIL whatever the clock says
    of the step that failed. `info["late_exit"]` is set when the proxy needed longer than a
    prompt exit to leave after its input closed, a server that keeps running being the cause.
    """
    try:
        route = _Route(argv, env, cwd, clock)
    except _live._CouldNotStart:
        raise
    except Exception:
        # The class of the failure is not worth a word: it could carry the command's text.
        raise _live._CouldNotStart("spawn") from None
    try:
        peer = route.peer
        short = clock.left() - PROXY_TEARDOWN_S < INITIALIZE_S
        peer.send(_live._INIT)
        init = _await_initialize(route, clock)
        if not _is_result(init):
            return None, {}, (REASON_OUT_OF_TIME if short or clock.spent()
                              else REASON_NO_INITIALIZE)

        # From here the route has answered, and every step that does not go right is a FAIL.
        # "disconnect" needs the server's group to have been seen, because it is the
        # server's group that has to be gone.
        checks = {"initialized": "FAIL", "deadline": "FAIL", "disconnect": "FAIL"}
        # As in the self-test, the clock starts before the second frame is written.
        started = time.monotonic()
        # The write is a step of the check: a pipe that took no bytes is a FAIL.
        if peer.send(_live._INITIALIZED):
            checks["initialized"] = "PASS"
        pong = None
        if peer.send(_live._PING):
            # A reply later than the bound fails whatever it says, so waiting longer buys nothing.
            pong, _ = peer.reply(4, clock.take(PING_WAIT_S, _live.GROUP_GONE_S))
        if _is_result(pong) and isinstance(pong["result"], dict) \
                and _live._ms(started) <= DEADLINE_BOUND_MS:
            checks["deadline"] = "PASS"

        peer.close_stdin()
        closed = time.monotonic()
        code = peer.wait(clock.take(PROXY_TEARDOWN_S, _live.GROUP_GONE_S))
        if code == 0 and route.groups:
            if info is not None and time.monotonic() - closed > _live.EXIT_WAIT_S:
                info["late_exit"] = True
            gone = clock.sub(_live.GROUP_GONE_S)
            while route.alive(gone) and not gone.spent():
                gone.sleep(NAP_S)
            if not route.alive(gone) and not _live._group_alive(peer.proc.pid):
                checks["disconnect"] = "PASS"

        every_check = (checks["initialized"] == "PASS" and checks["deadline"] == "PASS"
                       and checks["disconnect"] == "PASS")
        return every_check, checks, ""
    finally:
        if not route.stop(clock) and notes is not None:
            notes["left_running"] = True
        if route.proxy_stopped_unseen and info is not None:
            info["unseen_stopped"] = True
