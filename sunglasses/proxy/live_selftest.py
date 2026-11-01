"""The doctor's live self-test: spawn the installed proxy against the bundled echo server.

`doctor.default_self_test` calls `run()` here. It starts the artifact that is
running right now (`sys.executable -m sunglasses.proxy`) in front of
`sunglasses.proxy.echo_server`, in a private folder, and reports the five named
checks plus the three controls the verdict logic in `doctor` already requires.

What it proves, and what it cannot:

* It runs BEFORE any approval exists and never writes one (a stored approval is
  a human at a terminal). So it exercises the withheld path and the request
  direction of the forward path, not the content scan of an approved route.
* `s1_forward_byte_equal` is defined on the request side: the bytes the echo
  server received equal the bytes the client wrote. The proxy re-serialises its
  replies, so a reply is value-equal, not byte-equal.
* The user's configured servers are never started here.

The private world: a 0700 temp folder, HOME pointed into it, `--state-root`
inside it, an environment of four constants (the system default PATH, that
folder as HOME, the package's own location, and no bytecode writes; nothing is
read from the user's environment), every process in its own group. The groups
are killed and the folder removed when the run ends normally, on an exception,
and on SIGTERM, SIGHUP or SIGINT. SIGKILL cannot be caught, so it leaves the folder.
"""
from __future__ import annotations

import json
import os
import queue
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

# The doctor's own bound is the contract's figure; it is imported, not copied.
from .doctor import DEADLINE_BOUND_MS
from .echo_server import handle as _echo_handle

# A spawn that has not answered `initialize` by now did not come up.
FIRST_REPLY_S = 20.0
# The whole self-test, controls included.
OVERALL_S = 60.0
# A control is rigged to fail fast, so it does not get the long first-reply wait.
CONTROL_FIRST_REPLY_S = 5.0
# How long one later frame may take before the wait is abandoned. The verdict on
# speed is `DEADLINE_BOUND_MS`; this only stops a silent peer hanging the run.
FRAME_WAIT_S = 5.0
EXIT_WAIT_S = 5.0
GROUP_GONE_S = 2.0
# Teardown is bounded too: a reader thread that a surviving descendant keeps
# blocked is abandoned after this, never waited on.
PUMP_JOIN_S = 2.0

ECHO_NAME = "sunglasses-echo"
WITHHELD_CODE = -32070
WITHHELD_MESSAGE = "SUNGLASSES_WITHHELD"

_INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2024-11-05", "capabilities": {},
                    "clientInfo": {"name": "sunglasses-doctor", "version": "1"}}}
_INITIALIZED = {"jsonrpc": "2.0", "method": "notifications/initialized"}
_PING = {"jsonrpc": "2.0", "id": 4, "method": "ping"}
_LIST = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
_CALL = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
         "params": {"name": "echo", "arguments": {"text": "doctor"}}}

# A peer that withholds everything: answers every request with the withheld
# error and never a result. The control for "a checker that always says no".
_DENY_STUB = (
    "import json,sys\n"
    "for raw in sys.stdin:\n"
    "    try:\n"
    "        m=json.loads(raw)\n"
    "    except ValueError:\n"
    "        continue\n"
    "    if isinstance(m,dict) and 'id' in m:\n"
    "        sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':m['id'],'error':"
    "{'code':-32070,'message':'SUNGLASSES_WITHHELD'}})+'\\n')\n"
    "        sys.stdout.flush()\n")


def _frame(message) -> bytes:
    return (json.dumps(message, separators=(",", ":")) + "\n").encode("utf-8")


class _Budget:
    """One wall-clock allowance for the whole run."""

    def __init__(self, seconds):
        self._end = time.monotonic() + seconds

    def left(self) -> float:
        return max(0.0, self._end - time.monotonic())

    def spent(self) -> bool:
        return self.left() <= 0.0


class _CouldNotStart(Exception):
    """The operating system refused to start a process or make the private folder."""


class _Terminated(BaseException):
    """SIGTERM, SIGHUP or SIGINT arrived. A BaseException so no `except Exception` swallows the unwind."""


class _Peer:
    """A spawned process in its own group, read through a queue so every wait has a limit."""

    def __init__(self, argv, env, cwd):
        self.proc = None
        self._reader = None
        self._lines = queue.Queue()
        # Everything from the spawn on is inside this try: a failure after the
        # process exists (the reader thread cannot start, a signal lands) kills
        # its group before the error leaves, so the caller never has to know a
        # half-built peer was ever there.
        try:
            self.proc = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, env=env, cwd=cwd, start_new_session=True)
            self._reader = threading.Thread(target=self._pump, daemon=True)
            self._reader.start()
        except BaseException as exc:
            self.kill()
            if isinstance(exc, (OSError, RuntimeError)):
                raise _CouldNotStart(type(exc).__name__) from None
            raise

    def _pump(self):
        try:
            for raw in self.proc.stdout:
                self._lines.put(raw)
        except (OSError, ValueError):
            pass
        self._lines.put(None)

    def send(self, message) -> bytes:
        """The bytes written, or b"" when the pipe is already closed."""
        data = _frame(message)
        try:
            self.proc.stdin.write(data)
            self.proc.stdin.flush()
        except (OSError, ValueError):
            return b""
        return data

    def reply(self, request_id, limit_s):
        """(message, elapsed_ms) for the reply with this id; (None, elapsed_ms) on EOF or timeout."""
        started = time.monotonic()
        end = started + limit_s
        while True:
            wait = end - time.monotonic()
            if wait <= 0:
                return None, _ms(started)
            try:
                raw = self._lines.get(timeout=wait)
            except queue.Empty:
                return None, _ms(started)
            if raw is None:
                return None, _ms(started)
            try:
                message = json.loads(raw)
            except ValueError:
                continue
            if isinstance(message, dict) and message.get("id") == request_id:
                return message, _ms(started)

    def close_stdin(self):
        try:
            self.proc.stdin.close()
        except (OSError, ValueError):
            pass

    def wait(self, limit_s):
        try:
            return self.proc.wait(timeout=limit_s)
        except subprocess.TimeoutExpired:
            return None

    def kill(self):
        if self.proc is None:
            return
        # The group is killed whether or not its leader is still alive: a leader
        # that exits first can leave a child holding our pipe, and that child is
        # the one that would hang the reader and the close below.
        _kill_group(self.proc.pid)
        try:
            self.proc.kill()
        except OSError:
            pass
        self.wait(2.0)
        self.close_stdin()
        reader_started = self._reader is not None and self._reader.ident is not None
        if reader_started:
            self._reader.join(PUMP_JOIN_S)
        if not reader_started or not self._reader.is_alive():
            try:
                self.proc.stdout.close()
            except (OSError, ValueError):
                pass


def _ms(started) -> int:
    return int((time.monotonic() - started) * 1000)


def _kill_group(pgid):
    """SIGKILL a group we started. Never our own, never a nonsense id."""
    if not isinstance(pgid, int) or pgid <= 1 or pgid == os.getpgid(0):
        return
    try:
        os.killpg(pgid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        pass


def _group_alive(pgid) -> bool:
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _read(path) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError:
        return b""


def _read_pgid(path):
    try:
        value = json.loads(_read(path).decode("utf-8")).get("pgid")
    except (ValueError, AttributeError, UnicodeDecodeError):
        return None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _is_withheld(message) -> bool:
    """The exact shape of a withheld reply, and not a result."""
    if not isinstance(message, dict) or "result" in message:
        return False
    error = message.get("error")
    if not isinstance(error, dict):
        return False
    data = error.get("data")
    return (error.get("code") == WITHHELD_CODE
            and error.get("message") == WITHHELD_MESSAGE
            and isinstance(data, dict)
            and data.get("reason_code") == "APPROVAL_REQUIRED"
            and data.get("rule") == "S4"
            and data.get("status") == "not_run"
            and bool(data.get("server_id"))
            and bool(data.get("snapshot_sha256")))


def _only_proxy_listing(received, sent) -> bool:
    """True when `received` is `sent` plus nothing but the proxy's own tool listing.

    Before an approval the proxy asks the server for its tool list itself, to
    snapshot it, under an id of its own (`sg-...`). That line is the proxy
    talking, not the client's `tools/list` or `tools/call` getting through, so it
    is the one thing allowed to follow the forwarded bytes.
    """
    if not received.startswith(sent):
        return False
    for raw in received[len(sent):].splitlines():
        try:
            message = json.loads(raw)
        except ValueError:
            return False
        if not (isinstance(message, dict) and message.get("method") == "tools/list"
                and isinstance(message.get("id"), str) and message["id"].startswith("sg-")):
            return False
    return True


_INIT_EXPECTED = _echo_handle(_INIT)
_PING_EXPECTED = {"jsonrpc": "2.0", "id": 4, "result": {}}


def _battery(argv, env, tmp, ingress, proc_file, first_reply_s, budget):
    """Run the five checks against one peer.

    Returns (came_up, checks, deadline_ms). `came_up` is False when the peer never
    answered `initialize`: nothing after that point was tried, so there are no checks.
    """
    peer = _Peer(argv, env, tmp)
    try:
        sent = peer.send(_INIT)
        init, _ = peer.reply(1, min(first_reply_s, budget.left()))
        if init is None:
            return False, {}, 0

        checks = {name: "FAIL" for name in
                  ("initialized", "s1_forward_byte_equal", "s2_block_schema",
                   "deadline", "disconnect")}
        # The echo server's own answer to this exact request, value for value.
        if init == _INIT_EXPECTED:
            checks["initialized"] = "PASS"

        # From the second frame the clock is the doctor's: it starts before that
        # frame is written and stops when the last reply is read, so writing,
        # flushing and every wait in between are charged. Start-up is not: the
        # first reply carries it.
        started = time.monotonic()
        sent += peer.send(_INITIALIZED)
        pong = None
        if peer.send(_PING):
            pong, _ = peer.reply(4, min(FRAME_WAIT_S, budget.left()))
        sent += _frame(_PING)
        forwarded = _read(ingress)
        if forwarded == sent:
            checks["s1_forward_byte_equal"] = "PASS"

        listed = called = None
        if peer.send(_LIST):
            listed, _ = peer.reply(2, min(FRAME_WAIT_S, budget.left()))
        if peer.send(_CALL):
            called, _ = peer.reply(3, min(FRAME_WAIT_S, budget.left()))
        elapsed_ms = _ms(started)
        if _is_withheld(listed) and _is_withheld(called) and _only_proxy_listing(_read(ingress), sent):
            checks["s2_block_schema"] = "PASS"

        if pong == _PING_EXPECTED and listed is not None and called is not None \
                and elapsed_ms <= DEADLINE_BOUND_MS:
            checks["deadline"] = "PASS"

        peer.close_stdin()
        exited = peer.wait(min(EXIT_WAIT_S, budget.left()))
        echo_group = _read_pgid(proc_file)
        if exited == 0 and echo_group is not None:
            gone_by = time.monotonic() + min(GROUP_GONE_S, budget.left())
            while (_group_alive(echo_group) or _group_alive(peer.proc.pid)) \
                    and time.monotonic() < gone_by:
                time.sleep(0.05)
            if not _group_alive(echo_group) and not _group_alive(peer.proc.pid):
                checks["disconnect"] = "PASS"
        return True, checks, elapsed_ms
    finally:
        echo_group = _read_pgid(proc_file)
        peer.kill()
        if echo_group is not None and echo_group != peer.proc.pid:
            _kill_group(echo_group)


def _echo_argv(ingress, proc_file):
    return [sys.executable, "-m", "sunglasses.proxy.echo_server",
            "--ingress", ingress, "--proc", proc_file]


def _env(tmp):
    """The system default PATH, a HOME inside the private folder, and where this package lives.

    The package location is the one addition to a bare environment: it makes the
    spawned proxy the same artifact the doctor is running from, rather than
    whichever `sunglasses` an interpreter finds first.
    """
    package_parent = os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))
    return {"PATH": os.defpath, "HOME": tmp,
            "PYTHONPATH": package_parent, "PYTHONDONTWRITEBYTECODE": "1"}


def _supported() -> bool:
    from .._platform import posix_pieces_missing
    if posix_pieces_missing():
        return False
    try:
        os.killpg
        os.getpgid
    except AttributeError:
        return False
    return True


def _on_terminate(signum, frame):
    raise _Terminated(signum)


def run():
    """(ok, controls, checks, info) for `doctor.run`, or `(False, {})` where this cannot run.

    `info["deadline_ms"]` is the time the doctor measured from the second frame to the last
    reply (0 when none was); `info["detail"]` names why the instrument did not come up, when
    it did not; `info["not_run_controls"]` lists a control whose process could not be started
    (that control is absent from `controls`: it did not run, so it neither failed nor passed).
    """
    from .doctor import SELF_TEST_COULD_NOT_START
    if not _supported():
        return False, {}
    # SIGTERM, SIGHUP and SIGINT (Ctrl-C) unwind through the `finally` below
    # instead of ending the process with children and the private folder in place.
    previous = {}
    if threading.current_thread() is threading.main_thread():
        # SIGHUP does not exist on every platform; this self-test only runs where
        # process groups do, which is POSIX, where all three are defined.
        for number in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
            previous[number] = signal.signal(number, _on_terminate)
    try:
        return _run()
    except _CouldNotStart:
        return False, {}, {}, {"detail": SELF_TEST_COULD_NOT_START, "deadline_ms": 0}
    except _Terminated as stop:
        # The cleanup has run; leave the way the signal asked, and say so once for Ctrl-C.
        if int(stop.args[0]) == signal.SIGINT:
            print("sunglasses doctor: interrupted; the self-test's processes and private folder "
                  "were cleaned up.", file=sys.stderr)
        raise SystemExit(128 + int(stop.args[0]))
    finally:
        for number, handler in previous.items():
            signal.signal(number, handler)


def _run():
    from .doctor import (SELF_TEST_COULD_NOT_START, SELF_TEST_NO_INITIALIZE,
                         SELF_TEST_OUT_OF_TIME)
    budget = _Budget(OVERALL_S)
    try:
        tmp = tempfile.mkdtemp(suffix="-sunglasses-doctor")
    except OSError as exc:
        raise _CouldNotStart(type(exc).__name__) from None
    try:
        os.chmod(tmp, 0o700)
        env = _env(tmp)

        def paths(name):
            return (os.path.join(tmp, name + ".ingress"), os.path.join(tmp, name + ".proc"))

        ingress, proc_file = paths("live")
        proxy = [sys.executable, "-m", "sunglasses.proxy",
                 "--state-root", os.path.join(tmp, "state"), "--"] + _echo_argv(ingress, proc_file)
        came_up, checks, deadline_ms = _battery(proxy, env, tmp, ingress, proc_file,
                                                FIRST_REPLY_S, budget)
        if not came_up:
            detail = SELF_TEST_OUT_OF_TIME if budget.spent() else SELF_TEST_NO_INITIALIZE
            return False, {}, {}, {"detail": detail, "deadline_ms": 0}

        # Each control is the same battery against a peer that cannot be right:
        # one that always allows, one that always denies, one that never started.
        # A control must FAIL; one that passes voids the run in `judge_self_test`.
        controls = {}
        not_run = []
        rigged = (
            ("constant_allow", _echo_argv, paths("allow")),
            ("constant_deny", lambda *_: [sys.executable, "-c", _DENY_STUB], paths("deny")),
            ("skipped_invocation", lambda *_: [sys.executable, "-c", "pass"], paths("skip")),
        )
        for name, build, (c_ingress, c_proc) in rigged:
            try:
                _, control_checks, _ = _battery(build(c_ingress, c_proc), env, tmp, c_ingress,
                                                c_proc, CONTROL_FIRST_REPLY_S, budget)
            except _CouldNotStart:
                # A control that cannot start has not been caught, so it has not
                # failed: it is not run, and a run with a control missing proves
                # nothing either way.
                not_run.append(name)
                continue
            passed = len(control_checks) == 5 and all(v == "PASS" for v in control_checks.values())
            controls[name] = "PASS" if passed else "FAIL"

        if not_run:
            return False, controls, checks, {"detail": SELF_TEST_COULD_NOT_START,
                                             "deadline_ms": deadline_ms,
                                             "not_run_controls": not_run}
        ok = all(v == "PASS" for v in checks.values())
        if budget.spent() and ok:
            # Out of time with nothing red: the run is unproven, not passed.
            return False, {}, {}, {"detail": SELF_TEST_OUT_OF_TIME, "deadline_ms": 0}
        # A check that already failed stays failed, whatever the clock says.
        return ok, controls, checks, {"deadline_ms": deadline_ms}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
