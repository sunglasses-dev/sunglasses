"""A child that scans files one request at a time, so the command line can stop a file that never finishes.

`sunglasses scan --file`, `--dir` and `--repo` used to run every rule inside their own
process. A file that made one rule run for minutes held the whole command with no exit
and nothing to read. The proxy is bounded by its worker deadline and the agent hook
by the host's limit; this is the same contract for the command line.

THE ENGINE IS UNTOUCHED. A verdict never depends on the clock: THREAT and CLEAN come
out of the rules exactly as before. Only INCOMPLETE can depend on it, the way
truncation and the proxy deadline already do. A file the scanner could not finish is
reported by name and never called clean.

ONE WARM CHILD PER RUN. `proxy.worker_process` starts one child per scan and cannot
carry a second request, so this is a thin sibling with the same kill shape (the
process group is stopped through `proxy.supervisor`, TERM then KILL). The child loads
the engine once, says so, and then answers requests until its stdin closes. It is
killed and replaced only after a deadline hit or a fault, so an honest run pays for one
extra process and nothing more.

THE CLOCK STARTS AT THE WRITE. Loading the engine is bounded separately (`STARTUP_S`)
and never charged to a file. Delivery of the request is inside the deadline, on its own
thread, so a child that stops reading cannot hold the parent past it.

THE CHILD'S WORDS ARE NEVER ECHOED. Whatever the child prints other than a framed
answer is a fault; a traceback is never shown to the reader.
"""
from __future__ import annotations

import base64
import json
import os
import select
import struct
import subprocess
import sys
import threading
import time

from . import _platform
from . import child_env
from .extractors.dispatch import NonRegularFile, UnreadableFile
from .extractors.member import Member
# Imported here, not when the child is stopped: a scan of the package's own folder must not
# import a module of it once the folder is open (see `cli._scan_tree`).
from .proxy import supervisor

# The default is set from measurement, not guessed: the 2,746-document corpus and the
# numpy tree must trip no file at this value (see the pull request's local evidence).
DEFAULT_FILE_DEADLINE_S = 120.0
# Loading the engine is not the file's time. A child that has not said ready by now is
# killed and the scan stops: a scanner that could not start is an operational failure.
STARTUP_S = 120.0
GRACE_MS = 2000
# One answer holds one file's findings. Past this the child is treated as faulty.
ANSWER_LIMIT = 64 * 1024 * 1024

REASON_DEADLINE = "not finished within the file deadline ({seconds} s)"
REASON_STOPPED = "the scanner process stopped before it finished this file"
# The line a start failure is written on is cut here. It is a message, not a dump.
START_LINE_LIMIT = 300

_HEADER = struct.Struct(">I")


class ScannerCouldNotStart(Exception):
    """The scanner could not be started, as opposed to one that started and could not finish a file.

    The text is one printable line ("ExcType: message" when the engine or the child says why, or
    a description of what happened to the child). A command that has scanned nothing yet stops
    on this and exits 2; once a scanner has answered for a file (with several processes, for a
    file handed out behind the first), a tree scan lists the file it could not hand over as not
    inspected instead. It is never a report about a file.
    """


def one_line(text):
    """`text` as one printable line, cut short, so a start failure can be written to a terminal."""
    text = " ".join(str(text).split())
    text = "".join(ch if ch.isprintable() else ch.encode("unicode_escape").decode("ascii") for ch in text)
    return text if len(text) <= START_LINE_LIMIT else text[:START_LINE_LIMIT - 3] + "..."

# The OSError classes the engine's file reads can raise, by name. The package reads no class
# off a module by a computed name, so the table is spelled out.
_OS_ERRORS = {cls.__name__: cls for cls in (
    OSError, FileNotFoundError, PermissionError, IsADirectoryError, NotADirectoryError,
    FileExistsError, BlockingIOError, InterruptedError, TimeoutError, ChildProcessError,
    ConnectionError, BrokenPipeError)}


def available():
    """The child is stopped by process group, which only exists where the platform helper
    says POSIX pieces are present (the same answer the proxy and `doctor` ask)."""
    return os.name == "posix" and not _platform.posix_pieces_missing()


def default_argv():
    # -B: the child never writes a bytecode cache, wherever the folder being scanned is.
    return [sys.executable, "-B", "-m", "sunglasses.scan_worker"]


# ---------------------------------------------------------------- framing

def _write_all(stream, data):
    """A raw pipe may take part of a write; a half frame is a corrupt frame."""
    view = memoryview(data)
    while view:
        view = view[stream.write(view):]
    stream.flush()


def _put(stream, value):
    body = json.dumps(value).encode("utf-8")
    _write_all(stream, _HEADER.pack(len(body)) + body)


def _read_exact(stream, count):
    chunks = []
    while count:
        chunk = stream.read(count)
        if not chunk:
            raise EOFError
        chunks.append(chunk)
        count -= len(chunk)
    return b"".join(chunks)


def _get(stream):
    (size,) = _HEADER.unpack(_read_exact(stream, _HEADER.size))
    return json.loads(_read_exact(stream, size).decode("utf-8"))


# ------------------------------------------------------------------ child

def _plain(result):
    """Every value a `ScanResult` holds, as JSON. The list is pinned by a test against the class."""
    return {
        "event_id": result.event_id, "decision": result.decision, "findings": result.findings,
        "raw_input": result.raw_input, "normalized_input": result.normalized_input,
        "channel": result.channel, "latency_ms": result.latency_ms, "truncated": result.truncated,
        "bytes_scanned": result.bytes_scanned, "extraction_complete": result.extraction_complete,
        "extraction_warnings": result.extraction_warnings,
        "extraction_sources": result.extraction_sources,
    }


def _answer(engine, request):
    try:
        op = request["op"]
        if op == "member":
            target = Member(base64.b64decode(request["data"]), request["name"])
        elif op == "path":
            target = request["path"]
        else:
            return {"ok": False, "error": "fault"}
        return {"ok": True, "result": _plain(engine.scan_file(target))}
    except NonRegularFile as exc:
        return {"ok": False, "error": "unreadable", "cls": "NonRegularFile",
                "message": str(exc), "path": str(exc.path), "kind": str(exc.kind)}
    except UnreadableFile as exc:
        return {"ok": False, "error": "unreadable", "cls": "UnreadableFile",
                "message": str(exc), "path": str(exc.path), "detail": str(exc.cause)}
    except OSError as exc:
        return {"ok": False, "error": "oserror", "cls": type(exc).__name__,
                "errno": exc.errno}
    except Exception:
        return {"ok": False, "error": "fault"}


def serve(engine, stdin, stdout, *, ready=True):
    """Answer requests until stdin closes. Returns the process exit code."""
    if ready:
        _put(stdout, {"ready": True})
    while True:
        try:
            request = _get(stdin)
        except EOFError:
            return 0
        except (ValueError, struct.error):
            return 1
        reply = _answer(engine, request)
        try:
            _put(stdout, reply)
        except (TypeError, ValueError):
            # Not JSON: a fault, said in the one shape the parent understands.
            _put(stdout, {"ok": False, "error": "fault"})


def main():
    # Frames go out on a private copy of stdout. Descriptor 1 is pointed at the null
    # device, so a stray print from an extractor can never look like an answer.
    channel = os.fdopen(os.dup(1), "wb", buffering=0)
    null = os.open(os.devnull, os.O_WRONLY)
    os.dup2(null, 1)
    os.close(null)
    try:
        from .engine import SunglassesEngine
        engine = SunglassesEngine()
    except Exception as exc:
        # Said in the one shape the parent reads before "ready", so the command can name it.
        try:
            _put(channel, {"ready": False, "error": one_line(f"{type(exc).__name__}: {exc}")})
        except Exception:
            pass
        return 1
    return serve(engine, sys.stdin.buffer, channel)


# ----------------------------------------------------------------- parent

class _Gone(Exception):
    """The child closed its pipe, or said something that is not one answer."""


class _Late(Exception):
    """The clock ran out."""


def _incomplete(reason, channel="file", latency_ms=0.0):
    """A result that says: nothing was concluded about this file. Never clean."""
    from .engine import ScanResult
    result = ScanResult("allow", [], "", "", channel, latency_ms)
    result.extraction_complete = False
    result.extraction_warnings = [reason]
    result.bytes_scanned = 0
    return result


def _unreadable(reply):
    """The exception the engine raised, same class and same words, rebuilt without its cause."""
    if reply.get("cls") == "NonRegularFile":
        exc = NonRegularFile.__new__(NonRegularFile)
        exc.kind = str(reply.get("kind", ""))
    else:
        exc = UnreadableFile.__new__(UnreadableFile)
        exc.cause = OSError(str(reply.get("detail", "")))
    OSError.__init__(exc, str(reply.get("message", "")))
    exc.path = str(reply.get("path", ""))
    return exc


# The largest errno the parent will hand to `os.strerror`; a real errno is a small number.
_ERRNO_LIMIT = 1 << 16


def _error_well_formed(reply):
    """Whether an error reply is one of the three the child writes: its discriminator is the
    boolean `False`, and every field the parent reads is present and of its type."""
    if reply.get("ok") is not False:
        return False
    kind = reply.get("error")
    if kind == "fault":
        return True
    if kind == "unreadable":
        cls = reply.get("cls")
        extra = "kind" if cls == "NonRegularFile" else "detail"
        if cls not in ("NonRegularFile", "UnreadableFile"):
            return False
        return all(isinstance(reply.get(key), str) for key in ("message", "path", extra))
    if kind == "oserror":
        if "errno" not in reply:
            return False
        number = reply["errno"]
        return isinstance(reply.get("cls"), str) and (
            number is None or (_is(number, int) and 0 <= number < _ERRNO_LIMIT))
    return False


def _raised(reply):
    """The exception an error reply reports, rebuilt; None when the reply is not a well-formed
    error the engine could have raised, or cannot be turned into one."""
    try:
        if not _error_well_formed(reply):
            return None
        if reply["error"] == "unreadable":
            return _unreadable(reply)
        if reply["error"] == "oserror":
            cls = _OS_ERRORS.get(reply["cls"], OSError)
            number = reply.get("errno")
            return cls(number, os.strerror(number)) if number is not None else cls()
    except Exception:
        pass
    return None


# What a rebuilt result must hold, and the type of each value. A reply that is not exactly
# this is a faulty child, never a verdict: a missing or mistyped coverage flag would otherwise
# read as "complete" and a result with no findings as clean.
_PLAIN_TYPES = (
    ("event_id", str), ("decision", str), ("findings", list), ("raw_input", str),
    ("normalized_input", str), ("channel", str), ("latency_ms", (int, float)),
    ("truncated", bool), ("bytes_scanned", int), ("extraction_complete", bool),
    ("extraction_warnings", list), ("extraction_sources", list),
)


def _is(value, kind):
    # bool is an int in Python; a flag or a count may not stand in for the other.
    if kind is bool:
        return value is True or value is False
    if isinstance(value, bool):
        return False
    return isinstance(value, kind)


# A finding must hold what every writer reads: these four as text, and the optional ones, when
# present, as the type the writers expect.
_FINDING_REQUIRED = ("id", "name", "severity", "category")
_FINDING_TEXT = ("matched_text", "description")
_DECISIONS = ("allow", "block", "quarantine", "allow_redacted")


def _finding_well_formed(finding):
    if not isinstance(finding, dict):
        return False
    if not all(isinstance(finding.get(key), str) for key in _FINDING_REQUIRED):
        return False
    if not all(isinstance(finding.get(key, ""), str) for key in _FINDING_TEXT):
        return False
    also = finding.get("also_matched", [])
    return isinstance(also, list) and all(isinstance(item, str) for item in also)


def _well_formed(plain):
    if not all(_is(plain.get(key), kind) for key, kind in _PLAIN_TYPES):
        return False
    return (plain["decision"] in _DECISIONS
            and all(_finding_well_formed(f) for f in plain["findings"])
            and all(isinstance(w, str) for w in plain["extraction_warnings"])
            and all(isinstance(label, str) for label in plain["extraction_sources"])
            and plain["bytes_scanned"] >= 0)


def _rebuild(plain):
    from .engine import ScanResult
    result = ScanResult(plain["decision"], plain["findings"], plain["raw_input"],
                        plain["normalized_input"], plain["channel"], plain["latency_ms"])
    result.event_id = plain["event_id"]
    result.truncated = plain["truncated"]
    result.bytes_scanned = plain["bytes_scanned"]
    result.extraction_complete = plain["extraction_complete"]
    result.extraction_warnings = plain["extraction_warnings"]
    result.extraction_sources = plain["extraction_sources"]
    return result


class ScanWorker:
    """`engine.scan_file`, through a child that can be stopped.

    `scan_file(target)` returns what the engine returns, raises what the engine raises
    (`UnreadableFile`, `OSError`), and returns an INCOMPLETE result when the file was
    not finished in `deadline_s` or the child failed after it was ready. It never returns
    a verdict for a file the child did not answer for.

    A child that never becomes ready is a different thing: the scanner could not start, no
    file was read, and `ScannerCouldNotStart` is raised (again on every later call).
    """

    def __init__(self, deadline_s, *, argv=None, startup_s=None, grace_ms=GRACE_MS,
                 answer_limit=ANSWER_LIMIT):
        self.deadline_s = float(deadline_s)
        self.argv = argv or default_argv()
        self.startup_s = STARTUP_S if startup_s is None else startup_s
        self.grace_ms = grace_ms
        self.answer_limit = answer_limit
        self._child = None
        self._ready = False
        self._broken = False
        self._start_failure = ""
        self._aborted = False
        self._lock = threading.Lock()
        self._gate = threading.Lock()     # guards `_child` and `_aborted`; never held while waiting

    # -- lifecycle

    def start(self):
        """Begin loading the engine now, so the load overlaps the caller's own work.

        A child that cannot be started (no such program, no process left to give) is the
        same answer as one that never says ready: the first file asked for raises
        `ScannerCouldNotStart`, and nothing is called clean.
        """
        with self._gate:
            if self._child is None and not self._broken and not self._aborted:
                try:
                    self._child = subprocess.Popen(
                        self.argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, bufsize=0, start_new_session=True,
                        env=child_env.scan_child_env())
                except (OSError, ValueError, subprocess.SubprocessError) as exc:
                    self._child = None
                    self._broken = True
                    self._start_failure = one_line(f"{type(exc).__name__}: {exc}")

    @property
    def pid(self):
        return None if self._child is None else self._child.pid

    def _stop(self):
        with self._gate:
            child, self._child = self._child, None
        self._ready = False
        if child is None:
            return
        supervisor.stop_group(child.pid, grace_ms=self.grace_ms, handle=child)
        for stream in (child.stdin, child.stdout):
            try:
                stream.close()
            except (OSError, ValueError):
                pass

    def close(self):
        with self._lock:
            child = self._child
            if child is not None:
                try:
                    child.stdin.close()      # EOF is the polite way out
                    child.wait(timeout=1)
                except (OSError, ValueError, subprocess.TimeoutExpired):
                    pass
            self._stop()

    def abort(self):
        """Stop the child's process group now, from another thread, without waiting for `scan_file`.

        The thread reading from the child sees its stream end and reports the file as not read;
        `close` then releases what is left. An aborted worker never starts a child again: a file
        handed to it afterwards is reported as not read, at once, so a read that was only
        being prepared when this ran cannot bring a new child back.
        """
        with self._gate:
            self._aborted = True
            child = self._child
        if child is not None:
            supervisor.stop_group(child.pid, grace_ms=self.grace_ms, handle=child)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    # -- one request

    def _receive(self, deadline):
        fd = self._child.stdout.fileno()
        buffer = bytearray()
        size = None
        while size is None or len(buffer) < _HEADER.size + size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise _Late()
            readable, _, _ = select.select([fd], [], [], remaining)
            if not readable:
                raise _Late()
            chunk = os.read(fd, 65536)
            if not chunk:
                raise _Gone()
            buffer += chunk
            if size is None and len(buffer) >= _HEADER.size:
                (size,) = _HEADER.unpack(bytes(buffer[:_HEADER.size]))
                if size > self.answer_limit:
                    raise _Gone()
        if len(buffer) != _HEADER.size + size:
            raise _Gone()                    # a second answer is not an answer
        try:
            value = json.loads(bytes(buffer[_HEADER.size:]).decode("utf-8"))
        except (ValueError, RecursionError):
            raise _Gone()               # not JSON, or nested past what the decoder will take
        if not isinstance(value, dict):
            raise _Gone()
        return value

    def _fail_to_start(self, reason):
        self._broken = True
        self._start_failure = reason
        raise ScannerCouldNotStart(reason)

    def _await_ready(self):
        """True once the child has said ready, False if the worker was aborted, else raises.

        Everything that stops the child before it is ready, whether it died, ran out of time
        or said why it cannot load the engine, is `ScannerCouldNotStart`.
        """
        if self._broken:
            raise ScannerCouldNotStart(self._start_failure)
        if self._child is None:
            self.start()
            if self._child is None:
                if self._aborted:
                    return False
                raise ScannerCouldNotStart(self._start_failure)
        if self._ready:
            return True
        try:
            value = self._receive(time.monotonic() + self.startup_s)
        except (_Late, _Gone) as exc:
            self._stop()
            self._broken = True
            if self._aborted:
                return False
            self._fail_to_start(
                f"the scanner process did not say ready within {self.startup_s:g} s"
                if isinstance(exc, _Late) else "the scanner process ended before it was ready")
        if value.get("ready") is not True:
            self._stop()
            self._broken = True
            if self._aborted:
                return False
            said = value.get("error") if value.get("ready") is False else None
            self._fail_to_start(one_line(said) if isinstance(said, str) and said.strip()
                                else "the scanner process did not say ready")
        self._ready = True
        return True

    def scan_file(self, target):
        request = self._request(target)
        with self._lock:
            if self._aborted:
                return _incomplete(REASON_STOPPED)
            if not self._await_ready():
                return _incomplete(REASON_STOPPED)
            if self._aborted:
                self._stop()
                return _incomplete(REASON_STOPPED)
            child = self._child
            body = json.dumps(request).encode("utf-8")
            frame = _HEADER.pack(len(body)) + body
            deadline = time.monotonic() + self.deadline_s

            def deliver():
                try:
                    _write_all(child.stdin, frame)
                except (OSError, ValueError):
                    pass

            writer = threading.Thread(target=deliver, daemon=True)
            writer.start()
            try:
                reply = self._receive(deadline)
            except _Late:
                self._stop()
                writer.join(timeout=1)
                return _incomplete(
                    REASON_DEADLINE.format(seconds=f"{self.deadline_s:g}"),
                    latency_ms=self.deadline_s * 1000.0)
            except _Gone:
                self._stop()
                writer.join(timeout=1)
                return _incomplete(REASON_STOPPED)
            writer.join(timeout=1)
            return self._outcome(reply)

    @staticmethod
    def _request(target):
        if isinstance(target, Member):
            return {"op": "member", "name": target.name,
                    "data": base64.b64encode(bytes(target)).decode("ascii")}
        return {"op": "path", "path": os.fspath(target)}

    def _outcome(self, reply):
        """The engine's answer, or what it raised, or INCOMPLETE. Called with the lock held.

        Anything that is not exactly one of the child's three answers is a faulty child: it is
        stopped (the next file gets a fresh one) and this file is reported as not finished.
        """
        if reply.get("ok") is True:
            plain = reply.get("result")
            if isinstance(plain, dict) and _well_formed(plain):
                result = _rebuild(plain)
                try:
                    result.to_dict()     # what every writer calls; a result it cannot read is a fault
                except Exception:
                    pass
                else:
                    return result
        else:
            raised = _raised(reply)
            if raised is not None:
                raise raised
        self._stop()
        return _incomplete(REASON_STOPPED)


if __name__ == "__main__":
    sys.exit(main())
