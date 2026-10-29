"""Keeping the report token out of the environment of what a scan starts.

`--report-to` reads its bearer token from `SUNGLASSES_REPORT_TOKEN`. Only the upload
needs it, so the scan runs without it in the environment: a program the scan starts
(a scan worker, `git`, `ffmpeg`, a helper program a library starts) is not handed a
copy of it through the environment it inherits.

This controls what is inherited. It is not isolation inside this process: the token
stays readable from Python state (`os.environ` is only emptied of it, and the value is
held in a local of this module), and a program that was already running before the scan
began, such as a scan worker started earlier in the same process, keeps whatever it was
started with.

Two things together, because a program can be started from two places:
  * `scan_child_env()`: the environment this package hands to the children it launches
    itself, with the token taken out. It applies with or without `--report-to`.
  * `token_withheld()`: for the length of one scan, this process's own environment has no
    token, so a program started from anywhere in the process (a library's included, which
    cannot be given an `env=`) does not inherit one.

Supported use is one scan at a time in a process, which is what the command line does.
A second `token_withheld()` while one is open is refused before it reads or touches the
token: two overlapping swaps would have the second save "no token" and the first put the
real one back while the second scan was still running. This is a registration, not a lock:
whether a call is let in is decided by who is first on the list when it checks, so a call that
arrives just as the first one ends is let in after it, with the token the first put back.

Putting the token back is safe to repeat, and is tried a second time if the first try raised. A
signal (Ctrl-C) that lands inside the cleanup is held until the cleanup is finished and then
raised again; one that lands on the line that starts the cleanup leaves the second try to do it.
Two signals that land one right after the other can still defeat both.
"""
import contextlib
import os

_TOKEN_ENV = "SUNGLASSES_REPORT_TOKEN"

# Who is inside `token_withheld()`, oldest first. A scan owns the swap while its ticket is first.
# Appending and removing are single list steps. The token is read only after a ticket is first,
# and put back before it is removed, so whoever becomes first next sees the token the last
# owner restored.
_tickets = []

_LEAVE_ATTEMPTS = 8


class ScanOverlap(RuntimeError):
    """A second scan asked to withhold the token while another one still is."""


def scan_child_env():
    """A copy of this process's environment without the report token."""
    env = dict(os.environ)
    env.pop(_TOKEN_ENV, None)
    return env


def _leave(ticket, held):
    """Put the token back (only for the scan that owns the swap) and take `ticket` off the list.

    Safe to call again after it has finished or part way: restoring the same value twice
    changes nothing, and once the ticket is gone a repeat does nothing, so a caller that
    was not sure the first call ran can call it again. An exception that lands inside is
    kept, the cleanup is tried again, and the first one is raised when it is done.
    """
    pending = None
    for _ in range(_LEAVE_ATTEMPTS):
        try:
            if held is not None and _tickets and _tickets[0] is ticket:
                os.environ[_TOKEN_ENV] = held
            if ticket in _tickets:
                _tickets.remove(ticket)
            break
        except BaseException as exc:
            if pending is None:
                pending = exc
    if pending is not None:
        raise pending


@contextlib.contextmanager
def token_withheld():
    """Run a scan with the report token out of this process's environment; put it back after.

    Yields the token that was set when the scan began (or None), so the caller can use it
    for the upload without reading the environment again. The token is read after this
    call is first on the list, never before, so a call that is let in always reads what
    the call before it put back.

    Raises `ScanOverlap`, with the environment untouched, when another scan in this
    process is already withholding the token. A refused call never reads, removes or
    restores the token.
    """
    held = None
    ticket = object()
    try:
        try:
            _tickets.append(ticket)
            if _tickets[0] is not ticket:
                raise ScanOverlap("another scan in this process is already running; "
                                  "--report-to supports one scan at a time per process")
            held = os.environ.get(_TOKEN_ENV)
            os.environ.pop(_TOKEN_ENV, None)
            yield held
        finally:
            _leave(ticket, held)
    except BaseException:
        _leave(ticket, held)
        raise
