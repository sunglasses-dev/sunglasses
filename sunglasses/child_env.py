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
A second `token_withheld()` while one is open is refused before it touches anything: two
overlapping swaps would have the second save "no token" and the first put the real one
back while the second scan was still running.
"""
import contextlib
import os

_TOKEN_ENV = "SUNGLASSES_REPORT_TOKEN"

# Who is inside `token_withheld()`, oldest first. A scan owns the swap while its ticket is first.
# A list append and a list remove are single steps, so a scan is never half-registered: an
# interrupt leaves it in the list (and the `finally` takes it out) or not in it at all.
_tickets = []


class ScanOverlap(RuntimeError):
    """A second scan asked to withhold the token while another one still is."""


def scan_child_env():
    """A copy of this process's environment without the report token."""
    env = dict(os.environ)
    env.pop(_TOKEN_ENV, None)
    return env


@contextlib.contextmanager
def token_withheld():
    """Run a scan with the report token out of this process's environment; put it back after.

    Yields the token that was set when the scan began (or None), so the caller can use it
    for the upload without reading the environment again. The value is read before
    anything is removed, and everything that changes state sits inside the protected
    region, so an interrupt at any point between the call and the scan body leaves the
    token set or puts it back, and leaves no scan registered.

    Raises `ScanOverlap`, with the environment untouched, when another scan in this
    process is already withholding the token.
    """
    held = os.environ.get(_TOKEN_ENV)
    ticket = object()
    try:
        _tickets.append(ticket)
        if _tickets[0] is not ticket:
            raise ScanOverlap("another scan in this process is already running; "
                              "--report-to supports one scan at a time per process")
        os.environ.pop(_TOKEN_ENV, None)
        yield held
    finally:
        try:
            if held is not None and _tickets and _tickets[0] is ticket:
                os.environ[_TOKEN_ENV] = held
        finally:
            if ticket in _tickets:
                _tickets.remove(ticket)
