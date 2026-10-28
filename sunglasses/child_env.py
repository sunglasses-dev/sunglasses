"""Keeping the report token away from everything a scan starts.

`--report-to` reads its bearer token from `SUNGLASSES_REPORT_TOKEN`. Only the upload
needs it, so a scan runs without it: a scanned file must not be able to read it from the
environment of a program the scan starts (a scan worker, `git`, `ffmpeg`, or a helper program a library starts).

Two things together, because a program can be started from two places:
  * `scan_child_env()`: the environment this package hands to the children it launches
    itself, with the token taken out.
  * `token_withheld()`: for the length of a scan, this process's own environment has no
    token, so a program started from anywhere in the process (a library's included, which
    cannot be given an `env=`) does not inherit one. It is put back for the upload.
"""
import contextlib
import os

_TOKEN_ENV = "SUNGLASSES_REPORT_TOKEN"


def scan_child_env():
    """A copy of this process's environment without the report token."""
    env = dict(os.environ)
    env.pop(_TOKEN_ENV, None)
    return env


@contextlib.contextmanager
def token_withheld():
    """Run a scan with the report token out of this process's environment; restore it after."""
    held = os.environ.pop(_TOKEN_ENV, None)
    try:
        yield
    finally:
        if held is not None:
            os.environ[_TOKEN_ENV] = held
