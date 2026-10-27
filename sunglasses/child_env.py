"""The environment a scan hands to the programs it starts (the scan worker, `git`).

`--report-to` reads its bearer token from `SUNGLASSES_REPORT_TOKEN`. Only the upload
needs it, so nothing the scan starts is given it: a scanned repository must not be able
to read it from a child's environment.
"""
import os

_TOKEN_ENV = "SUNGLASSES_REPORT_TOKEN"


def scan_child_env():
    """A copy of this process's environment without the report token."""
    env = dict(os.environ)
    env.pop(_TOKEN_ENV, None)
    return env
