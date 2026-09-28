"""FINDING #14: `python -m sunglasses.mcp --help` must answer the flag, not start the server.

On 0.6.2 `mcp.main()` never read argv. `--help` printed no usage and went straight
into the stdio loop, so an operator asking what the command does got a running
server that read their terminal as JSON-RPC. The same for `--version`.

Every row sends the same stimulus on stdin: one `initialize` request, then EOF. A
server that started answers it on stdout and says so on stderr. The last row is
the stimulus control: with no flag the same input MUST produce both, or the flag
rows could pass against a server that simply never answered.
"""
import json
import os
import subprocess
import sys

import pytest

from sunglasses import __version__

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INITIALIZE = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2024-11-05", "capabilities": {},
    "clientInfo": {"name": "finding-14", "version": "0"}}}) + "\n"
STARTED = "Starting SUNGLASSES MCP server"


def _run(*flags):
    return subprocess.run(
        [sys.executable, "-m", "sunglasses.mcp", *flags],
        input=INITIALIZE, capture_output=True, text=True, cwd=REPO_ROOT, timeout=60,
    )


def _answered_initialize(stdout):
    for line in stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if isinstance(msg, dict) and msg.get("id") == 1 and "result" in msg:
            return True
    return False


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_prints_usage_and_starts_no_server(flag):
    proc = _run(flag)
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-600:])
    assert "usage:" in proc.stdout, proc.stdout[:600]
    assert "--version" in proc.stdout, proc.stdout[:600]
    assert STARTED not in proc.stderr, proc.stderr[:600]
    assert not _answered_initialize(proc.stdout), proc.stdout[:600]


def test_version_prints_the_version_and_starts_no_server():
    proc = _run("--version")
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-600:])
    assert proc.stdout.split() and proc.stdout.split()[-1] == __version__, proc.stdout[:600]
    assert STARTED not in proc.stderr, proc.stderr[:600]
    assert not _answered_initialize(proc.stdout), proc.stdout[:600]


def test_an_unknown_argument_is_still_ignored_and_named():
    """A client config that passes an extra argument started the server before
    the fix. It still does, and stderr now names what was ignored."""
    proc = _run("--transport-hint-from-some-client")
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-600:])
    assert STARTED in proc.stderr, proc.stderr[:600]
    assert "Ignoring arguments: --transport-hint-from-some-client" in proc.stderr, proc.stderr[:600]
    assert _answered_initialize(proc.stdout), proc.stdout[:600]


def test_the_stimulus_shows_a_started_server_when_no_flag_is_given():
    """The control. Without a flag the server starts, says so on stderr and
    answers `initialize`. If this row fails, the rows above prove nothing."""
    proc = _run()
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-600:])
    assert STARTED in proc.stderr, proc.stderr[:600]
    assert _answered_initialize(proc.stdout), proc.stdout[:600]
