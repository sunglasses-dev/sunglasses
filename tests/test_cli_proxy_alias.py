"""`sunglasses proxy …`, the product surface for 0.6.0 beta.

T9 approved this on 2026-09-14 as its own commit and as the one change outside
`sunglasses/proxy/`. It is an alias and nothing more: everything it does lives
in `sunglasses.proxy.commands`, so the CLI gains a door and no behaviour.

The door is opened BEFORE argparse rather than as a subparser. `sunglasses
proxy -- npx server` carries a bare separator and a server's own flags, and a
subparser would have to be told to keep its hands off all of it. Intercepting
the word `proxy` and handing the rest over whole is smaller, and it means the
server's command line reaches the mediator exactly as the user wrote it.
"""
import json
import os
import subprocess
import sys

import pytest


def _cli(*args, **kw):
    return subprocess.run([sys.executable, "-m", "sunglasses.cli", *args],
                          capture_output=True, timeout=120, **kw)


def _module(*args, **kw):
    return subprocess.run([sys.executable, "-m", "sunglasses.proxy", *args],
                          capture_output=True, timeout=120, **kw)


def test_the_alias_and_the_module_give_the_same_report(tmp_path):
    """Same command, same exit code, same three lines. If they ever differ,
    one of them is the real product and nobody knows which."""
    config = tmp_path / ".mcp.json"
    config.write_text(json.dumps({"mcpServers": {"fs": {"command": "npx"}}}))
    viaalias = _cli("proxy", "doctor", "--config", str(config))
    viamodule = _module("doctor", "--config", str(config))
    assert viaalias.returncode == viamodule.returncode
    assert viaalias.stdout == viamodule.stdout


def test_the_alias_passes_the_separator_and_the_server_argv_through(tmp_path):
    """The whole reason it is not a subparser. Everything after `--` is the
    server's command line and must arrive unedited."""
    ingress = tmp_path / "in.log"
    frame = (json.dumps({"jsonrpc": "2.0", "id": 5, "method": "ping"})
             + "\n").encode()
    proc = subprocess.run(
        [sys.executable, "-m", "sunglasses.cli", "proxy",
         "--state-root", str(tmp_path / "state"), "--",
         sys.executable, "-m", "sunglasses.proxy.echo_server",
         "--ingress", str(ingress)],
        input=frame, capture_output=True, timeout=120)
    assert proc.returncode == 0, proc.stderr[:400]
    assert frame in ingress.read_bytes()
    assert json.loads(proc.stdout.splitlines()[0])["id"] == 5


def test_the_alias_with_nothing_after_it_is_a_usage_error():
    proc = _cli("proxy")
    assert proc.returncode == 2
    assert b"usage" in proc.stderr.lower()


def test_the_rest_of_the_cli_still_works():
    """The positive control for a change that reaches into the shared entry
    point. Adding a door must not move the building."""
    proc = _cli("--help")
    assert proc.returncode == 0
    assert b"scan" in proc.stdout
