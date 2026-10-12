"""`sunglasses mcp` and the `sunglasses-mcp` console script start the same MCP server.

Directories that run a listed Python package start it by the package's own command, so
the server needs a command of its own: before this the only way in was
`python -m sunglasses.mcp`, and `sunglasses mcp` fell through to argparse as an
unknown command.

Every row sends the same stimulus: initialize, the initialized notification, then
tools/list, then EOF. A real server answers both requests on stdout with the three
tool names. The `--help` / `--version` rows prove the flags are answered, not forwarded
into a running server.
"""
import json
import os
import re
import subprocess
import sys

import pytest

from sunglasses import __version__

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = {"scan_text", "scan_file", "scanner_info"}
STIMULUS = "".join(json.dumps(m) + "\n" for m in (
    {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2024-11-05", "capabilities": {},
        "clientInfo": {"name": "entry-points", "version": "0"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
))
STARTED = "Starting SUNGLASSES MCP server"


def _env():
    return dict(os.environ, PYTHONPATH=REPO_ROOT)


def _run(argv, stdin=STIMULUS):
    return subprocess.run(argv, input=stdin, capture_output=True, text=True,
                          cwd=REPO_ROOT, env=_env(), timeout=60)


def _tool_names(stdout):
    for line in stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            continue
        if isinstance(msg, dict) and msg.get("id") == 2 and "result" in msg:
            return {t["name"] for t in msg["result"]["tools"]}
    return None


def _console_script_target(name):
    setup = open(os.path.join(REPO_ROOT, "setup.py"), encoding="utf-8").read()
    m = re.search(r'"%s=([\w.]+):(\w+)"' % re.escape(name), setup)
    assert m, "setup.py declares no %s console script" % name
    return m.group(1), m.group(2)


CLI_ROUTE = [sys.executable, "-c", "import sys; from sunglasses.cli import main; main()", "mcp"]


def test_subcommand_starts_the_server_and_lists_the_three_tools():
    proc = _run(CLI_ROUTE)
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-600:])
    assert STARTED in proc.stderr, proc.stderr[:600]
    assert _tool_names(proc.stdout) == TOOLS, proc.stdout[:600]


def test_console_script_target_starts_the_server_and_lists_the_three_tools():
    module, func = _console_script_target("sunglasses-mcp")
    code = "import sys; from %s import %s as m; m()" % (module, func)
    proc = _run([sys.executable, "-c", code])
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-600:])
    assert STARTED in proc.stderr, proc.stderr[:600]
    assert _tool_names(proc.stdout) == TOOLS, proc.stdout[:600]


def test_both_routes_run_the_same_function_as_python_dash_m():
    module, func = _console_script_target("sunglasses-mcp")
    assert (module, func) == ("sunglasses.mcp", "main")
    via_m = _run([sys.executable, "-m", "sunglasses.mcp"])
    via_cli = _run(CLI_ROUTE)
    assert _tool_names(via_m.stdout) == _tool_names(via_cli.stdout) == TOOLS


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_subcommand_help_prints_usage_and_starts_no_server(flag):
    proc = _run(CLI_ROUTE + [flag])
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-600:])
    assert "usage:" in proc.stdout, proc.stdout[:600]
    assert STARTED not in proc.stderr, proc.stderr[:600]
    assert _tool_names(proc.stdout) is None, proc.stdout[:600]


def test_subcommand_version_prints_the_version_and_starts_no_server():
    proc = _run(CLI_ROUTE + ["--version"])
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-600:])
    assert proc.stdout.split() and proc.stdout.split()[-1] == __version__, proc.stdout[:600]
    assert STARTED not in proc.stderr, proc.stderr[:600]


def test_top_level_help_lists_the_mcp_subcommand():
    proc = _run([sys.executable, "-c", "import sys; from sunglasses.cli import main; main()", "--help"])
    assert proc.returncode == 0, proc.stderr[-600:]
    assert re.search(r"^\s+mcp\s", proc.stdout, re.M), proc.stdout[:1500]
