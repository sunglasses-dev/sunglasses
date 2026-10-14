"""`sunglasses mcp` and the `sunglasses-mcp` console script start the same MCP server.

Directories that run a listed Python package start it by the package's own command, so
the server needs a command of its own: before this the only way in was
`python -m sunglasses.mcp`, and `sunglasses mcp` fell through to argparse as an
unknown command.

Every row sends the same stimulus: initialize, the initialized notification, then
tools/list, then EOF. A real server answers both requests on stdout with the three
tool names, and every stdout line must be a success reply. The `--help` / `--version` rows prove the flags are answered, not forwarded
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


def _env(extra_path=None):
    return dict(os.environ, PYTHONPATH=os.pathsep.join(p for p in (REPO_ROOT, extra_path) if p))


def _run(argv, stdin=STIMULUS, extra_path=None):
    return subprocess.run(argv, input=stdin, capture_output=True, text=True,
                          cwd=REPO_ROOT, env=_env(extra_path), timeout=60)


def _is_success_reply(msg):
    """Exactly the envelope a successful reply has: jsonrpc 2.0, an int or str id, an object result, nothing else.

    Narrow on purpose. The stimulus sends two requests and the server must answer each with a
    success reply, so a request, a notification, an error reply, a null or empty `error`, a
    boolean id or an extra member all count as something that should not be on the wire.
    """
    return (isinstance(msg, dict) and set(msg) == {"jsonrpc", "id", "result"}
            and msg["jsonrpc"] == "2.0"
            and isinstance(msg["id"], (int, str)) and not isinstance(msg["id"], bool)
            and isinstance(msg["result"], dict))


def _messages(stdout):
    """Every stdout line must have the success-reply shape: anything else on the wire breaks a client."""
    out = []
    for line in stdout.splitlines():
        try:
            msg = json.loads(line)
        except ValueError:
            raise AssertionError("stdout line is not JSON: %r" % line[:200])
        assert _is_success_reply(msg), "stdout line is not a success reply: %r" % line[:200]
        out.append(msg)
    return out


def _replies(stdout):
    """The stimulus sends two requests, ids 1 and 2: stdout holds exactly one success reply for each, in any order."""
    msgs = _messages(stdout)
    ids = sorted(repr(m["id"]) for m in msgs)
    assert ids == ["1", "2"], "expected one reply each for ids 1 and 2, got ids %s" % ids
    return {m["id"]: m for m in msgs}


def _tool_names(stdout):
    return {t["name"] for t in _replies(stdout)[2]["result"].get("tools", [])}


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
    assert via_m.returncode == via_cli.returncode == 0, (via_m.returncode, via_cli.returncode)
    assert _tool_names(via_m.stdout) == _tool_names(via_cli.stdout) == TOOLS


def test_a_noisy_mailer_dependency_is_not_imported_on_the_mcp_route(tmp_path):
    """The `sunglasses mcp` route skips the mailer import.

    `resend` is the mailer's optional dependency; a copy that prints on import must
    leave stdout holding nothing but the server's replies on this route. Other optional
    imports the server shares with the CLI (the scanner engine's) are not covered here.
    """
    (tmp_path / "resend.py").write_text("print('NOISE ON STDOUT')\n", encoding="utf-8")
    proc = _run(CLI_ROUTE, extra_path=str(tmp_path))
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-600:])
    assert "NOISE" not in proc.stdout, proc.stdout[:600]
    assert _tool_names(proc.stdout) == TOOLS, proc.stdout[:600]


@pytest.mark.parametrize("line", [
    '{"jsonrpc": "2.0"}',
    '{"jsonrpc": "2.0", "id": 99}',
    '{"jsonrpc": "2.0", "id": 1, "result": {}, "error": {}}',
    '{"jsonrpc": "2.0", "id": 1, "result": {}, "error": null}',
    '{"jsonrpc": "2.0", "id": 1, "error": null}',
    '{"jsonrpc": "2.0", "id": 1, "error": {}}',
    '{"jsonrpc": "2.0", "id": 1, "error": {"code": -32601, "message": "x"}}',
    '{"jsonrpc": "2.0", "id": true, "result": {}}',
    '{"jsonrpc": "2.0", "id": 1.5, "result": {}}',
    '{"jsonrpc": "2.0", "id": null, "result": {}}',
    '{"jsonrpc": "2.0", "id": 1, "result": 5}',
    '{"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": 5}',
    '{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}',
    '{"jsonrpc": "2.0", "method": "notifications/initialized"}',
    '{"jsonrpc": "2.0", "method": 5}',
    '{"id": 1, "result": {}}',
    '[]',
    'NOISE',
])
def test_the_stdout_check_rejects_everything_but_a_success_reply(line):
    with pytest.raises(AssertionError):
        _messages(line + "\n")


@pytest.mark.parametrize("line", [
    '{"jsonrpc": "2.0", "id": 1, "result": {}}',
    '{"jsonrpc": "2.0", "id": "a", "result": {"tools": []}}',
])
def test_the_stdout_check_accepts_a_success_reply(line):
    assert len(_messages(line + "\n")) == 1


_INIT = '{"jsonrpc": "2.0", "id": 1, "result": {}}'
_LIST = '{"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "scan_text"}]}}'


@pytest.mark.parametrize("lines", [
    [_INIT],
    [_LIST],
    [_INIT, _INIT, _LIST],
    [_INIT, _LIST, '{"jsonrpc": "2.0", "id": 99, "result": {}}'],
    ['{"jsonrpc": "2.0", "id": 99, "result": {}}', _INIT, _LIST],
    [_INIT, '{"jsonrpc": "2.0", "id": 1, "result": {"tools": []}}'],
    [_INIT, '{"jsonrpc": "2.0", "id": "2", "result": {"tools": []}}'],
    [],
])
def test_the_reply_check_wants_exactly_one_reply_for_each_request_sent(lines):
    with pytest.raises(AssertionError):
        _replies("".join(l + "\n" for l in lines))


@pytest.mark.parametrize("lines", [[_INIT, _LIST], [_LIST, _INIT]])
def test_the_reply_check_accepts_one_reply_for_each_request_in_either_order(lines):
    assert set(_replies("".join(l + "\n" for l in lines))) == {1, 2}


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_subcommand_help_prints_usage_and_starts_no_server(flag):
    proc = _run(CLI_ROUTE + [flag])
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-600:])
    assert "usage:" in proc.stdout, proc.stdout[:600]
    assert STARTED not in proc.stderr, proc.stderr[:600]
    assert "jsonrpc" not in proc.stdout, proc.stdout[:600]


def test_subcommand_version_prints_the_version_and_starts_no_server():
    proc = _run(CLI_ROUTE + ["--version"])
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-600:])
    assert proc.stdout.split() and proc.stdout.split()[-1] == __version__, proc.stdout[:600]
    assert STARTED not in proc.stderr, proc.stderr[:600]


def test_top_level_help_lists_the_mcp_subcommand():
    proc = _run([sys.executable, "-c", "import sys; from sunglasses.cli import main; main()", "--help"])
    assert proc.returncode == 0, proc.stderr[-600:]
    assert re.search(r"^\s+mcp\s", proc.stdout, re.M), proc.stdout[:1500]
