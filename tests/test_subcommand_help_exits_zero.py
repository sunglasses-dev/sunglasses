"""`X --help` is a request, not a mistake: it prints to stdout, exits 0 and leaves stderr empty.

`scan --help` always did. `proxy` is dispatched by hand (a bare `--` and a wrapped server's own
flags must reach the server untouched), and that route used to answer `--help` with its usage
error on stderr and exit 2.
"""
import io
import os
import pathlib
import re
import subprocess
import sys

import pytest

from sunglasses.proxy import commands

REPO = pathlib.Path(__file__).resolve().parent.parent
SUBCOMMANDS = ["scan", "check", "info", "firewall-hook", "pin", "init", "receipts", "demo", "report",
               "install", "uninstall", "doctor", "config", "proxy", "mcp"]


def _run(args, tmp_path):
    env = dict(os.environ, HOME=str(tmp_path), NO_COLOR="1", PYTHONPATH=str(REPO))
    env.pop("SUNGLASSES_HOME", None)
    return subprocess.run([sys.executable, "-m", "sunglasses.cli", *args], capture_output=True,
                          text=True, timeout=120, env=env, cwd=str(tmp_path))


def test_the_list_is_every_subcommand_the_top_level_help_names(tmp_path):
    out = _run(["--help"], tmp_path).stdout
    listed = re.search(r"\{([a-z\-,]+)\}", out).group(1).split(",")
    assert sorted(listed) == sorted(SUBCOMMANDS)


@pytest.mark.parametrize("command", SUBCOMMANDS)
@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_each_subcommand_help_goes_to_stdout_and_succeeds(tmp_path, command, flag):
    done = _run([command, flag], tmp_path)
    assert done.returncode == 0, done.stderr
    assert done.stdout.strip()
    assert done.stderr == ""


@pytest.mark.parametrize("args", [["approve", "--help"], ["--state-root", "/x", "--help", "--", "srv"],
                                  ["approve", "srv", "--snapshot", "abc", "-h"]])
def test_the_proxy_forms_that_ask_for_help_succeed(tmp_path, args):
    done = _run(["proxy", *args], tmp_path)
    assert done.returncode == 0, done.stderr
    assert "sunglasses proxy approve" in done.stdout
    assert done.stderr == ""


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_after_the_separator_belongs_to_the_wrapped_server(flag):
    seen = []
    out, err = io.StringIO(), io.StringIO()
    code = commands.main(["--", "srv", flag], stdout=out, stderr=err, serve=lambda argv: seen.append(argv) or 0)
    assert code == 0
    assert seen == [["--", "srv", flag]]
    assert out.getvalue() == "" and err.getvalue() == ""


def test_a_mistyped_command_is_still_a_usage_error():
    out, err = io.StringIO(), io.StringIO()
    assert commands.main(["docter"], stdout=out, stderr=err) == commands.EXIT_USAGE
    assert out.getvalue() == "" and "usage:" in err.getvalue()
    assert commands.main([], stdout=io.StringIO(), stderr=io.StringIO()) == commands.EXIT_USAGE
