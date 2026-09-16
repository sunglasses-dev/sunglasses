"""T10.R4/R5 at the CLI, through a real subprocess.

Exit codes follow AGENTS.md: 0 clean · 1 threat · 2 usage or operational error ·
3 incomplete inspection, and `0` and `3` must never collapse into each other.

`install` and `uninstall` never default to a path in the user's home. This
repo's CLAUDE.md records the hazard directly: `sunglasses init` writing into a
real settings file once inspected an agent's own subsequent tool calls. A wiring
command whose default target is `~/.claude.json` is the same hazard with a
different file, so the default is the project `.mcp.json` in the working
directory and anything else is explicit.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

REPO = str(pathlib.Path(__file__).resolve().parents[2])

RAW_CONFIG = (
    '{\n'
    '  "mcpServers": {\n'
    '    "github": {\n'
    '      "args": ["-y", "server-github"],\n'
    '      "command": "npx"\n'
    '    }\n'
    '  }\n'
    '}'
)


def sg(*args, cwd, home):
    """PYTHONPATH is pinned to the repo on purpose.

    Without it these tests run `-m sunglasses.cli` from a tmp cwd, the import
    fails before argparse is ever reached, and every assertion of the form
    "invalid choice not in stderr" passes against a process that never started.
    Three of these tests passed that way before this line existed. Installed
    versus tree, the Sep-14 lesson, inside my own harness.
    """
    env = dict(os.environ, SUNGLASSES_HOME=str(home),
               PYTHONPATH=REPO, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-B", "-m", "sunglasses.cli", *args],
                          cwd=str(cwd), env=env, capture_output=True, text=True)


def test_the_harness_actually_reaches_the_cli(tmp_path):
    """Guard on the guard: if this fails, every other test in this file is
    asserting against a process that died on import.

    Asserts on help text only our CLI emits. Round 1 asserted `returncode == 0`
    and "No module named" absent, which an empty `sys.exit(0)` satisfies.
    """
    r = sg("--help", cwd=tmp_path, home=tmp_path / "h")
    assert r.returncode == 0, r.stderr
    assert "No module named" not in r.stderr
    assert "Wrap an MCP server entry" in r.stdout


@pytest.fixture
def project(tmp_path):
    (tmp_path / ".mcp.json").write_text(RAW_CONFIG, encoding="utf-8")
    return tmp_path


def test_install_is_a_real_subcommand(project, tmp_path):
    """Positive evidence: the refusal diagnostic our install prints. "invalid
    choice" being absent is also true of a process that never started."""
    r = sg("install", "github", cwd=project, home=tmp_path / "h")
    assert "invalid choice" not in r.stderr
    assert "SUNGLASSES install" in (r.stdout + r.stderr)


def test_uninstall_is_a_real_subcommand(project, tmp_path):
    r = sg("uninstall", "github", cwd=project, home=tmp_path / "h")
    assert "invalid choice" not in r.stderr
    assert "SUNGLASSES uninstall" in (r.stdout + r.stderr)


def test_install_exits_2_and_says_why_when_the_artifact_is_absent(project, tmp_path):
    """On a build with no proxy entry point this is the ONLY outcome, and it is
    an operational error, not a clean pass."""
    before = (project / ".mcp.json").read_bytes()
    r = sg("install", "github", cwd=project, home=tmp_path / "h")
    assert r.returncode == 2, r.stderr
    assert (project / ".mcp.json").read_bytes() == before
    assert "proxy entry point" in (r.stdout + r.stderr)


def test_install_never_writes_outside_the_named_config(project, tmp_path):
    home = tmp_path / "h"
    r = sg("install", "github", cwd=project, home=home)
    assert "proxy entry point" in r.stdout          # the refusal really ran
    assert not (home / "proxy" / "installs" / "github.json").exists()


def test_uninstall_without_a_record_exits_2_and_does_not_mutate(project, tmp_path):
    before = (project / ".mcp.json").read_bytes()
    r = sg("uninstall", "github", cwd=project, home=tmp_path / "h")
    assert "invalid choice" not in r.stderr   # argparse also exits 2
    assert r.returncode == 2, r.stderr
    assert "SUNGLASSES uninstall refused" in r.stdout
    assert "no recorded install" in r.stdout
    assert (project / ".mcp.json").read_bytes() == before


def test_install_exits_2_when_it_cannot_proceed_at_all(tmp_path):
    """Renamed from "on an unreadable config", which it did not prove.

    ASTRA: on this head install refuses at artifact resolution BEFORE it ever
    reads the config, so a green result here was never evidence about
    config-read handling. While the artifact is absent the real CLI cannot
    reach the parser, so config reading is proven at module level instead, in
    `test_install_refuses_an_unreadable_config` and the R4-SHAPE controls.
    What this still proves is that the CLI exits 2 rather than 1 and prints a
    diagnostic instead of a traceback.
    """
    d = tmp_path / "empty"
    d.mkdir()
    r = sg("install", "github", cwd=d, home=tmp_path / "h")
    assert "invalid choice" not in r.stderr   # argparse also exits 2
    assert r.returncode == 2, r.stderr
    assert "SUNGLASSES install" in r.stdout
    assert "Traceback" not in r.stderr


def test_install_default_target_is_the_project_config_not_the_home_one(project, tmp_path):
    """The default must be the cwd's .mcp.json. Proven by pointing the process
    at a cwd with no config: it must fail on THAT path, never reach into HOME."""
    d = tmp_path / "bare"
    d.mkdir()
    r = sg("install", "github", cwd=d, home=tmp_path / "h")
    out = r.stdout + r.stderr
    assert ".mcp.json" in out
    assert ".claude.json" not in out


def test_install_accepts_an_explicit_config_path(tmp_path):
    other = tmp_path / "somewhere" / "custom.json"
    other.parent.mkdir()
    other.write_text(RAW_CONFIG, encoding="utf-8")
    d = tmp_path / "bare"
    d.mkdir()
    r = sg("install", "github", "--config", str(other), cwd=d, home=tmp_path / "h")
    assert "custom.json" in (r.stdout + r.stderr)
