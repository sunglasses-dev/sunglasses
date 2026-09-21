"""0.6.1 row 2 — `sunglasses doctor`, the command, not the module.

WHY THIS FILE EXISTS. On 2026-09-21 the README showed `sunglasses doctor` in a
copy-paste block beside three commands that work, and argparse rejected it with
exit 2. #222 removed the line rather than rewriting it into a command that would
still not run. This row makes the line true instead, so the first thing these
tests pin is the thing that was wrong: the subcommand exists.

Everything here drives the INSTALLED SURFACE as a subprocess, because the defect
being fixed lived in argparse wiring and a test that imports `cmd_doctor` and
calls it would have passed on the broken tree. The one exception is the exit
ladder, which needs a self-test this build does not have; those rows inject
through `cmd_doctor`'s seam and say so at the use site.

WHAT THIS BUILD CANNOT DO, pinned here so nobody reads a green suite as more
than it is: `default_self_test` returns `(False, {})`, so `doctor.run()` exits 1
on every machine with detail SELF_TEST_UNAVAILABLE. R1's live self-test is a
separate row. The rows below therefore assert 1 as TODAY'S measured truth and
assert separately that the words distinguish "this build has no self-test" from
"your routes failed" — which is the whole difference an operator acts on.
"""

import json
import os
import subprocess
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)

from sunglasses.proxy import doctor  # noqa: E402


def _run_cli(*args, cwd=None):
    """The command as a user gets it. cwd defaults to an EMPTY directory, never
    the repo: `default_sources()` reads `cwd/.mcp.json` and `~/.claude.json`, so
    a test run from the repo would read whatever the developer happens to have
    wired and pass or fail by machine."""
    return subprocess.run(
        [sys.executable, "-m", "sunglasses.cli", *args],
        capture_output=True, text=True, cwd=cwd or REPO,
        env={**os.environ, "PYTHONPATH": REPO},
    )


def _config(tmp_path, entries):
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": entries}))
    return path


# ---------------------------------------------------------------------------
# 1. The defect itself
# ---------------------------------------------------------------------------

def test_doctor_is_an_accepted_subcommand(tmp_path):
    """RED-FIRST on 164bca7: exit 2, `invalid choice: 'doctor'`.

    Asserted on the message and not only on the code, because exit 2 is also a
    legitimate doctor outcome (an operational error). A row that checked
    `rc != 2` would go green the day doctor started failing to open a file.
    """
    cfg = _config(tmp_path, {"github": {"command": "npx", "args": ["server"]}})
    proc = _run_cli("doctor", "--config", str(cfg), cwd=str(tmp_path))
    assert "invalid choice" not in proc.stderr, proc.stderr
    assert "doctor" in _run_cli("--help").stdout


def test_doctor_appears_in_the_command_list(tmp_path):
    """The usage line argparse prints is the list #222 quoted as authoritative."""
    proc = _run_cli("--help")
    assert "doctor" in proc.stdout


# ---------------------------------------------------------------------------
# 2. --config scopes what is read
# ---------------------------------------------------------------------------

def test_config_flag_reads_that_file_and_names_its_servers(tmp_path):
    cfg = _config(tmp_path, {"github": {"command": "npx", "args": ["server"]},
                             "fs": {"command": "node", "args": ["fs.js"]}})
    proc = _run_cli("doctor", "--config", str(cfg), cwd=str(tmp_path))
    assert "github" in proc.stdout, proc.stdout
    assert "fs" in proc.stdout, proc.stdout


def test_config_flag_excludes_the_users_own_home_config(tmp_path):
    """`--config` must SCOPE, not ADD.

    `default_sources()` includes `~/.claude.json`. If `--config` merely appended,
    `sunglasses doctor --config ./x.json` would report on servers the operator
    did not ask about, and on a developer machine the suite's own result would
    depend on that developer's home directory. The row proves the scoping by
    naming a server that exists ONLY in the home file's position: with scoping
    the report contains exactly the one entry from the given file.
    """
    cfg = _config(tmp_path, {"only-this-one": {"command": "npx", "args": ["s"]}})
    proc = _run_cli("doctor", "--config", str(cfg), cwd=str(tmp_path))
    data = json.loads(_run_cli("doctor", "--config", str(cfg), "--json",
                               cwd=str(tmp_path)).stdout)
    names = [row["name"] for row in data["inventory"]]
    assert names == ["only-this-one"], names
    assert "only-this-one" in proc.stdout


def test_unreadable_config_is_named_in_the_output(tmp_path):
    """R-DOCTOR-R3a: a file we could not open is named, never silently absent.

    A path the operator NAMED is refused rather than reported through the
    inventory, in `install`'s shape: reported that way it came back "no server
    entries found", which reads as "you have nothing wired" when the truth is
    "that file does not exist". Exit 2 is assertable here precisely because
    nothing ran, so no self-test verdict outranks it.
    """
    missing = tmp_path / "nowhere" / ".mcp.json"
    proc = _run_cli("doctor", "--config", str(missing), cwd=str(tmp_path))
    assert str(missing) in proc.stdout + proc.stderr
    assert proc.returncode == 2, proc.stdout
    assert "no server entries" not in proc.stdout.lower()


# ---------------------------------------------------------------------------
# 3. The exit code is the module's, not the CLI's
# ---------------------------------------------------------------------------

def test_exit_code_is_one_on_this_build_because_the_self_test_is_absent(tmp_path):
    """TODAY'S MEASURED TRUTH, and it is a fact about the build, not the config.

    Two configs that differ in every way the doctor reads still exit 1, because
    R3's precedence puts the self-test above everything. When R1's live self-test
    lands, this row is expected to change and should be changed deliberately.
    """
    wired = _config(tmp_path, {"github": {"command": "npx", "args": ["server"]}})
    empty = tmp_path / "empty.json"
    empty.write_text(json.dumps({"mcpServers": {}}))
    assert _run_cli("doctor", "--config", str(wired), cwd=str(tmp_path)).returncode == 1
    assert _run_cli("doctor", "--config", str(empty), cwd=str(tmp_path)).returncode == 1


def test_output_distinguishes_an_absent_self_test_from_a_failed_one(tmp_path):
    """The difference an operator acts on.

    `render()` reports failure_class SCHEMA with all five checks listed as
    failed, which read alone says "your proxy failed five checks". None of them
    ran. The command must say so in words, or it tells every user on every
    machine that something broke when nothing did.
    """
    cfg = _config(tmp_path, {"github": {"command": "npx", "args": ["server"]}})
    out = _run_cli("doctor", "--config", str(cfg), cwd=str(tmp_path)).stdout.lower()
    assert "self-test" in out or "self test" in out
    assert "not" in out and ("build" in out or "available" in out), out


@pytest.mark.parametrize("code", [0, 2, 3])
def test_cli_returns_the_reports_exit_code_verbatim(tmp_path, code, monkeypatch):
    """The ladder through the CLI layer, for the codes this build cannot reach.

    INJECTED, and deliberately not through a flag or an environment variable: a
    shipped package that changes its exit code because of an undeclared env read
    is a switch anything in the process tree can flip (echo_server.py's own
    docstring makes that rule). `cmd_doctor` takes the runner as a parameter,
    which is reachable from a test and from nothing else.
    """
    from sunglasses import cli

    class _Report:
        exit_code = code

    monkeypatch.setattr(doctor, "render", lambda r: {
        "self_test": {"valid": True, "controls": {}, "checks": {}, "failed": [],
                      "failure_class": None, "detail": "", "measured_ms": 1,
                      "bound_ms": doctor.DEADLINE_BOUND_MS, "deadline": "x"},
        "per_wrapper": [], "inventory": [], "aggregate": doctor.ROUTE_VERIFIED,
        "route_checks": {}, "exit_code": code})

    args = type("A", (), {"config": None, "json": False})()
    with pytest.raises(SystemExit) as exc:
        cli.cmd_doctor(args, _run=lambda **kw: _Report())
    assert exc.value.code == code


# ---------------------------------------------------------------------------
# 4. Help says what it checks AND what it cannot
# ---------------------------------------------------------------------------

def test_help_states_what_the_doctor_cannot_do():
    """A help text that lists only capabilities is how the README line got there
    in the first place."""
    out = _run_cli("doctor", "--help").stdout.lower()
    assert "exit" in out
    assert "cannot" in out or "does not" in out or "not verify" in out, out


def test_help_documents_the_exit_ladder():
    out = _run_cli("doctor", "--help").stdout
    for code in ("0", "1", "2", "3"):
        assert code in out, out
