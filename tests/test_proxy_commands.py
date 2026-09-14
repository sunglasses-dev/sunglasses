"""The commands, specified before they exist.

T10.R4 and T10.R5 are written as commands: `install <name> -- <argv>` and
`uninstall <name>`. T10.R3 is a report with three lines and an exit code, which
only means something to somebody who can run it. None of that was reachable.
doctor.py has existed for hours as a library that nothing in the package
invokes, which is the same fault a review of this lane found at five
components: correct parts, no caller, nothing protected.

So `python -m sunglasses.proxy doctor`, `install`, `uninstall`, and the bare
`-- <server>` form that runs the mediator.

The dispatch itself carries one rule worth stating. A first token that is not a
known command and is not the separator is a USAGE ERROR, never a server to run.
Guessing there means executing a name the user typed by mistake, with whatever
arguments followed it, as a child process.

The `sunglasses proxy ...` alias lives in sunglasses/cli.py and is not added
here, because that file is outside sunglasses/proxy/ and every review of this
lane so far has been scoped to what is inside it.
"""
import json

import pytest

commands = pytest.importorskip("sunglasses.proxy.commands",
                               reason="the commands are the slice being specified")


def _config(tmp_path, entry=None):
    path = tmp_path / ".mcp.json"
    path.write_text(json.dumps({"mcpServers": {
        "fs": entry or {"command": "npx", "args": ["server"]}}}))
    return path


class _Out:
    def __init__(self):
        self.text = ""

    def write(self, chunk):
        self.text += chunk


# ── dispatch ─────────────────────────────────────────────────────────────

def test_an_unknown_first_token_is_a_usage_error_not_a_server():
    """Running it would execute a mistyped command name as a child process
    with whatever arguments followed it."""
    err = _Out()
    assert commands.main(["docter"], stderr=err) == 2
    assert "usage" in err.text.lower()


def test_no_arguments_at_all_is_a_usage_error():
    err = _Out()
    assert commands.main([], stderr=err) == 2


def test_the_separator_form_is_the_mediator():
    """`-- <server>` is the form an MCP client config writes, so it stays the
    default rather than becoming a subcommand of its own."""
    seen = {}

    def fake_serve(argv, **kw):
        seen["argv"] = argv
        return 0

    assert commands.main(["--", "npx", "srv"], serve=fake_serve) == 0
    assert seen["argv"] == ["--", "npx", "srv"]


# ── T10.R3 · the doctor reports three lines and an exit code ─────────────

def test_doctor_prints_the_three_lines_and_returns_the_exit_code(tmp_path):
    out = _Out()
    code = commands.main(["doctor", "--config", str(_config(tmp_path))],
                         stdout=out,
                         report=lambda **kw: _report(aggregate="ROUTE_UNVERIFIED",
                                                    exit_code=3))
    assert code == 3
    assert "ROUTE_UNVERIFIED" in out.text
    assert "inventory" in out.text.lower()
    assert "self" in out.text.lower()


def test_doctor_never_prints_upstream_stderr(tmp_path):
    """T10.R3's last sentence, at the one place the text would actually be
    printed rather than merely carried."""
    out = _Out()
    commands.main(["doctor", "--config", str(_config(tmp_path))], stdout=out,
                  report=lambda **kw: _report(
                      aggregate="ROUTE_UNVERIFIED", exit_code=1,
                      route_checks={"project:fs": {"deadline": "FAIL"}},
                      leak="SECRET upstream text"))
    assert "SECRET upstream text" not in out.text


def _report(*, aggregate, exit_code, route_checks=None, leak=None):
    from sunglasses.proxy import doctor
    outcome = doctor.Outcome(aggregate=aggregate, exit_code=exit_code,
                             per_wrapper=[{"name": "fs", "source": "project",
                                           "result": "FAIL"}],
                             inventory=[{"name": "fs", "source": "project",
                                         "state": doctor.DIRECT}])
    report = doctor.Report(outcome=outcome, exit_code=exit_code,
                           self_test_ok=False,
                           self_test_detail=leak or "",
                           route_checks=route_checks or {})
    return report


# ── T10.R4 and T10.R5 · install and uninstall ────────────────────────────

def test_install_wraps_the_named_entry(tmp_path):
    config = _config(tmp_path)
    code = commands.main(["install", "fs", "--config", str(config),
                          "--state-root", str(tmp_path / "state"),
                          "--", "python", "-m", "sunglasses.proxy"],
                         stdout=_Out())
    assert code == 0
    entry = json.loads(config.read_text())["mcpServers"]["fs"]
    assert "sunglasses.proxy" in json.dumps(entry)


def test_install_without_the_separator_is_a_usage_error(tmp_path):
    """R4's syntax is `install <name> -- <argv>`. Without the separator there
    is no wrapper command, and inventing one would wrap the entry in whatever
    this process happens to be."""
    err = _Out()
    code = commands.main(["install", "fs", "--config", str(_config(tmp_path))],
                         stderr=err)
    assert code == 2


def test_uninstall_restores_and_reports_which_kind_of_restore(tmp_path):
    config = _config(tmp_path)
    original = config.read_text()
    root = str(tmp_path / "state")
    commands.main(["install", "fs", "--config", str(config),
                   "--state-root", root, "--", "python", "-m",
                   "sunglasses.proxy"], stdout=_Out())
    out = _Out()
    code = commands.main(["uninstall", "fs", "--config", str(config),
                          "--state-root", root], stdout=out)
    assert code == 0
    assert config.read_text() == original
    assert "byte" in out.text.lower()


def test_uninstall_on_an_unknown_state_reports_the_conflict_and_fails(tmp_path):
    """R5. No mutation, and an exit code that says so, because a script that
    reads zero here will carry on as though the entry were restored."""
    out = _Out()
    config = _config(tmp_path, entry={"command": "mystery"})
    before = config.read_text()
    code = commands.main(["uninstall", "fs", "--config", str(config),
                          "--state-root", str(tmp_path / "state")], stdout=out)
    assert code != 0
    assert "CONFIG_CONFLICT" in out.text
    assert config.read_text() == before
