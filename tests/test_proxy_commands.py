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

import io
import sys

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


def test_the_wrapped_argv_keeps_its_own_flags_verbatim(tmp_path):
    """Everything after `--` belongs to the command being wrapped. A wrapper
    argv carrying its own `--config` is ordinary, and reinterpreting it as ours
    would both lose it from the entry and point this tool at a file the server
    meant for itself."""
    config = _config(tmp_path)
    commands.main(["install", "fs", "--config", str(config),
                   "--state-root", str(tmp_path / "state"), "--",
                   "python", "-m", "sunglasses.proxy", "--config", "theirs.json"],
                  stdout=_Out())
    entry = json.loads(config.read_text())["mcpServers"]["fs"]
    flat = json.dumps(entry)
    assert "theirs.json" in flat
    assert "--config" in flat


# ── AR12: the approve command T5.R1 names ──────────────────────────────────

def test_approve_is_a_command_and_not_a_usage_error(tmp_path, capsys):
    """AR12. `approvals.py` refuses every other writer with a message naming
    `sunglasses proxy approve`, and the package did not ship it. A gate nobody
    can open is a gate that gets worked around."""
    code = commands.main(["approve", "review-id", "--snapshot", "a" * 64,
                          "--state-root", str(tmp_path)])
    assert code != commands.EXIT_USAGE
    assert code == commands.EXIT_FAULT


def test_approve_refuses_when_there_is_no_capture_to_have_seen(tmp_path):
    out, err = io.StringIO(), io.StringIO()
    code = commands.main(["approve", "review-id", "--snapshot", "a" * 64,
                          "--state-root", str(tmp_path)],
                         stdout=out, stderr=err)
    assert code == commands.EXIT_FAULT
    assert "no stored capture" in err.getvalue()


def _capture(tmp_path):
    from sunglasses.proxy import approvals

    store = approvals.Store(tmp_path, server_id="review-id")
    store.capture("a" * 64, payload={
        "sha256": "a" * 64,
        "tools_by_name": {"read_text_file": {"descriptor_sha256": "b" * 64}},
        "pages": [{"tools": [{"name": "read_text_file"}]}]})
    return store


def test_approve_will_not_record_that_nobody_looked(tmp_path):
    """T5.R1. `viewed` records that a PERSON looked, and a pipe cannot look.
    Approving here would write the record on their behalf, which is exactly
    what the library's `write_without_human` refuses."""
    store = _capture(tmp_path)
    out, err = io.StringIO(), io.StringIO()
    code = commands.main(["approve", "review-id", "--snapshot", "a" * 64,
                          "--state-root", str(tmp_path)],
                         stdout=out, stderr=err, confirm=lambda: None)
    assert code == commands.EXIT_FAULT
    assert "not an interactive terminal" in err.getvalue()
    assert store.state() == "UNAPPROVED"


def test_approve_shows_the_descriptors_before_asking(tmp_path):
    """What the human is asked to approve has to be in front of them, or
    `viewed` records a look at nothing."""
    _capture(tmp_path)
    out, err = io.StringIO(), io.StringIO()
    commands.main(["approve", "review-id", "--snapshot", "a" * 64,
                   "--state-root", str(tmp_path)],
                  stdout=out, stderr=err, confirm=lambda: False)
    shown = out.getvalue()
    assert "read_text_file" in shown
    assert "a" * 64 in shown


def test_a_person_saying_no_does_not_approve(tmp_path):
    store = _capture(tmp_path)
    code = commands.main(["approve", "review-id", "--snapshot", "a" * 64,
                          "--state-root", str(tmp_path)],
                         stdout=io.StringIO(), stderr=io.StringIO(),
                         confirm=lambda: False)
    assert code == commands.EXIT_FAULT
    assert store.state() == "UNAPPROVED"


def test_a_person_saying_yes_writes_the_record(tmp_path):
    """The positive control. Without it the row above is satisfied by a command
    that never approves anything."""
    store = _capture(tmp_path)
    code = commands.main(["approve", "review-id", "--snapshot", "a" * 64,
                          "--state-root", str(tmp_path)],
                         stdout=io.StringIO(), stderr=io.StringIO(),
                         confirm=lambda: True)
    assert code == commands.EXIT_OK
    assert store.read()["approved_by"] == "human"
    assert store.read()["snapshot_sha256"] == "a" * 64


class _Stdin:
    """A stdin that can say whether it is a terminal, because that is the whole
    question `_ask` has to answer."""

    def __init__(self, tty, line=""):
        self._tty = tty
        self._line = line

    def isatty(self):
        return self._tty

    def readline(self):
        return self._line


def test_the_real_prompt_refuses_to_ask_a_pipe(tmp_path, monkeypatch):
    """T5.R1's unattended guard, exercised through the prompt itself.

    Every other test here injects `confirm`, so the function that decides
    whether there is a person to ask was reachable by nothing: deleting its
    terminal check left the whole suite green while the command would approve
    an MCP server from a cron job.
    """
    store = _capture(tmp_path)
    monkeypatch.setattr(sys, "stdin", _Stdin(tty=False, line="y\n"))
    code = commands.main(["approve", "review-id", "--snapshot", "a" * 64,
                          "--state-root", str(tmp_path)],
                         stdout=io.StringIO(), stderr=io.StringIO())
    assert code == commands.EXIT_FAULT
    assert not store._path.exists(), "a record was written with nobody to ask"


@pytest.mark.parametrize("typed,approved", [
    ("y\n", True), ("yes\n", True), ("\n", False), ("n\n", False),
    ("no\n", False), ("maybe\n", False),
])
def test_the_real_prompt_reads_what_the_person_typed(tmp_path, monkeypatch,
                                                     typed, approved):
    """And the positive half: on a terminal it asks, and only an affirmative
    answer approves. Anything else, including an empty line, is no."""
    store = _capture(tmp_path)
    monkeypatch.setattr(sys, "stdin", _Stdin(tty=True, line=typed))
    code = commands.main(["approve", "review-id", "--snapshot", "a" * 64,
                          "--state-root", str(tmp_path)],
                         stdout=io.StringIO(), stderr=io.StringIO())
    assert (code == commands.EXIT_OK) is approved
    # The RECORD is what approving writes. `state()` stays UNAPPROVED until an
    # activation runs, which is T5.R3's separate step and not this command's.
    assert store._path.exists() is approved
