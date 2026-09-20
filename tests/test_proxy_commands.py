"""The commands, specified before they exist.

T10.R4 and T10.R5 are written as commands: `install <name> -- <argv>` and
`uninstall <name>`. T10.R3 is a report with three lines and an exit code, which
only means something to somebody who can run it. None of that was reachable.
`sunglasses/install.py` owns install, uninstall and classify (R-DOCTOR-OWNER,
2026-09-15); the rows that drove this lane's second implementation moved out
with it. What is left is the dispatch itself: the mediator form, the usage
error, and approve.

The old opening line said doctor.py had existed for hours as a library nothing
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


def test_approve_finds_the_capture_from_an_unrelated_directory(tmp_path, monkeypatch):
    """WITHOUT `--state-root`, and standing somewhere else entirely.

    `--state-root` used to default to `"."`, so `approve` looked for the capture
    under whatever directory the user happened to be in while the proxy had
    written it to `serve.state_root()`. It then refused with "no stored capture"
    — a true statement about a directory nobody had written to — and nothing
    told the reader where to look instead. Measured before the fix: exit 1 from
    any other directory, exit 0 only with the flag pointed at the proxy's root.

    The proxy's root is HOME-derived, so pointing HOME at a temp dir is what
    makes this row hermetic; `serve.state_root()` deliberately reads no
    environment variable of its own.
    """
    home = tmp_path / "home"
    (home / ".sunglasses" / "proxy").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.chdir(tmp_path / "elsewhere" if (tmp_path / "elsewhere").mkdir()
                      or (tmp_path / "elsewhere").exists() else tmp_path)

    store = _capture(home / ".sunglasses" / "proxy")
    code = commands.main(["approve", "review-id", "--snapshot", "a" * 64],
                         stdout=io.StringIO(), stderr=io.StringIO(),
                         confirm=lambda: True)
    assert code == commands.EXIT_OK
    assert store.read()["approved_by"] == "human"


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
