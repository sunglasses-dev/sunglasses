"""The proxy's startup refusals name a configured path without letting it act on the terminal.

`serve.main` stops before it spawns anything when the receipt log or the approval store
cannot be made, and says which path is in the way. That path comes from `--state-root`, a
config file or a parent directory somebody else named, so it can carry an escape sequence, a
newline or bytes that are not text. Echoed raw, it could split the line, rewrite what the
terminal already showed, or fail the write. These cases run the real entry point in a child
interpreter and read the real stderr:

* a name with control characters is shown escaped, on one line, with a sentence saying so, and
  the "Fix it" line does not pretend the escaped form is an argument a shell would read back;
* a name with spaces is still named, shell-quoted, so the sentence can be pasted whole;
* a name that cannot be handed to the operating system at all (a NUL) is the same refusal,
  not a traceback.

Exit codes are unchanged: 1 for the receipt log, EXIT_FAULT for the approval store.
"""
import os
import subprocess
import sys

import pytest

from sunglasses.proxy import receipts, serve

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPSTREAM = [sys.executable, "-c", "import sys; sys.stdin.read()"]

# One name per class of character a terminal acts on; each sits inside the directory name.
CONTROLS = {
    "esc": "a\x1b[2Jb",
    "newline": "a\nb",
    "carriage-return": "a\rb",
    "tab": "a\tb",
    "del": "a\x7fb",
    "c1": "a\x85b",
    "line-separator": "a b",
}


def _run(tmp_path, state, opted=False):
    """serve.main in a child with `state` (a str, written into the script as an escaped literal)."""
    home = tmp_path / "sunglasses-home"
    home.mkdir(exist_ok=True)
    (tmp_path / "user").mkdir(exist_ok=True)
    script = ("import sys\nfrom sunglasses.proxy import serve\n"
              f"sys.exit(serve.main(['--state-root', {state!r}, '--', *{UPSTREAM!r}]))\n")
    env = {**os.environ, "HOME": str(tmp_path / "user"), "SUNGLASSES_HOME": str(home),
           "PYTHONPATH": TREE, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-c", script], input=b"", cwd=str(tmp_path),
                          env=env, capture_output=True, timeout=60)


def _state(tmp_path, name):
    return str(tmp_path / "user" / name)


def _blocked_receipts(tmp_path, name):
    """A state root called `name` whose receipts directory is a regular file."""
    state = tmp_path / "user" / name
    state.mkdir(parents=True)
    (state / "receipts").write_text("not a directory\n")
    return state, state / "receipts"


def _blocked_approvals(tmp_path, name):
    """A state root called `name` that opens a receipt log but whose approvals directory is a file."""
    state = tmp_path / "user" / name
    state.mkdir(parents=True)
    (state / "approvals").write_text("not a directory\n")
    return state, state / "approvals"


def _escaped(text):
    """What the line must show for `text`: each non-printable character as its escape, written
    here independently of the code under test."""
    return "".join(c if c.isprintable() else
                   "\\x%02x" % ord(c) if ord(c) < 0x100 else "\\u%04x" % ord(c) for c in text)


def _one_safe_line(err):
    assert b"Traceback" not in err, err[-400:]
    text = err.decode("utf-8", errors="strict")
    assert text.endswith("\n") and text.count("\n") == 1, repr(text)
    assert text[:-1].isprintable(), repr(text)
    return text[:-1]


# ---------------------------------------------------------------------------
# control characters
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kind", sorted(CONTROLS))
def test_receipt_log_refusal_escapes_the_name_and_stays_one_line(tmp_path, kind):
    state, blocked = _blocked_receipts(tmp_path, "proxy-" + CONTROLS[kind])
    p = _run(tmp_path, str(state))
    assert p.returncode == 1, p.stderr[-400:]
    line = _one_safe_line(p.stderr)
    assert "the receipt log could not be opened" in line
    assert "its name has control characters, shown escaped" in line
    assert _escaped(str(blocked)) in line
    assert "chmod 700" in line


@pytest.mark.parametrize("kind", sorted(CONTROLS))
def test_approval_store_refusal_escapes_the_name_and_stays_one_line(tmp_path, kind):
    state, blocked = _blocked_approvals(tmp_path, "proxy-" + CONTROLS[kind])
    p = _run(tmp_path, str(state))
    assert p.returncode == serve.EXIT_FAULT, p.stderr[-400:]
    line = _one_safe_line(p.stderr)
    assert "the approval store at" in line and "could not be made" in line
    assert _escaped(str(blocked)) in line
    assert "its name has control characters, shown escaped" in line


def test_a_name_that_is_not_text_is_escaped_not_a_write_failure(tmp_path):
    """Bytes that are not UTF-8 reach Python as lone surrogates; the line must still be written."""
    state = str(tmp_path / "user" / "proxy-\udc80\udcff")
    p = _run(tmp_path, state)
    assert p.returncode == 1, p.stderr[-400:]
    line = _one_safe_line(p.stderr)
    assert "the receipt log could not be opened" in line
    assert "\\udc80\\udcff" in line


def test_a_nul_in_the_state_root_is_a_refusal_not_a_traceback(tmp_path):
    p = _run(tmp_path, _state(tmp_path, "proxy-\x00-x"))
    assert p.returncode == 1, p.stderr[-400:]
    line = _one_safe_line(p.stderr)
    assert "the receipt log could not be opened" in line
    assert "\\x00" in line


# ---------------------------------------------------------------------------
# spaces: still a sentence a person can paste
# ---------------------------------------------------------------------------

def test_receipt_log_refusal_quotes_a_path_with_spaces(tmp_path):
    state, blocked = _blocked_receipts(tmp_path, "my proxy state")
    p = _run(tmp_path, str(state))
    assert p.returncode == 1, p.stderr[-400:]
    line = _one_safe_line(p.stderr)
    assert f"Fix it: make '{blocked}' a directory, chmod 700" in line
    assert "control characters" not in line


def test_approval_store_refusal_quotes_a_path_with_spaces(tmp_path):
    state, blocked = _blocked_approvals(tmp_path, "my proxy state")
    p = _run(tmp_path, str(state))
    assert p.returncode == serve.EXIT_FAULT, p.stderr[-400:]
    line = _one_safe_line(p.stderr)
    assert f"Fix it: make '{blocked}' a directory you own, chmod 700." in line
    assert "control characters" not in line


def test_a_plain_path_is_named_exactly_as_before(tmp_path):
    state, blocked = _blocked_receipts(tmp_path, "proxy")
    p = _run(tmp_path, str(state))
    line = _one_safe_line(p.stderr)
    assert f"Fix it: make {blocked} a directory, chmod 700" in line
    assert "'" not in line


# ---------------------------------------------------------------------------
# the helpers
# ---------------------------------------------------------------------------

def test_printable_leaves_text_alone_and_escapes_the_rest():
    assert receipts.printable("/a b/ü/é") == "/a b/ü/é"
    assert receipts.printable("a\x1bb\n\x7f\x85 \udc80\U0001f600") == \
        "a\\x1bb\\x0a\\x7f\\x85\\u2028\\udc80\U0001f600"


def test_shown_path_quotes_a_clean_path_and_escapes_a_dirty_one():
    assert receipts.shown_path("/a b") == ("'/a b'", True)
    assert receipts.shown_path("/ab") == ("/ab", True)
    assert receipts.shown_path("/a\x1bb") == ("/a\\x1bb", False)
