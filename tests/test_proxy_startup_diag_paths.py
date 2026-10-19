"""The proxy's startup refusals name a configured path without letting it act on the terminal.

`serve.main` stops before it spawns anything when the receipt log or the approval store
cannot be made, and says which path is in the way. That path comes from `--state-root`, a
config file or a parent directory somebody else named, so it can carry an escape sequence, a
newline, a character that prints as nothing, or bytes that are not text. Echoed raw, it could
split the line, rewrite what the terminal already showed, make one directory read as another,
or fail the write. These cases run the real entry point in a child interpreter and read its
stderr:

* a name with a control or invisible character is written between $'...' with those
  characters as escapes (a backslash and a quote escaped too), on one line, with a sentence
  saying so, and two different names never print the same;
* any other name is shell-quoted, at every place the message names a path;
* a name that cannot be handed to the operating system at all (a NUL) is the same refusal,
  not a traceback.

Exit codes at the command line are unchanged: 1 for the receipt log, EXIT_FAULT for the
approval store. Two cases call the display helpers directly and thirty give what is shown to
the system bash (3.2) and zsh and compare the bytes they read back; the rest run `serve.main`.
"""
import os
import shlex
import subprocess
import sys

import pytest

from sunglasses.proxy import receipts, serve

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPSTREAM = [sys.executable, "-c", "import sys; sys.stdin.read()"]
NOTE = "the name has control or invisible characters, so it is written between $'...' as escapes"

# One name per class of character a terminal acts on; each sits inside the directory name.
CONTROLS = {
    "esc": "a\x1b[2Jb",
    "newline": "a\nb",
    "carriage-return": "a\rb",
    "tab": "a\tb",
    "del": "a\x7fb",
    "c1": "a\x85b",
    "line-separator": "a b",
    "bidi-override": "a‮b",
    "zero-width-space": "a​b",
}
# Printable to Python, invisible on a screen: they can make one name read as another.
INVISIBLE = {
    "combining-grapheme-joiner": "a͏b",
    "variation-selector": "a️b",
    "variation-selector-supplement": "a\U000e0100b",
}
HIDDEN = {**CONTROLS, **INVISIBLE}


def _run(tmp_path, state):
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


def _written(text):
    """What a diagnostic must show for a name with something hidden in it, built here
    independently of the code under test: $'...', backslash and quote escaped, each hidden
    character as a hex byte escape for each of its bytes (a lone surrogate is the one byte it
    stands for)."""
    invisible = "͏️\U000e0100"
    out = []
    for c in text:
        n = ord(c)
        if c == "\\":
            out.append("\\\\")
        elif c == "'":
            out.append("\\'")
        elif c.isprintable() and c not in invisible:
            out.append(c)
        else:
            raw = bytes([n - 0xDC00]) if 0xDC80 <= n <= 0xDCFF else c.encode("utf-8", "surrogatepass")
            out.append("".join("\\x%02x" % byte for byte in raw))
    return "$'" + "".join(out) + "'"


def _one_safe_line(err):
    assert b"Traceback" not in err, err[-400:]
    text = err.decode("utf-8", errors="strict")
    assert text.endswith("\n") and text.count("\n") == 1, repr(text)
    assert text[:-1].isprintable(), repr(text)
    return text[:-1]


# ---------------------------------------------------------------------------
# control and invisible characters
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("kind", sorted(HIDDEN))
def test_receipt_log_refusal_writes_the_name_as_escapes_on_one_line(tmp_path, kind):
    state, blocked = _blocked_receipts(tmp_path, "proxy-" + HIDDEN[kind])
    p = _run(tmp_path, str(state))
    assert p.returncode == 1, p.stderr[-400:]
    line = _one_safe_line(p.stderr)
    assert "the receipt log could not be opened" in line
    # both places the message names a path: the root and the thing in the way
    assert f"the receipts directory {_written(str(blocked))}" in line
    assert f"Fix it: make {_written(str(blocked))} a directory, chmod 700" in line
    assert NOTE in line


@pytest.mark.parametrize("kind", sorted(HIDDEN))
def test_approval_store_refusal_writes_the_name_as_escapes_on_one_line(tmp_path, kind):
    state, blocked = _blocked_approvals(tmp_path, "proxy-" + HIDDEN[kind])
    p = _run(tmp_path, str(state))
    assert p.returncode == serve.EXIT_FAULT, p.stderr[-400:]
    line = _one_safe_line(p.stderr)
    assert f"the approval store at {_written(str(blocked))} could not be made" in line
    assert f"Fix it: make {_written(str(blocked))} a directory you own, chmod 700." in line
    assert NOTE in line


COLLIDING = [
    # a real ESC beside the text \x1b, in either order: one line if a backslash is left alone
    ("proxy-p\x1b\\x1bq", "proxy-p\\x1b\x1bq"),
    ("proxy-a\x1bb", "proxy-a\\x1bb"),
    ("proxy-a͏b", "proxy-a\\xcd\\x8fb"),
]


@pytest.mark.parametrize("pair", COLLIDING, ids=["esc-order", "esc-vs-text", "invisible"])
@pytest.mark.parametrize("blocker", [_blocked_receipts, _blocked_approvals],
                         ids=["receipt-log", "approval-store"])
def test_two_different_names_do_not_print_alike(tmp_path, pair, blocker):
    lines = []
    for n, name in enumerate(pair):
        sub = tmp_path / str(n)
        sub.mkdir()
        state, _ = blocker(sub, name)
        p = _run(sub, str(state))
        assert p.returncode in (1, serve.EXIT_FAULT), p.stderr[-400:]
        lines.append(_one_safe_line(p.stderr).replace(str(sub), "<T>"))
    assert lines[0] != lines[1], lines


def test_a_backslash_and_a_quote_in_a_name_are_escaped_inside_the_delimiters(tmp_path):
    state, blocked = _blocked_receipts(tmp_path, "proxy-it's\\\x1b")
    p = _run(tmp_path, str(state))
    line = _one_safe_line(p.stderr)
    assert _written(str(blocked)) in line
    assert "it\\'s\\\\\\x1b" in line


def test_a_name_that_is_not_text_is_escaped_with_the_note(tmp_path):
    """Bytes that are not UTF-8 reach Python as lone surrogates; the line must still be written."""
    state = str(tmp_path / "user" / "proxy-\udc80\udcff")
    p = _run(tmp_path, state)
    assert p.returncode == 1, p.stderr[-400:]
    line = _one_safe_line(p.stderr)
    assert "the receipt log could not be opened" in line
    assert "proxy-\\x80\\xff" in line
    assert NOTE in line


def test_a_nul_in_the_state_root_is_a_refusal_with_the_note_not_a_traceback(tmp_path):
    p = _run(tmp_path, str(tmp_path / "user" / "proxy-\x00-x"))
    assert p.returncode == 1, p.stderr[-400:]
    line = _one_safe_line(p.stderr)
    assert "the receipt log could not be opened" in line
    assert "proxy-\\x00-x" in line
    assert NOTE in line


# ---------------------------------------------------------------------------
# anything else: shell-quoted everywhere, no note
# ---------------------------------------------------------------------------

def test_receipt_log_refusal_quotes_a_path_with_spaces_at_every_place(tmp_path):
    state, blocked = _blocked_receipts(tmp_path, "my proxy state")
    p = _run(tmp_path, str(state))
    assert p.returncode == 1, p.stderr[-400:]
    line = _one_safe_line(p.stderr)
    assert f"the receipts directory {shlex.quote(str(blocked))} cannot be made" in line
    assert f"{shlex.quote(str(blocked))} is not a directory. Fix it: make {shlex.quote(str(blocked))} " in line
    assert "control or invisible" not in line


def test_approval_store_refusal_quotes_a_path_with_spaces(tmp_path):
    state, blocked = _blocked_approvals(tmp_path, "my proxy state")
    p = _run(tmp_path, str(state))
    assert p.returncode == serve.EXIT_FAULT, p.stderr[-400:]
    line = _one_safe_line(p.stderr)
    assert f"the approval store at {shlex.quote(str(blocked))} could not be made" in line
    assert f"Fix it: make {shlex.quote(str(blocked))} a directory you own, chmod 700." in line
    assert "control or invisible" not in line


def test_a_plain_path_is_named_exactly_as_before(tmp_path):
    state, blocked = _blocked_receipts(tmp_path, "proxy")
    p = _run(tmp_path, str(state))
    assert p.returncode == 1, p.stderr[-400:]
    line = _one_safe_line(p.stderr)
    assert f"Fix it: make {blocked} a directory, chmod 700" in line
    assert "'" not in line and "control or invisible" not in line


# ---------------------------------------------------------------------------
# the helpers
# ---------------------------------------------------------------------------

def test_printable_leaves_text_alone_escapes_the_hidden_and_is_idempotent():
    assert receipts.printable("/a b/ü/é") == "/a b/ü/é"
    once = receipts.printable("a\x1bb\n\x7f\x85 \udc80͏️\U0001f600")
    assert once == ("a\\x1bb\\x0a\\x7f\\xc2\\x85\\xe2\\x80\\xa8\\x80\\xcd\\x8f\\xef\\xb8\\x8f"
                    "\U0001f600")
    assert receipts.printable(once) == once


def test_shown_path_quotes_a_clean_path_and_delimits_a_hidden_one():
    assert receipts.shown_path("/a b") == ("'/a b'", False)
    assert receipts.shown_path("/ab") == ("/ab", False)
    assert receipts.shown_path("/a\x1bb") == (r"$'/a\x1bb'", True)
    assert receipts.shown_path("/a\\x1bb") == (r"'/a\x1bb'", False)
    assert receipts.shown_path("/a͏b") == (r"$'/a\xcd\x8fb'", True)
    assert receipts.shown_path("/it's\x1b") == (r"$'/it\'s\x1b'", True)


SHELLS = [s for s in ("/bin/bash", "/bin/zsh", "/opt/homebrew/bin/bash", "/usr/local/bin/bash")
          if os.path.exists(s)]
ROUND_TRIP = [
    "/a\x1bb", "/a\nb", "/p\x1b\\x1bq", "/it's\\\x1b", "/a b\x7f", "/c1\x85", "/ls ",
    "/cgj͏", "/vs️", "/vs-sup\U000e0100", "/ü\x1bé", "/plain space", "/it's",
    os.fsdecode(b"/raw\x80\xff"), os.fsdecode(b"/mix\x1b\xc3\xa9\x80"),
]


@pytest.mark.skipif(not SHELLS, reason="no bash or zsh to read the notation back")
@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("name", ROUND_TRIP, ids=range(len(ROUND_TRIP)))
def test_what_is_shown_is_what_a_shell_reads_back(shell, name):
    """The shown form, given to bash (3.2 included) or zsh, is the name's own bytes."""
    text, _ = receipts.shown_path(name)
    out = subprocess.run([shell, "-c", f"printf %s {text}"], capture_output=True, timeout=30)
    assert out.returncode == 0, out.stderr
    assert out.stdout == os.fsencode(name)
