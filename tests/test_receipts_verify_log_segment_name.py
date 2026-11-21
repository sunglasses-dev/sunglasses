"""A segment of a received log is a file, and its name is chosen by whoever made the
log. `sunglasses receipts --verify --log` printed that name raw in the `first failure:`
line and in each `-- name` header, so a segment named with a terminal escape sequence,
a bidi control and a newline reached the terminal as those characters (it could clear
the screen, hide the line that follows, or forge a line of its own).

The name is now written as one line of text, the way every other name in a receipt
diagnostic is (`receipts._shown.shown_name`). The data is not touched: the report still
holds the exact name. Every row runs the REAL command on a home with a real signed chain.
"""
import os
import pathlib
import subprocess
import sys

import pytest

from sunglasses.firewall import run_hook
from sunglasses.receipts import keys, optin

TREE = pathlib.Path(__file__).resolve().parents[1]
CALL = ('{"hook_event_name": "PreToolUse", "tool_name": "Bash", '
        '"tool_input": {"command": "echo hello"}, "session_id": "c895-test"}')
# CSI clear-screen, a right-to-left override, a newline and a line of its own.
HOSTILE = "segment-000001\x1b[2J‮evil\nforged line: all clear.chain"


@pytest.fixture
def home(tmp_path):
    home = tmp_path / "sunglasses-home"
    keys.init(home)
    run_hook(CALL, home=home)
    return home


def _hostile_log(home, tmp_path, tamper):
    """A copy of the home's real hook log whose only segment carries HOSTILE as its
    name; `tamper` flips a byte so the chain fails and names that segment."""
    (segment,) = sorted(optin.hook_log(home).glob("segment-*.chain"))
    data = bytearray(segment.read_bytes())
    if tamper:
        data[len(data) // 2] ^= 0x01
    log = tmp_path / "received"
    log.mkdir()
    (log / HOSTILE).write_bytes(bytes(data))
    return log


def _receipts(home, *argv):
    env = {**os.environ, "SUNGLASSES_HOME": str(home), "HOME": str(home.parent / "user")}
    proc = subprocess.run([sys.executable, "-m", "sunglasses.cli", "receipts", *argv],
                          cwd=TREE, env=env, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


def _verify_log(home, log):
    (public,) = sorted((home / keys.KEY_DIR / keys.PUBLIC_DIR).glob("*.pub"))
    return _receipts(home, "--verify", "--log", str(log), "--public-key", str(public))


def _no_raw_control(text):
    return not any(ch in text for ch in ("\x1b", "‮", "\r", "\x00", "\x07"))


@pytest.mark.parametrize("tamper", [False, True], ids=["intact", "tampered"])
def test_a_segment_name_reaches_the_terminal_as_text(home, tmp_path, tamper):
    log = _hostile_log(home, tmp_path, tamper)
    rc, out = _verify_log(home, log)
    assert "Traceback" not in out, out[-400:]
    assert _no_raw_control(out), repr(out[:400])
    # the name is one quoted line: no line of the output is the forged one
    assert not any(line.startswith("forged line") for line in out.splitlines()), out
    assert "\\x1b[2J\\u202eevil\\x0aforged line: all clear.chain" in out, out[-600:]
    header = [line for line in out.splitlines() if line.startswith("-- ")]
    assert len(header) == 1 and header[0].startswith("-- '"), header


def test_the_first_failure_line_names_the_segment_as_text(home, tmp_path):
    log = _hostile_log(home, tmp_path, tamper=True)
    rc, out = _verify_log(home, log)
    lines = [line for line in out.splitlines() if line.startswith("first failure: '")]
    assert len(lines) == 1, out[-600:]
    assert lines[0].startswith("first failure: '") and "\\x1b" in lines[0], lines[0]


def test_a_plain_segment_name_prints_unchanged(home, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    (segment,) = sorted(optin.hook_log(home).glob("segment-*.chain"))
    (plain / "segment-000001.chain").write_bytes(segment.read_bytes())
    rc, out = _verify_log(home, plain)
    assert "\n-- segment-000001.chain\n" in out, out[-400:]
