"""The README block on how the proxy stops is present and carries the qualified limits.

These tests read text. They check that the block exists once, that each limit has its identifying
phrases, that the closed-stdin outcome keeps both of its conditions, and that none of a short list of
words is in the block. They do not check that the prose is true: the statements were measured with a
real proxy and a real server (see the pull request), and a sentence can be edited into something false
without failing here.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
HEADING = "### Known limits when the proxy is stopped"
BANNED = ("bounded", "exactly", "always", "guaranteed", "guarantee")


def _block():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert text.count(HEADING) == 1
    rest = text.split(HEADING, 1)[1]
    return re.split(r"\n#{1,3} ", rest, maxsplit=1)[0]


def _flat():
    return " ".join(_block().split())


def test_the_block_names_the_signal_limit():
    block = _flat()
    assert "SIGTERM" in block and "SIGHUP" in block
    assert "do not stop the server" in block


def test_the_block_names_the_ctrl_c_ending():
    block = _flat()
    assert "Ctrl-C" in block and "SIGINT" in block
    assert "Fatal Python error" in block


def test_the_closed_stdin_outcome_keeps_its_conditions():
    block = _flat()
    assert "While the server is reading its input" in block
    assert "between messages ends the proxy with exit status 0" in block
    assert "in the middle of a message ends the proxy with exit status 1" in block


def test_the_block_names_the_server_that_stopped_reading():
    block = _flat()
    assert "stopped reading" in block
    assert "neither closing stdin nor Ctrl-C ends it" in block
    assert "do not rely on closing stdin or on Ctrl-C" in block


def test_the_block_makes_no_guarantee():
    block = _block().lower()
    for word in BANNED:
        assert word not in block, word


def test_the_doctor_page_points_at_the_block():
    page = (ROOT / "docs" / "proxy-doctor.md").read_text(encoding="utf-8")
    assert "#known-limits-when-the-proxy-is-stopped" in page
