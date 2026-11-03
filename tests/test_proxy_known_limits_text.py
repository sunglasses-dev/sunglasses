"""The README block on how the proxy stops is present and has the three limits it states.

These tests pin text. They check that the block exists once, that each limit keeps its identifying
phrases, that none of a short list of words is in the block, and that the doctor page points at it.
They do not check that the prose is true: a sentence can be edited into something false without
failing here. What the sentences say was run with a real proxy and a real server (see the pull request).
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
HEADING = "### Known limits when the proxy is stopped"
BANNED = ("bounded", "exactly", "always", "guaranteed", "guarantee", "cleanly", "certif")


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
    assert "do not stop the server it started" in block


def test_the_block_names_the_ctrl_c_limit():
    block = _flat()
    assert "Ctrl-C (SIGINT)" in block
    assert "Fatal Python error" in block
    assert "status -6" in block and "134 in a shell" in block


def test_the_block_names_the_server_that_stopped_reading():
    block = _flat()
    assert "stopped reading" in block
    assert "170,870-byte message" in block
    assert "do not rely on closing stdin or on Ctrl-C" in block


def test_the_block_lists_what_was_not_measured():
    block = _flat()
    assert "Not measured:" in block
    assert "Python 3.10 and 3.11" in block


def test_the_block_uses_none_of_the_banned_words():
    block = _block().lower()
    for word in BANNED:
        assert word not in block, word


def test_the_doctor_page_points_at_the_block():
    page = (ROOT / "docs" / "proxy-doctor.md").read_text(encoding="utf-8")
    assert "#known-limits-when-the-proxy-is-stopped" in page
