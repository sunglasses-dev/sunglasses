"""The README names the proxy's stop-time limits, and says nothing stronger than was measured.

The block is documentation of behaviour the proxy has today. This test pins that the block exists, that it
names each limit, and that it does not use words that would turn a limit into a promise. It does not test
the proxy; the behaviour was measured with a real proxy and a real server (see the pull request).
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
HEADING = "### Known limits when the proxy is stopped"


def _block():
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert text.count(HEADING) == 1
    rest = text.split(HEADING, 1)[1]
    return re.split(r"\n#{1,3} ", rest, maxsplit=1)[0]


def test_the_block_names_the_signal_limit():
    block = _block()
    assert "SIGTERM" in block and "SIGHUP" in block
    assert "do not stop the server" in block


def test_the_block_names_the_ctrl_c_ending():
    block = _block()
    assert "Ctrl-C" in block and "SIGINT" in block
    assert "Fatal Python error" in block


def test_the_block_names_the_server_that_stopped_reading():
    block = _block()
    assert "stopped reading" in block
    assert "closing stdin" in block


def test_the_block_makes_no_guarantee():
    block = _block().lower()
    for word in ("bounded", "exactly", "always", "guaranteed", "guarantee"):
        assert word not in block, word


def test_the_doctor_page_points_at_the_block():
    page = (ROOT / "docs" / "proxy-doctor.md").read_text(encoding="utf-8")
    assert "#known-limits-when-the-proxy-is-stopped" in page
