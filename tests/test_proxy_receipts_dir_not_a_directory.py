"""
test_proxy_receipts_dir_not_a_directory.py — THE PROXY NAMES WHAT STANDS WHERE
ITS RECEIPTS DIRECTORY BELONGS (T9 ruling 63 (b)).

The proxy makes `<state root>/receipts` before anything else. When a regular
file, a dangling symlink or a symlink to a file stands at that path, or at the
state root, or above it, `mkdir` raised FileExistsError or NotADirectoryError
straight out of `serve.main`: exit 1 with a traceback and no cause named. It
now stops like every other receipt failure, rc 1, naming the thing in the way,
and nothing is written, signed or unsigned. The home is healthy throughout, so
this is the proxy's own state tree, not an obstructed home (row AB).
"""
import json
import os
import subprocess
import sys

import pytest

from sunglasses.proxy import receipts as proxy_receipts
from sunglasses.receipts import keys

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPSTREAM = [sys.executable, "-c", "import sys; sys.stdin.read()"]

# where the obstruction goes, relative to the state root S:
#   receipts-*   at S/receipts
#   state-file   S itself is a file
#   above-file   a file above S
PLACES = ["receipts-file", "receipts-dangling", "receipts-link-file",
          "state-file", "above-file"]


def _home(tmp_path, opted):
    home = tmp_path / "sunglasses-home"
    home.mkdir()
    if opted:
        keys.init(home)
    return home


def _obstruct(tmp_path, place):
    """Returns (state root, the path that is in the way)."""
    base = tmp_path / "user"
    base.mkdir()
    state = base / "proxy"
    if place.startswith("receipts-"):
        state.mkdir()
        at = state / "receipts"
        if place == "receipts-file":
            at.write_text("not a directory\n")
        elif place == "receipts-dangling":
            at.symlink_to(tmp_path / "nowhere")
        else:
            (tmp_path / "afile").write_text("a file\n")
            at.symlink_to(tmp_path / "afile")
        blocked = at
    elif place == "state-file":
        state.write_text("not a directory\n")
        blocked = state
    else:
        blocked = base / "above"
        blocked.write_text("not a directory\n")
        state = blocked / "deeper" / "proxy"
    assert not os.path.isdir(blocked), blocked
    return state, blocked


def _written(tmp_path):
    return sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*")
                  if p.name.endswith((".jsonl", ".chain")) and "sunglasses-home" not in p.parts)


def _serve(tmp_path, home, state):
    script = ("import sys\nfrom sunglasses.proxy import serve\n"
              f"sys.exit(serve.main(['--state-root', {str(state)!r}, '--', *{UPSTREAM!r}]))\n")
    env = {**os.environ, "HOME": str(tmp_path / "user"), "SUNGLASSES_HOME": str(home),
           "PYTHONPATH": TREE, "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run([sys.executable, "-c", script], input=b"", cwd=str(tmp_path),
                          env=env, capture_output=True, timeout=60)


@pytest.mark.parametrize("opted", [False, True], ids=["never", "opted"])
@pytest.mark.parametrize("place", PLACES)
def test_the_log_refuses_by_name_and_writes_nothing(tmp_path, place, opted):
    home = _home(tmp_path, opted)
    state, blocked = _obstruct(tmp_path, place)
    with pytest.raises(proxy_receipts.ReceiptIOError) as raised:
        proxy_receipts.Log(state, run_id="0" * 32, header={"session_id": "r"}, home=home)
    assert str(blocked) in str(raised.value), raised.value
    assert "not a directory" in str(raised.value), raised.value
    assert _written(tmp_path) == []


@pytest.mark.parametrize("opted", [False, True], ids=["never", "opted"])
@pytest.mark.parametrize("place", PLACES)
def test_the_proxy_stops_rc_1_naming_it_with_no_traceback(tmp_path, place, opted):
    home = _home(tmp_path, opted)
    state, blocked = _obstruct(tmp_path, place)
    p = _serve(tmp_path, home, state)
    err = p.stderr.decode(errors="replace")
    assert p.returncode == 1, err[-400:]
    assert "Traceback" not in err, err[-400:]
    assert "the receipt log could not be opened" in err, err[-400:]
    assert str(blocked) in err, err[-400:]
    assert _written(tmp_path) == []


@pytest.mark.parametrize("opted", [False, True], ids=["never", "opted"])
def test_the_control_a_healthy_state_root_runs_and_logs(tmp_path, opted):
    home = _home(tmp_path, opted)
    (tmp_path / "user").mkdir()
    state = tmp_path / "user" / "proxy"          # absent, under a listable dir
    p = _serve(tmp_path, home, state)
    assert p.returncode == 0, p.stderr.decode(errors="replace")[-400:]
    written = _written(tmp_path)
    assert written, "the run wrote no log"
    assert all(w.endswith(".chain") for w in written) is opted, written


def test_the_control_receipts_behind_a_symlink_to_a_directory_runs(tmp_path):
    home = _home(tmp_path, False)
    state = tmp_path / "user" / "proxy"
    state.mkdir(parents=True)
    (tmp_path / "real-receipts").mkdir()
    (state / "receipts").symlink_to(tmp_path / "real-receipts")
    p = _serve(tmp_path, home, state)
    assert p.returncode == 0, p.stderr.decode(errors="replace")[-400:]
    assert len(list((tmp_path / "real-receipts").glob("*.jsonl"))) == 1
