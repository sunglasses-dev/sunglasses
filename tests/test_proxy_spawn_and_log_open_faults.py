"""
test_proxy_spawn_and_log_open_faults.py — A SERVER THAT CANNOT START AND A
RECEIPT LOG THAT CANNOT BE OPENED END THE RUN IN THE PROXY'S OWN WORDS.

Two faults end the run with one line on stderr that says what failed and that
nothing was started, exit 1, and no traceback: the server command does not
exist or cannot be run, and the receipts directory exists but cannot be
written. The first also writes the refusal down as the run's ending; the
second raises `ReceiptIOError` from the log, so every caller sees the same
failure type.
"""
import json
import os
import subprocess
import sys

import pytest

from sunglasses.proxy import receipts as proxy_receipts

TREE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

needs_posix_perms = pytest.mark.skipif(
    sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="needs POSIX permissions and a non-root user")


def _serve(tmp_path, upstream):
    state = tmp_path / "state"
    script = ("import sys\nfrom sunglasses.proxy import serve\n"
              f"sys.exit(serve.main(['--state-root', {str(state)!r}, '--', *{upstream!r}]))\n")
    env = {**os.environ, "HOME": str(tmp_path), "SUNGLASSES_HOME": str(tmp_path / "home"),
           "PYTHONPATH": TREE, "PYTHONDONTWRITEBYTECODE": "1"}
    done = subprocess.run([sys.executable, "-c", script], input=b"", cwd=str(tmp_path),
                          env=env, capture_output=True, timeout=60)
    return done, state


def _rows(state):
    rows = []
    for log in sorted((state / "receipts").glob("*.jsonl")):
        rows.extend(json.loads(line) for line in log.read_text().splitlines() if line.strip())
    return rows


def _teardown(rows):
    found = [r for r in rows if r.get("kind") == "SESSION_TORN_DOWN"]
    assert len(found) == 1, rows
    return found[0]


# ── the server command cannot be started ────────────────────────────────────

def test_a_missing_server_command_is_one_refusal_line_not_a_traceback(tmp_path):
    done, state = _serve(tmp_path, [str(tmp_path / "no-such-server")])
    err = done.stderr.decode(errors="replace")
    assert done.returncode == 1, err[-400:]
    assert "Traceback" not in err, err[-400:]
    assert "the server could not be started, so nothing was started" in err, err[-400:]
    assert "FileNotFoundError" in err, err[-400:]
    assert len([line for line in err.splitlines() if line.strip()]) == 1, err


def test_a_missing_server_command_writes_the_refusal_down(tmp_path):
    _, state = _serve(tmp_path, [str(tmp_path / "no-such-server")])
    ending = _teardown(_rows(state))
    assert ending["reason_code"] == "CONFIG_IO_ERROR", ending
    assert ending["rule"] == "S3", ending


def test_a_server_command_that_is_not_executable_is_the_same_refusal(tmp_path):
    plain = tmp_path / "plain-file"
    plain.write_text("not a program\n")
    done, _ = _serve(tmp_path, [str(plain)])
    err = done.stderr.decode(errors="replace")
    assert done.returncode == 1, err[-400:]
    assert "Traceback" not in err, err[-400:]
    assert "the server could not be started, so nothing was started" in err, err[-400:]


# ── the receipts directory exists and cannot be written ─────────────────────

@needs_posix_perms
def test_an_unwritable_receipts_directory_is_a_receipt_io_error(tmp_path):
    state = tmp_path / "state"
    (state / "receipts").mkdir(parents=True)
    (state / "receipts").chmod(0o500)
    try:
        with pytest.raises(proxy_receipts.ReceiptIOError) as raised:
            proxy_receipts.Log(state, run_id="0" * 32, header={"session_id": "r"})
    finally:
        (state / "receipts").chmod(0o700)
    assert "PermissionError" in str(raised.value), raised.value
    assert str(state / "receipts") in str(raised.value), raised.value


@needs_posix_perms
def test_an_unwritable_receipts_directory_stops_the_proxy_in_its_own_words(tmp_path):
    state = tmp_path / "state"
    (state / "receipts").mkdir(parents=True)
    (state / "receipts").chmod(0o500)
    try:
        done, _ = _serve(tmp_path, [sys.executable, "-c", "import sys; sys.stdin.read()"])
    finally:
        (state / "receipts").chmod(0o700)
    err = done.stderr.decode(errors="replace")
    assert done.returncode == 1, err[-400:]
    assert "Traceback" not in err, err[-400:]
    assert "the receipt log could not be opened, so nothing was started" in err, err[-400:]
    assert list((state / "receipts").glob("*")) == []



def test_the_control_a_healthy_run_still_exits_clean(tmp_path):
    done, state = _serve(tmp_path, [sys.executable, "-c", "import sys; sys.stdin.read()"])
    assert done.returncode == 0, done.stderr.decode(errors="replace")[-400:]
    assert _rows(state), "the run wrote no log"
