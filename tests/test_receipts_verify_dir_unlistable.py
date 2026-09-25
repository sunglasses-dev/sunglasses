"""The verifier half of ruling 56, ruled in as T9 ruling 57. `sunglasses receipts --verify`
decided what logs exist with `Path.glob`, which swallows PermissionError, so
a signed log under a directory nobody can list read as NO_LOG, "no receipts",
and without --strict exited 3, the exit of a healthy chain with a limit. An
unlistable key directory read as "no public key", and an unlistable --log as
"not a directory of signed segments": failing, but naming absence as the cause.
And receipts/ itself unlistable died on a raw PermissionError traceback.

R57: each of these is PATH_UNREADABLE, one FAIL code, exit 1 with or without
--strict, printing the path and the OS cause. Never NO_LOG, never exit 3.

Every row runs the REAL command, `python -m sunglasses.cli receipts`, on a
home with a real signed chain; the fixture proves each directory is
unlistable before any row reads it, and skips by name where it cannot (R55).
"""
import ast
import io
import json
import os
import pathlib
import subprocess
import sys

import pytest

from sunglasses.firewall import run_hook
from sunglasses.receipts import keys, optin, verify

TREE = pathlib.Path(__file__).resolve().parents[1]
CALL = json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "echo hello"},
    "session_id": "r57-test",
})

MODES = [pytest.param(0o000, id="mode000"), pytest.param(0o300, id="mode300")]
STRICT = [pytest.param([], id="verify"), pytest.param(["--strict"], id="strict")]


@pytest.fixture
def home(tmp_path):
    """A home that opted in: a key, and one sealed hook call on its chain."""
    home = tmp_path / "sunglasses-home"
    keys.init(home)
    run_hook(CALL, home=home)
    return home


@pytest.fixture
def unlistable():
    made = []

    def make(directory, mode):
        assert directory.is_dir(), directory
        os.chmod(directory, mode)
        made.append(directory)
        try:
            os.listdir(directory)
        except PermissionError:
            return directory
        pytest.skip(f"cannot make an unlistable directory here: os.listdir "
                    f"read {directory} under mode {mode:o} (running as root?)")

    yield make
    for directory in reversed(made):
        os.chmod(directory, 0o700)


def _receipts(home, *argv):
    env = {**os.environ, "SUNGLASSES_HOME": str(home)}
    proc = subprocess.run([sys.executable, "-m", "sunglasses.cli", "receipts", *argv],
                          cwd=TREE, env=env, capture_output=True, text=True)
    return proc.returncode, proc.stdout + proc.stderr


# ── the local logs: a hidden signed log is not "no receipts" ─────────────────

@pytest.mark.parametrize("strict", STRICT)
@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("which", ["hook", "receipts"])
def test_an_unlistable_log_dir_is_never_no_log(home, unlistable, which, mode, strict):
    target = optin.hook_log(home) if which == "hook" else home / "receipts"
    unlistable(target, mode)
    rc, out = _receipts(home, "--verify", *strict)
    assert "NO_LOG" not in out and "no receipts" not in out, out[-400:]
    assert "Traceback" not in out, out[-400:]
    assert "PATH_UNREADABLE" in out and str(target) in out, out[-400:]
    assert "cannot be listed (PermissionError)" in out, out[-400:]
    assert rc == 1, (rc, out[-400:])


@pytest.mark.parametrize("strict", STRICT)
def test_an_unlistable_public_key_dir_is_not_a_missing_key(home, unlistable, strict):
    public = home / keys.KEY_DIR / keys.PUBLIC_DIR
    unlistable(public, 0o000)
    rc, out = _receipts(home, "--verify", *strict)
    assert "no public key" not in out, out[-400:]
    assert "PATH_UNREADABLE" in out and str(public) in out, out[-400:]
    assert "PermissionError" in out, out[-400:]
    assert rc == 1, (rc, out[-400:])


# ── a received log (--log): unlistable is not "not a log" ────────────────────

@pytest.mark.parametrize("mode", MODES)
def test_an_unlistable_received_log_names_the_cause(home, unlistable, mode):
    log = optin.hook_log(home)
    unlistable(log, mode)
    rc, out = _receipts(home, "--verify", "--log", str(log))
    assert "not a directory of signed segments" not in out, out[-400:]
    assert "PATH_UNREADABLE" in out and "PermissionError" in out, out[-400:]
    assert rc == 1, (rc, out[-400:])


def test_verify_log_raises_on_an_unlistable_directory(home, unlistable):
    """verify.py:378: an unlistable directory is not "no segment in this log"."""
    public = next(iter(sorted(os.listdir(home / keys.KEY_DIR / keys.PUBLIC_DIR))))
    key = (home / keys.KEY_DIR / keys.PUBLIC_DIR / public).read_bytes()
    unlistable(optin.hook_log(home), 0o000)
    with pytest.raises(OSError) as raised:
        verify.verify_log(optin.hook_log(home), key)
    assert "cannot be listed" in str(raised.value), raised.value


# ── structural: no listing left on Path.glob in the verifier ─────────────────

VERIFIER_FUNCTIONS = ("_chain_logs", "_log_chain_ids", "_verify_received",
                      "_receipt_public_key", "cmd_receipts")


def _glob_calls(tree):
    return [call.lineno for call in ast.walk(tree)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
            and call.func.attr in ("glob", "rglob", "iglob")]


def test_no_verifier_path_lists_a_directory_with_glob():
    cli = ast.parse((TREE / "sunglasses/cli.py").read_text())
    functions = {node.name: node for node in ast.walk(cli)
                 if isinstance(node, ast.FunctionDef)}
    missing = set(VERIFIER_FUNCTIONS) - set(functions)
    assert missing == set(), f"renamed, so this reads nothing: {missing}"
    found = [f"cli.py:{line}" for name in VERIFIER_FUNCTIONS
             for line in _glob_calls(functions[name])]
    found += [f"verify.py:{line}" for line in
              _glob_calls(ast.parse((TREE / "sunglasses/receipts/verify.py").read_text()))]
    assert found == [], found


def test_the_structural_reader_sees_a_glob_call():
    tree = ast.parse("# p.glob('x')\ndef f(p):\n    return p.glob('*.chain')\n")
    assert _glob_calls(tree) == [3]


# ── controls: a healthy log is unchanged on the R48 table, absent is NO_LOG ──

@pytest.mark.parametrize("strict", STRICT)
def test_the_control_a_healthy_log_is_unchanged_on_the_r48_table(home, strict):
    """CHAIN_OK with the two limits a plain `--verify` carries (no
    fingerprint, no retained endpoint): exit 3, and 1 under --strict."""
    rc, out = _receipts(home, "--verify", *strict)
    assert "CHAIN_OK" in out and "KEY_UNTRUSTED" in out, out[-400:]
    assert "HISTORY_EXTENT_UNKNOWN" in out and "PATH_UNREADABLE" not in out, out[-400:]
    assert rc == (1 if strict else 3), (rc, out[-400:])


def test_the_control_an_absent_home_is_no_log(tmp_path):
    rc, out = _receipts(tmp_path / "never", "--verify")
    assert "NO_LOG" in out and "PATH_UNREADABLE" not in out, out[-400:]
    assert rc == 3, (rc, out[-400:])
