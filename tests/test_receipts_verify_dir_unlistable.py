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
import uuid

import pytest

from sunglasses.firewall import run_hook
from sunglasses.proxy import receipts as proxy_receipts
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


def _proxy_root(home):
    """The proxy's default state root, ~/.sunglasses/proxy, under the HOME a
    row gives its child: a row never reads the user's own proxy logs."""
    return home.parent / "user" / ".sunglasses" / "proxy"


def _receipts(home, *argv):
    env = {**os.environ, "SUNGLASSES_HOME": str(home), "HOME": str(home.parent / "user")}
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

VERIFIER_MODULES = ("sunglasses/cli.py", "sunglasses/receipts/verify.py")


def _glob_calls(tree):
    return [call.lineno for call in ast.walk(tree)
            if isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
            and call.func.attr in ("glob", "rglob", "iglob")]


def test_no_verifier_path_lists_a_directory_with_glob():
    """R58 (2): the whole of cli.py and verify.py, not a list of functions. A
    function list was the gap: a verifier helper added or renamed outside it
    was never read."""
    found = [f"{name}:{line}" for name in VERIFIER_MODULES
             for line in _glob_calls(ast.parse((TREE / name).read_text()))]
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


# ── R58: a log's own path in the wrong shape is not "no log" ────────────────

@pytest.fixture
def proxy_run(home):
    """A proxy run's signed chain, by the proxy's own writer, at the state
    root the verifier reads, closed the way serve closes one: a session with
    no terminal is LIFECYCLE_ORPHAN, a FAIL, and no healthy control. The run
    id is the one serve gives a run, written here from uuid itself, not from
    the rule under test."""
    log = proxy_receipts.Log(_proxy_root(home), run_id=uuid.uuid4().hex,
                             header={"session_id": "r58-test"}, home=home)
    log.event("SESSION_TORN_DOWN", reason_code=None, rule=None, settled=True)
    log.close()
    assert any(n.startswith("segment-") for n in os.listdir(log.path)), log.path
    return log.path


SHAPES = ["file", "dangling_symlink", "symlink_to_file"]


def _wrong_shape(log, shape, outside):
    """Put `shape` where a log's directory stands. Its signed segments and any
    link target go OUTSIDE both receipts/ directories: left beside it the
    segments would be a second log that verifies, and the row would read that
    instead. The stimulus is proven: the log's receipts/ then holds the one
    entry, the log's own name."""
    outside.mkdir(exist_ok=True)
    log.rename(outside / "moved")
    if shape == "file":
        log.write_bytes(b"not a directory\n")
    elif shape == "dangling_symlink":
        log.symlink_to(outside / "nowhere")
    else:
        target = outside / "a-file"
        target.write_bytes(b"a file\n")
        log.symlink_to(target)
    assert os.path.lexists(log) and not log.is_dir(), shape
    assert sorted(p.name for p in log.parent.iterdir()) == [log.name], shape
    return log


def _path_unreadable(rc, out, log):
    assert "NO_LOG" not in out and "no receipts" not in out, out[-400:]
    assert "Traceback" not in out, out[-400:]
    assert "PATH_UNREADABLE" in out and str(log) in out, out[-400:]
    assert rc == 1, (rc, out[-400:])


@pytest.mark.parametrize("strict", STRICT)
@pytest.mark.parametrize("shape", SHAPES)
def test_the_hook_log_path_in_the_wrong_shape_is_path_unreadable(home, tmp_path, shape, strict):
    log = _wrong_shape(optin.hook_log(home), shape, tmp_path / "outside")
    _path_unreadable(*_receipts(home, "--verify", *strict), log)


@pytest.mark.parametrize("strict", STRICT)
@pytest.mark.parametrize("shape", SHAPES)
def test_a_proxy_run_log_in_the_wrong_shape_is_path_unreadable(home, proxy_run, tmp_path,
                                                               shape, strict):
    """The hook's log still verifies here, so the gap read "CHAIN_OK" on a
    home that lost a run's log: the run's name says it is a log (R58)."""
    log = _wrong_shape(proxy_run, shape, tmp_path / "outside")
    _path_unreadable(*_receipts(home, "--verify", *strict), log)


@pytest.mark.parametrize("shape", SHAPES)
def test_a_log_named_with_log_in_the_wrong_shape_is_path_unreadable(home, tmp_path, shape):
    log = _wrong_shape(optin.hook_log(home), shape, tmp_path / "outside")
    rc, out = _receipts(home, "--verify", "--log", str(log))
    assert "not a directory of signed segments" not in out, out[-400:]
    _path_unreadable(rc, out, log)


def test_the_writer_and_the_verifier_name_a_run_log_by_one_rule():
    """R58: the rule is written once, in the proxy's receipts module. serve
    names each run with it and the verifier reads the proxy's logs by it."""
    names = {proxy_receipts.new_run_id() for _ in range(64)}
    assert len(names) == 64 and all(map(proxy_receipts.is_run_log_name, names))
    for name in ("ab" * 16 + ".jsonl", "AB" * 16, "ab" * 15, "ab" * 17,
                 "ab" * 16 + "\n", "notes.txt", "hook"):
        assert not proxy_receipts.is_run_log_name(name), name

    def names_used(module):
        tree = ast.parse((TREE / module).read_text())
        return {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert {"new_run_id"} <= names_used("sunglasses/proxy/serve.py")
    assert "uuid4" not in names_used("sunglasses/proxy/serve.py")
    assert {"is_run_log_name"} <= names_used("sunglasses/cli.py")


# ── R58 controls: a healthy run is read, what is not a log is passed over ───

@pytest.mark.parametrize("strict", STRICT)
def test_the_control_a_healthy_proxy_run_is_read_beside_the_hook_log(home, proxy_run, strict):
    rc, out = _receipts(home, "--verify", *strict)
    assert "CHAIN_OK" in out and "PATH_UNREADABLE" not in out, out[-400:]
    assert out.count("segment(s)") == 2, out[-600:]
    assert rc == (1 if strict else 3), (rc, out[-400:])


@pytest.mark.parametrize("strict", STRICT)
def test_the_control_a_stray_file_under_receipts_is_still_ignored(home, strict):
    """Only a log's own name is held to R58. A file beside the hook's log that
    is no log at all is not a log, so the healthy chain reads as before."""
    (home / "receipts" / "notes.txt").write_bytes(b"not a log\n")
    rc, out = _receipts(home, "--verify", *strict)
    assert "CHAIN_OK" in out and "PATH_UNREADABLE" not in out, out[-400:]
    assert "notes.txt" not in out, out[-400:]
    assert rc == (1 if strict else 3), (rc, out[-400:])


STRAYS = [pytest.param("notes.txt", "file", id="notes_txt"),
          pytest.param("ab" * 16 + ".jsonl", "file", id="unchained_run_jsonl"),
          pytest.param("AB" * 16, "file", id="uppercase_hex_file"),
          pytest.param("ab" * 15, "file", id="short_hex_file"),
          pytest.param("junk", "dir", id="non_hex_empty_dir")]


@pytest.mark.parametrize("strict", STRICT)
@pytest.mark.parametrize("name, kind", STRAYS)
def test_the_control_a_stray_under_the_proxy_receipts_is_still_ignored(home, proxy_run,
                                                                      name, kind, strict):
    """A run's unchained `<run id>.jsonl` reads exactly as at 44e1dae7, and a
    name that is not a run id is not a log: the two healthy logs read."""
    stray = proxy_run.parent / name
    stray.mkdir() if kind == "dir" else stray.write_bytes(b"not a log\n")
    rc, out = _receipts(home, "--verify", *strict)
    assert "CHAIN_OK" in out and "PATH_UNREADABLE" not in out, out[-400:]
    assert name not in out and out.count("segment(s)") == 2, out[-600:]
    assert rc == (1 if strict else 3), (rc, out[-400:])
