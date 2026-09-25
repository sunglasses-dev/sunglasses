"""ASTRA receipts172-ef0463b r3, item 3, and T9 ruling 56. A directory nobody
can list is not an empty directory.

The opt-in decision found the hook chain's segments with `Path.glob`, and
`Path.glob` swallows the directory scan's OSError, PermissionError included,
and answers []. So with the key deleted, no `receipts off`, and the hook chain
directory unlistable, "opted in" read False and the hook fell to the legacy
unsigned writer: a signed log turning unsigned by itself, which ruling 21
forbids. The key directory had the same hole one step earlier.

R56 fixes the class: one helper, `receipts._fs.listing`, answers [] for a
directory that is not there and raises `Unlistable` for one that is there and
cannot be listed, and every presence decision in the receipts paths asks it.
The hook rows run the REAL entry point, `python -m sunglasses.firewall`: a
decision on stdout and exit 0.
"""
import io
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tokenize

import pytest

from sunglasses.firewall import run_hook
from sunglasses.proxy import doctor
from sunglasses.proxy import receipts as proxy_receipts
from sunglasses.receipts import keys, optin

TREE = pathlib.Path(__file__).resolve().parents[1]
CALL = json.dumps({
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {"command": "echo hello"},
    "session_id": "r56-test",
})

# 000: nothing. 0o300: the directory can be entered and written, not listed.
MODES = [pytest.param(0o000, id="mode000"), pytest.param(0o300, id="mode300")]


@pytest.fixture
def home(tmp_path):
    """A home that opted in: a key, and one sealed hook call on its chain."""
    home = tmp_path / "sunglasses-home"
    keys.init(home)
    run_hook(CALL, home=home)
    return home


@pytest.fixture
def unlistable():
    """Makes a directory unlistable, and PROVES it before any row reads it: a
    row that ran on a directory it could still list would pass for the wrong
    reason. Where it cannot make one it skips by name (R55: a skip on the
    development Mac is a defect, and the run reports the count)."""
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
    for directory in made:
        os.chmod(directory, 0o700)


def _legacy(home):
    return sorted((home / "receipts").glob("*.jsonl"))


def _hook(home):
    env = {**os.environ, "SUNGLASSES_HOME": str(home)}
    proc = subprocess.run([sys.executable, "-m", "sunglasses.firewall"],
                          input=CALL, cwd=TREE, env=env,
                          capture_output=True, text=True)
    assert proc.returncode == 0, (proc.returncode, proc.stderr[-400:])
    return json.loads(proc.stdout)


def _decision(out):
    spec = out.get("hookSpecificOutput", {})
    return spec.get("permissionDecision"), spec.get("permissionDecisionReason", "")


# ── the ASTRA sequence, at the real entry point ──────────────────────────────

@pytest.mark.parametrize("mode", MODES)
def test_a_deleted_key_under_an_unlistable_chain_dir_asks_and_writes_nothing_unsigned(
        home, unlistable, mode):
    keys.private_path(home).unlink()
    unlistable(optin.hook_log(home), mode)
    kind, reason = _decision(_hook(home))
    assert kind == "ask", reason
    assert "cannot be listed" in reason, reason
    assert _legacy(home) == [], "a signed log never turns unsigned by itself"


@pytest.mark.parametrize("mode", MODES)
def test_an_unlistable_chain_dir_is_never_not_opted_in(home, unlistable, mode):
    keys.private_path(home).unlink()
    unlistable(optin.hook_log(home), mode)
    with pytest.raises(OSError) as raised:
        optin.opted_in(home)
    assert type(raised.value).__name__ == "Unlistable", raised.value


# ── the key directory: KEY_UNUSABLE naming the cause, never "no key" ─────────

@pytest.mark.parametrize("mode", MODES)
def test_an_unlistable_key_dir_before_any_chain_asks_key_unusable(
        tmp_path, unlistable, mode):
    """`receipts init` and no call yet: the key is the only opt-in there is."""
    home = tmp_path / "fresh"
    keys.init(home)
    unlistable(home / optin.KEY_DIR, mode)
    kind, reason = _decision(_hook(home))
    assert kind == "ask", reason
    assert "KEY_UNUSABLE" in reason and "cannot be listed" in reason, reason
    assert _legacy(home) == []


def test_the_signer_names_an_unlistable_key_dir(home, unlistable):
    unlistable(home / optin.KEY_DIR, 0o000)
    with pytest.raises(optin.KeyUnusable) as raised:
        optin.signer(home)
    assert "cannot be listed" in str(raised.value), raised.value


def test_the_doctor_says_key_unusable_for_an_unlistable_key_dir(tmp_path, unlistable):
    home = tmp_path / "fresh"
    keys.init(home)
    unlistable(home / optin.KEY_DIR, 0o000)
    status, cause = doctor.receipts_key_status(home)
    assert status == "KEY_UNUSABLE" and "cannot be listed" in cause, (status, cause)


def _chain_bytes(home):
    return {p.name: p.read_bytes() for p in sorted(optin.hook_log(home).iterdir())}


def test_receipts_off_on_an_unlistable_key_dir_refuses_by_name(home, unlistable):
    """T10's escape review: `receipts off` caught OSError and ValueError, and
    KeyUnusable is neither, so it died on a raw traceback. At 42a5bfd the same
    case said "Signing is off", appended an UNSIGNED off row and left the key
    unretired. It refuses, names the cause, and changes nothing."""
    before = _chain_bytes(home)
    key = keys.private_path(home)
    unlistable(home / optin.KEY_DIR, 0o000)
    env = {**os.environ, "SUNGLASSES_HOME": str(home)}
    proc = subprocess.run([sys.executable, "-m", "sunglasses.cli", "receipts", "off"],
                          cwd=TREE, env=env, capture_output=True, text=True)
    out = proc.stdout + proc.stderr
    os.chmod(home / optin.KEY_DIR, 0o700)
    assert proc.returncode == 1, (proc.returncode, out[-400:])
    assert "Traceback" not in out and "cannot be listed" in out, out[-400:]
    assert "Signing is off" not in out, out[-400:]
    assert _chain_bytes(home) == before, "no off row, signed or unsigned"
    assert key.exists(), "the key was not retired"
    assert not (home / optin.KEY_DIR / optin.RETIRED_DIR).exists()


# ── the proxy: no receipt, no mediation, and never an unsigned jsonl ─────────

@pytest.mark.parametrize("which", ["chain", "keys"])
def test_the_proxy_log_refuses_to_open_unsigned(home, unlistable, tmp_path, which):
    if which == "chain":
        keys.private_path(home).unlink()
        unlistable(optin.hook_log(home), 0o000)
    else:
        unlistable(home / optin.KEY_DIR, 0o000)
    root = tmp_path / "state"
    with pytest.raises(proxy_receipts.ReceiptIOError) as raised:
        proxy_receipts.Log(root, run_id="run", header={"session_id": "r"}, home=home)
    assert "cannot be listed" in str(raised.value), raised.value
    assert list(root.rglob("*.jsonl")) == []


# ── R57: something at the chain path that is not a listable directory ──────

NOT_A_DIR = ["file", "dangling_symlink", "symlink_to_file"]


def _replace_chain_dir(home, kind):
    """The key deleted, and where the hook chain directory was, one of the
    things ruling 57 names as there-but-not-listable."""
    keys.private_path(home).unlink()
    chain_dir = optin.hook_log(home)
    shutil.rmtree(chain_dir)
    if kind == "file":
        chain_dir.write_text("")
    elif kind == "dangling_symlink":
        chain_dir.symlink_to(chain_dir.parent / "gone")
    else:
        (chain_dir.parent / "a-file").write_text("")
        chain_dir.symlink_to(chain_dir.parent / "a-file")
    assert os.path.lexists(chain_dir) and not chain_dir.is_dir(), kind
    return chain_dir


@pytest.mark.parametrize("kind", NOT_A_DIR)
def test_a_non_directory_at_the_chain_path_asks_and_writes_nothing_unsigned(home, kind):
    _replace_chain_dir(home, kind)
    kind_, reason = _decision(_hook(home))
    assert kind_ == "ask", reason
    assert "cannot be listed" in reason, reason
    assert _legacy(home) == [], "a signed log never turns unsigned by itself"


@pytest.mark.parametrize("kind", NOT_A_DIR)
def test_a_non_directory_at_the_chain_path_stops_the_proxy_log(home, tmp_path, kind):
    _replace_chain_dir(home, kind)
    root = tmp_path / "state"
    with pytest.raises(proxy_receipts.ReceiptIOError) as raised:
        proxy_receipts.Log(root, run_id="run", header={"session_id": "r"}, home=home)
    assert "cannot be listed" in str(raised.value), raised.value
    assert list(root.rglob("*.jsonl")) == []


# ── the helper's contract ────────────────────────────────────────────────────

def test_listing_absent_listable_and_unlistable(tmp_path, unlistable):
    from sunglasses.receipts import _fs
    assert _fs.listing(tmp_path / "absent", "*.x") == []
    there = tmp_path / "there"
    there.mkdir()
    for name in ("b.x", "a.x", "c.y"):
        (there / name).write_text("")
    assert _fs.listing(there, "*.x") == [there / "a.x", there / "b.x"]
    unlistable(there, 0o000)
    with pytest.raises(_fs.Unlistable) as raised:
        _fs.listing(there, "*.x")
    assert raised.value.directory == there
    assert isinstance(raised.value.cause, PermissionError)


def test_listing_draws_absent_at_the_directory_entry(tmp_path):
    """R57: only NO entry is absent; a file or a symlink in the directory's
    place is there. A missing or non-directory PARENT means no entry."""
    from sunglasses.receipts import _fs
    a_file = tmp_path / "a-file"
    a_file.write_text("")
    assert _fs.listing(tmp_path / "no" / "parent", "*") == []
    assert _fs.listing(a_file / "under-a-file", "*") == []
    dangling = tmp_path / "dangling"
    dangling.symlink_to(tmp_path / "gone")
    to_file = tmp_path / "to-file"
    to_file.symlink_to(a_file)
    to_dir = tmp_path / "to-dir"
    (tmp_path / "real").mkdir()
    (tmp_path / "real" / "x.chain").write_text("")
    to_dir.symlink_to(tmp_path / "real")
    for there in (a_file, dangling, to_file):
        with pytest.raises(_fs.Unlistable) as raised:
            _fs.listing(there, "*")
        assert raised.value.directory == there, there
    assert _fs.listing(to_dir, "*.chain") == [to_dir / "x.chain"]


# ── structural: no presence decision left on Path.glob ───────────────────────

PRESENCE_MODULES = ("sunglasses/receipts/optin.py", "sunglasses/receipts/keys.py",
                    "sunglasses/receipts/chain.py", "sunglasses/firewall.py",
                    "sunglasses/proxy/receipts.py", "sunglasses/proxy/doctor.py")


def _glob_calls(path, label=None):
    """Every `.glob(`, `.rglob(` and `.iglob(` in the CODE, read by the
    tokenizer so a comment or a docstring that names them is not a call."""
    tokens = [t for t in tokenize.generate_tokens(io.StringIO(path.read_text()).readline)
              if t.type not in (tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE)]
    label = label or path.relative_to(TREE)
    return [f"{label}:{tokens[i].start[0]}"
            for i in range(1, len(tokens) - 1)
            if tokens[i].string in ("glob", "rglob", "iglob")
            and tokens[i - 1].string == "." and tokens[i + 1].string == "("]


def test_no_presence_module_lists_a_directory_with_glob():
    found = [hit for name in PRESENCE_MODULES for hit in _glob_calls(TREE / name)]
    assert found == [], found


def test_the_structural_reader_sees_a_glob_call(tmp_path):
    """The reader's own control: on source that calls `.glob(` it must say so,
    and on a comment naming it it must not."""
    sample = tmp_path / "sample.py"
    sample.write_text("# p.glob('x') in a comment\nhits = p.glob('*.chain')\n")
    assert _glob_calls(sample, "sample.py") == ["sample.py:2"]


# ── no over-close: absent and empty stay "not opted in" ──────────────────────

def test_the_control_an_absent_home_is_not_opted_in(tmp_path):
    assert optin.opted_in(tmp_path / "never") is False


def test_the_control_an_empty_listable_chain_dir_is_not_opted_in(tmp_path):
    home = tmp_path / "empty"
    optin.hook_log(home).mkdir(parents=True)
    assert optin.opted_in(home) is False


def test_the_control_a_listable_chain_with_a_deleted_key_still_asks(home):
    keys.private_path(home).unlink()
    kind, reason = _decision(_hook(home))
    assert kind == "ask", reason
    assert _legacy(home) == []


def test_the_control_a_usable_key_under_an_unlistable_chain_asks(home, unlistable):
    unlistable(optin.hook_log(home), 0o000)
    kind, reason = _decision(_hook(home))
    assert kind == "ask", reason
    assert _legacy(home) == []
