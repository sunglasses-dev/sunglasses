"""What the Claude Code hook does, and what its receipt says, for each state a policy can be in.

Row 13 of the 0.6.5 follow ups. Measured on 89cd6e0e, a Read of a key shaped path:
no policy and a disabled starter policy both DEFER, and both wrote the same receipt (GLS-FW-CLEAN) as a policy that
was read and found nothing. The decision was right, the record was not: an auditor could not tell "no policy" from
"policy checked this call and it was fine".

This file pins two things together so neither can move alone.
  1. The decision for every state. With no policy the hook has no opinion about a credential path, which is the
     fail open default. Whoever flips that default has to change this table and the README sentence in one commit.
  2. The receipt names the state: none_configured when there is no policy file, inert when the file has no enabled
     entry. A policy that was read and listed something else carries no state at all.
The key path is assembled at run time so no literal credential path sits in this file.
"""
import json
import os
import pathlib
import re
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parent.parent
SSH = "." + "ssh"
KEY = "id_" + "ed25519"
OLD_HEADER = "an empty file (or no file at all) enforces nothing"


def _none(sh):
    pass


def _marker_only(sh):
    (sh / "installed").write_text("x\n", encoding="utf-8")


def _empty(sh):
    (sh / "policy.yaml").write_text("", encoding="utf-8")


def _disabled_starter(sh):
    from sunglasses.firewall import write_starter_policy
    write_starter_policy(home=sh, enabled=False)


def _enabled_starter(sh):
    from sunglasses.firewall import write_starter_policy
    write_starter_policy(home=sh, enabled=True)


def _key_with_no_entries(sh):
    (sh / "policy.yaml").write_text("blocked_paths:\n", encoding="utf-8")


def _active_but_unrelated(sh):
    (sh / "policy.yaml").write_text("blocked_paths:\n  - /opt/not-a-credential-dir\n", encoding="utf-8")


def _call(tmp_path, setup):
    home = tmp_path / "home"
    (home / SSH).mkdir(parents=True)
    key = home / SSH / KEY
    key.write_text("scratch file, not a key\n", encoding="utf-8")
    sh = home / ".sunglasses"
    sh.mkdir()
    setup(sh)
    env = dict(os.environ, HOME=str(home), SUNGLASSES_HOME=str(sh), PYTHONPATH=str(REPO))
    event = {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": str(key)}, "cwd": str(home)}
    out = subprocess.run([sys.executable, "-m", "sunglasses.cli", "firewall-hook"], input=json.dumps(event),
                         capture_output=True, text=True, env=env, cwd=str(home), timeout=120)
    assert out.returncode == 0, out.stderr
    text = out.stdout.strip()
    decision = "defer" if (not text or text == "{}") else json.loads(text)["hookSpecificOutput"]["permissionDecision"]
    records = []
    for f in sorted(sh.rglob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("kind") == "decision":
                records.append(rec)
    assert len(records) == 1, records
    return decision, records[0]


# state, setup, decision, rule id, policy_state on the receipt (None = the field is absent)
STATES = [
    ("no policy", _none, "defer", "GLS-FW-CLEAN", "none_configured"),
    ("no policy file but the install marker", _marker_only, "ask", "GLS-FW-POLICY-MISSING", "missing"),
    ("empty policy file", _empty, "ask", "GLS-FW-POLICY-EMPTY", "empty"),
    ("disabled starter", _disabled_starter, "defer", "GLS-FW-CLEAN", "inert"),
    ("a key with no entries", _key_with_no_entries, "defer", "GLS-FW-CLEAN", "inert"),
    ("enabled starter", _enabled_starter, "deny", "GLS-FW-POL-PATH", None),
    ("active policy that lists something else", _active_but_unrelated, "defer", "GLS-FW-CLEAN", None),
]
IDS = [s[0] for s in STATES]


@pytest.mark.parametrize("name,setup,decision,rule_id,state", STATES, ids=IDS)
def test_the_decision_for_each_policy_state(tmp_path, name, setup, decision, rule_id, state):
    got, rec = _call(tmp_path, setup)
    assert got == decision, (name, got)
    assert rec["decision"] == decision and rec["rule_id"] == rule_id, rec


@pytest.mark.parametrize("name,setup,decision,rule_id,state", STATES, ids=IDS)
def test_the_receipt_names_the_policy_state(tmp_path, name, setup, decision, rule_id, state):
    _, rec = _call(tmp_path, setup)
    assert rec.get("policy_state") == state, (name, rec)


def test_no_policy_does_not_read_like_a_policy_that_found_nothing(tmp_path):
    _, none_rec = _call(tmp_path / "a", _none)
    _, read_rec = _call(tmp_path / "b", _active_but_unrelated)
    assert none_rec["rule_id"] == read_rec["rule_id"] == "GLS-FW-CLEAN"
    assert none_rec.get("policy_state") != read_rec.get("policy_state")


def _readme_lines():
    return (REPO / "README.md").read_text(encoding="utf-8").splitlines()


def test_readme_hook_bullet_says_your_policy_lists():
    bullet = next(l for l in _readme_lines() if l.startswith("- A Claude Code hook that blocks"))
    assert "your policy lists" in bullet, bullet


def test_readme_opening_line_does_not_promise_credential_leaks_it_cannot_see():
    """A key piped to curl carries no secret in the command text. Blocking it is the policy's job."""
    opening = next(l for l in _readme_lines() if l.startswith("**Open source input firewall"))
    assert "credential leaks" not in opening, opening
    assert "secret material" in opening and "your policy lists" in opening, opening


def test_readme_still_says_a_fresh_install_adds_no_path_or_host_rule_it_was_not_asked_for():
    """The secret check runs with no configuration, so the README may not say nothing is enforced."""
    text = re.sub(r"\s+", " ", (REPO / "README.md").read_text(encoding="utf-8"))
    assert "a fresh install still adds no path or host rule you did not ask for" in text
    assert "and no path or host rule is enforced" in text
    assert "and nothing is enforced" not in text
    assert "a fresh install still blocks nothing you did not ask it to" not in text


def test_the_policy_file_header_does_not_say_an_empty_file_enforces_nothing(tmp_path):
    """An empty policy file asks on every call, so the file must not say it is harmless."""
    from sunglasses.firewall import starter_policy_text
    for enabled in (True, False):
        text = starter_policy_text(enabled=enabled)
        flat = re.sub(r"\s*\n#\s*", " ", text)  # comment wrapping must not hide the sentence
        assert OLD_HEADER not in flat
        assert "An empty file is treated as a broken policy, and a tool call that nothing else settles asks until the file is repaired" in flat


# ── what init says and what receipts show ───────────────────────────────────
# The decision table above is unchanged on purpose: nothing here moves a verdict.
# These pin the two places a person reads the state, so "no policy" cannot read
# like "a policy checked this call", on screen as well as on the receipt.

# setup, the word init prints. `active` has no receipt state, init needs a word for it.
INIT_WORDS = [
    ("no policy", _none, "none_configured"),
    ("no policy file but the install marker", _marker_only, "missing"),
    ("empty policy file", _empty, "empty"),
    ("disabled starter", _disabled_starter, "inert"),
    ("a key with no entries", _key_with_no_entries, "inert"),
    ("enabled starter", _enabled_starter, "active"),
    ("active policy that lists something else", _active_but_unrelated, "active"),
]


@pytest.mark.parametrize("name,setup,word", INIT_WORDS, ids=[s[0] for s in INIT_WORDS])
def test_the_init_line_names_the_state_and_the_file(tmp_path, name, setup, word):
    from sunglasses.cli import _policy_state_line
    sh = tmp_path / ".sunglasses"
    sh.mkdir()
    setup(sh)
    line = _policy_state_line(sh)
    assert "\n" not in line, line
    assert f"Policy state {word} for " in line, line
    assert str(sh / "policy.yaml") in line, line


def test_a_dead_policy_control_says_the_firewall_asks(tmp_path):
    from sunglasses.cli import _policy_state_line
    sh = tmp_path / ".sunglasses"
    sh.mkdir()
    _empty(sh)
    assert "asks on any tool call that no other check settles" in _policy_state_line(sh)


def test_an_active_policy_line_does_not_promise_the_policy_is_read_on_every_call(tmp_path):
    """A secret in a call is denied before the policy is loaded, so the line says so."""
    from sunglasses.cli import _policy_state_line
    sh = tmp_path / ".sunglasses"
    sh.mkdir()
    _enabled_starter(sh)
    line = _policy_state_line(sh)
    assert "on every tool call" not in line, line
    assert "unless the secret check has already denied it" in line, line


def test_a_no_policy_line_says_the_secret_check_runs_and_does_not_promise_a_deny(tmp_path):
    """The secret check denies only recognised secret text in an outbound call, so the line says it runs."""
    from sunglasses.cli import _policy_state_line
    sh = tmp_path / ".sunglasses"
    sh.mkdir()
    for make in (_none, _disabled_starter):
        make(sh)
        line = _policy_state_line(sh)
        assert "the secret check on outbound calls runs as before" in line, line
        for promise in ("still denied", "is denied", "could send", "blocked"):
            assert promise not in line, line


def _init(tmp_path, *flags):
    """Run the real `sunglasses init` in a scratch project, the way a person does."""
    home = tmp_path / "home"
    home.mkdir()
    sh = home / ".sunglasses"
    proj = tmp_path / "proj"
    proj.mkdir()
    env = dict(os.environ, HOME=str(home), SUNGLASSES_HOME=str(sh), PYTHONPATH=str(REPO))
    out = subprocess.run([sys.executable, "-m", "sunglasses.cli", "init", *flags],
                         capture_output=True, text=True, env=env, cwd=str(proj),
                         stdin=subprocess.DEVNULL, timeout=180)
    assert out.returncode == 0, out.stdout + out.stderr
    return out.stdout, sh


@pytest.mark.parametrize("flags,word", [
    (("--no-policy",), "none_configured"),
    ((), "inert"),                      # not a terminal: the starter is written commented out
    (("--policy",), "active"),
], ids=["no-policy", "not-a-terminal", "policy"])
def test_init_prints_the_state_line_on_every_road(tmp_path, flags, word):
    """READ THE CALL SITE. The helper is correct and a test of it alone would pass
    with `init` never calling it."""
    stdout, sh = _init(tmp_path, *flags)
    lines = [l for l in stdout.splitlines() if "Policy state" in l]
    assert len(lines) == 1, stdout
    assert f"Policy state {word} for " in lines[0], lines[0]
    assert str(sh / "policy.yaml") in lines[0], lines[0]


def test_init_no_longer_says_deleting_the_policy_enforces_nothing(tmp_path):
    """With the install marker in place a deleted policy asks on every call."""
    stdout, _ = _init(tmp_path, "--policy")
    assert "enforces nothing" not in stdout, stdout
    flat = re.sub(r"\s+", " ", stdout)
    assert "If you delete it, the firewall asks on any tool call that no other check settles, until you restore it" in flat


def test_load_policy_docstring_names_the_marker_not_the_home_directory():
    from sunglasses.firewall import load_policy
    doc = re.sub(r"\s+", " ", load_policy.__doc__)
    assert "no home directory" not in doc, doc
    assert "install marker" in doc, doc


def _receipts(tmp_path, setup):
    _call(tmp_path, setup)
    home = tmp_path / "home"
    env = dict(os.environ, HOME=str(home), SUNGLASSES_HOME=str(home / ".sunglasses"), PYTHONPATH=str(REPO))
    out = subprocess.run([sys.executable, "-m", "sunglasses.cli", "receipts"], capture_output=True,
                         text=True, env=env, cwd=str(home), timeout=120)
    assert out.returncode == 0, out.stdout + out.stderr
    return out.stdout


def test_the_receipt_view_marks_a_call_that_ran_without_a_policy(tmp_path):
    shown = _receipts(tmp_path, _none)
    assert "none_configured" in shown, shown
    assert "ran with no path or host rules loaded" in shown, shown


def test_the_receipt_view_marks_an_inert_policy_the_same_way(tmp_path):
    shown = _receipts(tmp_path, _disabled_starter)
    assert "inert" in shown, shown
    assert "ran with no path or host rules loaded" in shown, shown


def test_the_receipt_view_stays_quiet_for_a_call_a_policy_checked(tmp_path):
    shown = _receipts(tmp_path, _active_but_unrelated)
    assert "none_configured" not in shown and "inert" not in shown, shown
    assert "ran with no path or host rules loaded" not in shown, shown


def test_readme_says_init_and_receipts_name_the_policy_state():
    text = re.sub(r"\s+", " ", (REPO / "README.md").read_text(encoding="utf-8"))
    assert "sunglasses init` prints one line with the state of the policy file and its path" in text
    assert "`sunglasses receipts` marks each call whose receipt records that it ran with no policy" in text


# ── a starter written by an earlier release ─────────────────────────────────
# `write_starter_policy` turns a disabled starter on only when the file is a starter this project
# wrote and the user has not changed. The header was reworded between releases, so the running
# code's own text is not the only text such a file can hold. Each earlier text is kept as a
# sha256, and the comparison reads and hashes the raw bytes of the file.

# The lines above the first rule in each release's starter. The rules below them were the same
# text, so an earlier starter is these lines plus the current body. The path list is not repeated
# here so no literal credential path sits in this file.
V065_HEAD = (
    "# SUNGLASSES policy — your rules, enforced as HARD BLOCKS.\n"
    "# Written by `sunglasses init`. Edit or delete freely: an empty file (or no\n"
    "# file at all) enforces nothing.\n"
)
V066_HEAD = (
    "# SUNGLASSES policy — your rules, enforced as HARD BLOCKS.\n"
    "# Written by `sunglasses init`. Edit it freely. No file at all enforces\n"
    "# nothing, and a file with only comments enforces nothing. An empty file is\n"
    "# treated as a broken policy, and a tool call that nothing else settles asks\n"
    "# until the file is repaired.\n"
)
# sha256 of the starter each of those releases wrote, read from the release tags themselves.
EARLIER = {
    "v0.6.5": (V065_HEAD, False, "47b9fe35d84b6af69b60cc89078fdcd025019b4149e6d18622474e67af0e5b4a"),
    "v0.6.6": (V066_HEAD, False, "bb68349c8fd83ce2d4422d9b4fdc61c737b8c6785c0711fa22c453e460950bb8"),
}
EARLIER_ENABLED = {
    "v0.6.5": (V065_HEAD, True, "cf4af074e20e6a2d2c5d62eade67ae6c31b8a03aeb360b8f38583032f5e11b68"),
    "v0.6.6": (V066_HEAD, True, "971ce41b7e2cdee9408517905ef417e26ed85c508034ea2267715f5a2467477a"),
}
BODY_START = "#\n# blocked_paths"


def _earlier(head, enabled=False):
    from sunglasses.firewall import starter_policy_text
    body = starter_policy_text(enabled=enabled).split(BODY_START, 1)[1]
    return (head + BODY_START + body).encode("utf-8")


def _sha(data):
    import hashlib
    return hashlib.sha256(data).hexdigest()


def _home(tmp_path, name="h"):
    sh = tmp_path / name / ".sunglasses"
    sh.mkdir(parents=True)
    return sh


def _put(sh, data):
    (sh / "policy.yaml").write_bytes(data)
    return sh / "policy.yaml"


def _leftovers(sh):
    return sorted(p.name for p in sh.iterdir() if p.name.endswith(".tmp"))


@pytest.mark.parametrize("tag", sorted(EARLIER))
def test_the_earlier_starter_texts_used_here_are_the_ones_that_shipped(tag):
    """If this fails the rules under the header changed. Add the hash of the text being replaced to the
    kept sets in firewall.py, then rebuild the head and body here from that release's tag."""
    for table in (EARLIER, EARLIER_ENABLED):
        head, enabled, digest = table[tag]
        assert _sha(_earlier(head, enabled)) == digest


def test_the_kept_hashes_are_the_hashes_of_the_releases_listed_here():
    from sunglasses.firewall import _EARLIER_DISABLED_STARTER_SHA256 as dis, _EARLIER_ENABLED_STARTER_SHA256 as en
    assert dis == {d for _, _, d in EARLIER.values()}
    assert en == {d for _, _, d in EARLIER_ENABLED.values()}


@pytest.mark.parametrize("tag", sorted(EARLIER))
def test_an_unchanged_disabled_starter_from_an_earlier_release_is_enabled_by_the_policy_rerun(tmp_path, tag):
    from sunglasses.firewall import starter_policy_text, write_starter_policy
    sh = _home(tmp_path)
    policy = _put(sh, _earlier(EARLIER[tag][0]))
    assert write_starter_policy(home=sh, enabled=True) == policy
    assert policy.read_bytes() == starter_policy_text(enabled=True).encode("utf-8")
    assert _leftovers(sh) == []


def test_a_current_disabled_starter_is_still_enabled_by_the_policy_rerun(tmp_path):
    """Control for the table above: the road that worked before still works."""
    from sunglasses.firewall import starter_policy_text, write_starter_policy
    sh = _home(tmp_path)
    write_starter_policy(home=sh, enabled=False)
    assert write_starter_policy(home=sh, enabled=True) == sh / "policy.yaml"
    assert (sh / "policy.yaml").read_bytes() == starter_policy_text(enabled=True).encode("utf-8")


def _crlf(b):
    return b.replace(b"\n", b"\r\n")


def _lone_cr(b):
    return b.replace(b"\n", b"\r")


def _one_crlf(b):
    return b.replace(b"\n", b"\r\n", 1)


def _bom(b):
    return b"\xef\xbb\xbf" + b


def _no_final_newline(b):
    return b.rstrip(b"\n")


def _extra_final_newline(b):
    return b + b"\n"


def _appended(b):
    return b + b"# mine\n"


def _leading_space(b):
    return b" " + b


def _one_line_uncommented(b):
    return b.replace(b"# allowed_hosts:\n", b"allowed_hosts:\n", 1)


def _a_word_changed(b):
    return b.replace(b"HARD BLOCKS", b"HARD BLOCKED", 1)


def _utf16(b):
    return b.decode("utf-8").encode("utf-16")


EDITS = [_crlf, _lone_cr, _one_crlf, _bom, _no_final_newline, _extra_final_newline, _appended,
         _leading_space, _one_line_uncommented, _a_word_changed, _utf16]


@pytest.mark.parametrize("edit", EDITS, ids=[e.__name__ for e in EDITS])
@pytest.mark.parametrize("which", ["current", "v0.6.5", "v0.6.6"])
def test_a_disabled_starter_whose_bytes_differ_is_left_as_it_is(tmp_path, which, edit):
    from sunglasses.firewall import starter_policy_text, write_starter_policy
    base = (starter_policy_text(enabled=False).encode("utf-8") if which == "current"
            else _earlier(EARLIER[which][0]))
    data = edit(base)
    assert data != base
    sh = _home(tmp_path)
    policy = _put(sh, data)
    assert write_starter_policy(home=sh, enabled=True) is None
    assert policy.read_bytes() == data
    assert _leftovers(sh) == []


@pytest.mark.parametrize("data_name", ["disabled_starter", "edited_file"])
def test_a_symlinked_policy_file_is_not_followed_or_replaced(tmp_path, data_name):
    from sunglasses.firewall import starter_policy_text, write_starter_policy
    sh = _home(tmp_path)
    real = tmp_path / "elsewhere.yaml"
    data = (starter_policy_text(enabled=False).encode("utf-8") if data_name == "disabled_starter"
            else b"blocked_paths: []\n")
    real.write_bytes(data)
    (sh / "policy.yaml").symlink_to(real)
    assert write_starter_policy(home=sh, enabled=True) is None
    assert (sh / "policy.yaml").is_symlink()
    assert real.read_bytes() == data
    assert _leftovers(sh) == []


@pytest.mark.parametrize("enabled", [True, False])
def test_a_dangling_symlink_does_not_get_its_target_created(tmp_path, enabled):
    from sunglasses.firewall import write_starter_policy
    sh = _home(tmp_path)
    target = tmp_path / "not-there.yaml"
    (sh / "policy.yaml").symlink_to(target)
    assert write_starter_policy(home=sh, enabled=enabled) is None
    assert not target.exists()
    assert (sh / "policy.yaml").is_symlink()


def _within(fn, seconds, unblock):
    """Run fn on a thread. True and its result when it finishes, False when it is still blocked."""
    import threading
    box = {}

    def go():
        try:
            box["v"] = fn()
        except BaseException as e:  # noqa: BLE001 - reported by the caller
            box["e"] = e

    t = threading.Thread(target=go, daemon=True)
    t.start()
    t.join(seconds)
    if t.is_alive():
        unblock()
        t.join(5)
        return False, None
    return True, box


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a POSIX fifo")
def test_a_fifo_in_place_of_the_policy_file_is_not_read_or_replaced(tmp_path):
    from sunglasses.firewall import write_starter_policy
    sh = _home(tmp_path)
    fifo = sh / "policy.yaml"
    os.mkfifo(fifo)

    def unblock():
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        os.close(fd)

    finished, box = _within(lambda: write_starter_policy(home=sh, enabled=True), 5, unblock)
    assert finished, "the call blocked reading a fifo"
    assert "e" not in box, box
    assert box["v"] is None
    import stat
    assert stat.S_ISFIFO(os.lstat(fifo).st_mode)


def test_a_folder_in_place_of_the_policy_file_is_left_as_it_is(tmp_path):
    from sunglasses.firewall import write_starter_policy
    sh = _home(tmp_path)
    (sh / "policy.yaml").mkdir()
    assert write_starter_policy(home=sh, enabled=True) is None
    assert (sh / "policy.yaml").is_dir()


def test_a_file_changed_after_it_was_read_is_not_replaced(tmp_path, monkeypatch):
    """The user saves their own policy over the starter between the read and the replace."""
    from sunglasses import firewall
    sh = _home(tmp_path)
    policy = _put(sh, _earlier(V065_HEAD))
    mine = b"blocked_paths:\n  - /opt/mine\n"
    real_fsync = os.fsync
    calls = []

    def fsync_then_the_user_saves(fd):
        real_fsync(fd)
        if not calls:
            calls.append(1)
            policy.write_bytes(mine)

    monkeypatch.setattr(os, "fsync", fsync_then_the_user_saves)
    assert firewall.write_starter_policy(home=sh, enabled=True) is None
    assert calls == [1]
    assert policy.read_bytes() == mine
    assert _leftovers(sh) == []


def test_a_failed_replace_leaves_the_file_and_no_temporary_file(tmp_path, monkeypatch):
    from sunglasses import firewall
    sh = _home(tmp_path)
    before = _earlier(V066_HEAD)
    policy = _put(sh, before)

    def boom(*a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError):
        firewall.write_starter_policy(home=sh, enabled=True)
    assert policy.read_bytes() == before
    assert _leftovers(sh) == []


def test_a_failed_first_write_leaves_no_policy_file(tmp_path, monkeypatch):
    from sunglasses import firewall
    sh = _home(tmp_path)

    def boom(fd):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(os, "fsync", boom)
    with pytest.raises(OSError):
        firewall.write_starter_policy(home=sh, enabled=True)
    assert not (sh / "policy.yaml").exists()
    assert _leftovers(sh) == []


def _the_user_saves(policy, data):
    """An editor's save: write beside the file, then rename over it."""
    side = policy.with_name("user-save.yaml")
    side.write_bytes(data)
    os.replace(side, policy)


def _removed_paths(monkeypatch):
    """Record each path handed to os.unlink while the test runs."""
    removed = []
    real_unlink = os.unlink

    def watch(path, *a, **k):
        removed.append(pathlib.Path(path))
        return real_unlink(path, *a, **k)

    monkeypatch.setattr(os, "unlink", watch)
    return removed


def test_a_policy_file_created_by_someone_else_during_the_first_write_is_kept(tmp_path, monkeypatch):
    """The name is taken after the new file is finished and before it is published."""
    from sunglasses import firewall
    sh = _home(tmp_path)
    policy = sh / "policy.yaml"
    mine = b"blocked_paths:\n  - /opt/mine\n"
    real_link = os.link

    def link_after_the_user_saves(src, dst, *a, **k):
        if pathlib.Path(dst) == policy:
            policy.write_bytes(mine)
        return real_link(src, dst, *a, **k)

    removed = _removed_paths(monkeypatch)
    monkeypatch.setattr(os, "link", link_after_the_user_saves)
    assert firewall.write_starter_policy(home=sh, enabled=True) is None
    assert policy.read_bytes() == mine
    assert policy not in removed
    assert _leftovers(sh) == []


def test_a_policy_saved_before_a_failed_first_write_is_not_removed(tmp_path, monkeypatch):
    """The user saves over the path while the new file is being synced, and the sync then fails.
    The cleanup removes the file this call made and nothing else."""
    from sunglasses import firewall
    sh = _home(tmp_path)
    policy = sh / "policy.yaml"
    mine = b"blocked_paths:\n  - /opt/mine\n"

    def save_then_fail(fd):
        _the_user_saves(policy, mine)
        raise OSError(5, "Input/output error")

    removed = _removed_paths(monkeypatch)
    monkeypatch.setattr(os, "fsync", save_then_fail)
    with pytest.raises(OSError):
        firewall.write_starter_policy(home=sh, enabled=True)
    assert policy.read_bytes() == mine
    assert policy not in removed
    assert _leftovers(sh) == []


def test_a_new_policy_file_is_not_seen_part_written(tmp_path, monkeypatch):
    """While the bytes are being written the policy name does not exist yet."""
    from sunglasses import firewall
    sh = _home(tmp_path)
    policy = sh / "policy.yaml"
    seen = []
    real_write = os.write

    def look_then_write(fd, data):
        seen.append(policy.exists())
        return real_write(fd, data[:100] if len(data) > 100 else data)

    monkeypatch.setattr(os, "write", look_then_write)
    assert firewall.write_starter_policy(home=sh, enabled=True) == policy
    assert len(seen) > 1 and not any(seen)
    assert policy.read_bytes() == firewall.starter_policy_text(enabled=True).encode("utf-8")
    assert _leftovers(sh) == []


def test_a_save_during_the_final_read_is_not_overwritten(tmp_path, monkeypatch):
    """The user saves over the starter while the second read of it is in progress, after the first
    chunk was read. The second read still reaches the end of the old file, so its bytes match."""
    from sunglasses import firewall
    sh = _home(tmp_path)
    policy = _put(sh, _earlier(V065_HEAD))
    mine = b"blocked_paths:\n  - /opt/mine\n"
    real_read_policy = firewall._read_policy_file
    real_read = os.read
    state = {"calls": 0, "saved": False}

    def save_after_the_first_chunk(fd, n):
        data = real_read(fd, n)
        if data and not state["saved"]:
            state["saved"] = True
            _the_user_saves(policy, mine)
        return data

    def second_read_with_a_save(path):
        state["calls"] += 1
        if state["calls"] != 2:
            return real_read_policy(path)
        monkeypatch.setattr(os, "read", save_after_the_first_chunk)
        try:
            return real_read_policy(path)
        finally:
            monkeypatch.setattr(os, "read", real_read)

    monkeypatch.setattr(firewall, "_read_policy_file", second_read_with_a_save)
    assert firewall.write_starter_policy(home=sh, enabled=True) is None
    assert state["saved"]
    assert policy.read_bytes() == mine
    assert _leftovers(sh) == []


def test_a_file_saved_with_the_same_bytes_but_as_a_new_file_is_not_replaced(tmp_path, monkeypatch):
    """Same bytes is not the same file. A save that rewrites the starter text as a new file during the
    staging is the user's file now, and it is kept."""
    from sunglasses import firewall
    sh = _home(tmp_path)
    before = _earlier(V066_HEAD)
    policy = _put(sh, before)
    real_fsync = os.fsync
    saved_inodes = []

    def fsync_then_the_user_saves_the_same_text(fd):
        real_fsync(fd)
        if not saved_inodes:
            _the_user_saves(policy, before)
            saved_inodes.append(os.stat(policy).st_ino)

    monkeypatch.setattr(os, "fsync", fsync_then_the_user_saves_the_same_text)
    assert firewall.write_starter_policy(home=sh, enabled=True) is None
    assert len(saved_inodes) == 1
    assert policy.read_bytes() == before
    assert os.stat(policy).st_ino == saved_inodes[0]
    assert _leftovers(sh) == []


def test_a_file_changed_while_it_is_being_read_is_refused(tmp_path, monkeypatch):
    """An in place save during the read gives a mix of old and new bytes at best, so it is not
    read as a starter."""
    from sunglasses import firewall
    sh = _home(tmp_path)
    policy = _put(sh, _earlier(V065_HEAD))
    real_read = os.read
    state = {"done": False}

    def rewrite_in_place_after_the_first_chunk(fd, n):
        data = real_read(fd, n)
        if data and not state["done"]:
            state["done"] = True
            with open(policy, "r+b") as f:
                f.write(b"# edited\n")
        return data

    monkeypatch.setattr(os, "read", rewrite_in_place_after_the_first_chunk)
    kind, data, _mode, _identity = firewall._read_policy_file(policy)
    assert state["done"]
    assert kind == "unsafe" and data is None


_DIES_AFTER_A_SHORT_WRITE = r"""
import os, pathlib, signal, sys
sys.path.insert(0, sys.argv[1])
from sunglasses import firewall as f
def short_write_then_die(fd, data):
    os.write(fd, data[:data.index(b"\n") + 1])
    os.kill(os.getpid(), signal.SIGKILL)
f._write_all = short_write_then_die
f.write_starter_policy(home=pathlib.Path(sys.argv[2]), enabled=True)
"""

_DIES_AFTER_A_FULL_STAGING_WRITE = r"""
import os, pathlib, signal, sys
sys.path.insert(0, sys.argv[1])
from sunglasses import firewall as f
def write_then_die(fd, data):
    os.write(fd, data)
    os.kill(os.getpid(), signal.SIGKILL)
f._write_all = write_then_die
f.write_starter_policy(home=pathlib.Path(sys.argv[2]), enabled=True)
"""


def _run_until_killed(code, sh):
    return subprocess.run([sys.executable, "-B", "-c", code, str(REPO), str(sh)], capture_output=True).returncode


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs a POSIX signal")
def test_a_writer_killed_after_a_short_write_leaves_no_partial_policy(tmp_path):
    """Process death cannot run cleanup. It may leave one staging file. It must not leave a
    policy.yaml holding the first comment line, which would load as an empty policy."""
    from sunglasses import firewall
    sh = _home(tmp_path)
    assert _run_until_killed(_DIES_AFTER_A_SHORT_WRITE, sh) == -9
    assert not (sh / "policy.yaml").exists()
    assert len(_leftovers(sh)) <= 1
    # the rerun is not blocked by what the killed run left, and writes the whole enabled starter
    assert firewall.write_starter_policy(home=sh, enabled=True) == sh / "policy.yaml"
    assert (sh / "policy.yaml").read_bytes() == firewall.starter_policy_text(enabled=True).encode("utf-8")


@pytest.mark.skipif(not hasattr(os, "fork"), reason="needs a POSIX signal")
def test_a_writer_killed_during_an_upgrade_leaves_the_old_file_whole(tmp_path):
    before = _earlier(V065_HEAD)
    sh = _home(tmp_path)
    policy = _put(sh, before)
    assert _run_until_killed(_DIES_AFTER_A_FULL_STAGING_WRITE, sh) == -9
    assert policy.read_bytes() == before
    assert len(_leftovers(sh)) <= 1


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs a POSIX fifo")
def test_a_fifo_at_the_policy_path_is_not_passed_to_open(tmp_path, monkeypatch):
    """The first look at the path refuses a fifo before an open is tried on it."""
    from sunglasses import firewall
    sh = _home(tmp_path)
    fifo = sh / "policy.yaml"
    os.mkfifo(fifo)
    opened = []
    real_open = os.open

    def watch(path, *a, **k):
        opened.append(pathlib.Path(path))
        return real_open(path, *a, **k)

    monkeypatch.setattr(os, "open", watch)
    assert firewall.existing_policy_kind(home=sh) == "other"
    assert firewall.write_starter_policy(home=sh, enabled=True) is None
    assert fifo not in opened


def test_an_upgrade_keeps_the_mode_of_the_file(tmp_path):
    from sunglasses.firewall import write_starter_policy
    sh = _home(tmp_path)
    policy = _put(sh, _earlier(V065_HEAD))
    os.chmod(policy, 0o640)
    assert write_starter_policy(home=sh, enabled=True) == policy
    assert (os.stat(policy).st_mode & 0o777) == 0o640


def test_the_untouched_check_reads_bytes_and_accepts_only_the_texts_that_were_written():
    from sunglasses.firewall import _is_our_untouched_disabled_starter as ours, starter_policy_text
    current = starter_policy_text(enabled=False).encode("utf-8")
    assert ours(current)                                          # control: today's own disabled starter
    assert ours(_earlier(V065_HEAD)) and ours(_earlier(V066_HEAD))
    assert not ours(starter_policy_text(enabled=True).encode("utf-8"))   # an enabled file is a policy
    assert not ours(b"")
    assert not ours(_earlier(V065_HEAD) + b"\n")
    assert not ours(_crlf(current))


def _init_policy(tmp_path, data):
    home = tmp_path / "home"
    sh = home / ".sunglasses"
    sh.mkdir(parents=True)
    (sh / "policy.yaml").write_bytes(data)
    proj = tmp_path / "proj"
    proj.mkdir()
    env = dict(os.environ, HOME=str(home), SUNGLASSES_HOME=str(sh), PYTHONPATH=str(REPO))
    out = subprocess.run([sys.executable, "-m", "sunglasses.cli", "init", "--policy"],
                         capture_output=True, text=True, env=env, cwd=str(proj),
                         stdin=subprocess.DEVNULL, timeout=180)
    return sh, out


def test_init_policy_enables_an_unchanged_older_starter_and_does_not_blame_the_user(tmp_path):
    """The CLI message is what a person reads."""
    sh, out = _init_policy(tmp_path, _earlier(V066_HEAD))
    assert out.returncode == 0, out.stdout + out.stderr
    assert "ENABLED" in out.stdout, out.stdout
    assert "your own edits" not in out.stdout, out.stdout
    from sunglasses.firewall import starter_policy_text
    assert (sh / "policy.yaml").read_bytes() == starter_policy_text(enabled=True).encode("utf-8")


@pytest.mark.parametrize("which", ["current", "v0.6.5", "v0.6.6"])
def test_init_policy_on_an_enabled_starter_says_it_is_already_enabled(tmp_path, which):
    from sunglasses.firewall import starter_policy_text
    data = (starter_policy_text(enabled=True).encode("utf-8") if which == "current"
            else _earlier(EARLIER_ENABLED[which][0], True))
    sh, out = _init_policy(tmp_path, data)
    assert out.returncode == 0, out.stdout + out.stderr
    assert "already enabled" in out.stdout, out.stdout
    assert "your own edits" not in out.stdout and "Uncomment" not in out.stdout, out.stdout
    assert (sh / "policy.yaml").read_bytes() == data


def test_init_policy_on_a_changed_file_says_it_was_left_untouched_without_claiming_who_changed_it(tmp_path):
    sh, out = _init_policy(tmp_path, _crlf(_earlier(V065_HEAD)))
    assert out.returncode == 0, out.stdout + out.stderr
    assert "left untouched" in out.stdout, out.stdout
    assert "your own edits" not in out.stdout and "already enabled" not in out.stdout, out.stdout
    assert (sh / "policy.yaml").read_bytes() == _crlf(_earlier(V065_HEAD))


def test_the_policy_file_header_says_where_the_secret_check_applies_and_keeps_the_empty_file_warning():
    from sunglasses.firewall import starter_policy_text
    for enabled in (True, False):
        flat = re.sub(r"\s*\n#\s*", " ", starter_policy_text(enabled=enabled))
        assert "Detected secret material in outbound tool calls is denied even without this file." in flat
        assert "This file adds your path and host rules." in flat
        assert "Secret material in tool calls is denied" not in flat
        assert "No file at all enforces nothing" not in flat
        assert "a file with only comments enforces nothing" not in flat
        assert "An empty file is treated as a broken policy, and a tool call that nothing else settles asks until the file is repaired" in flat
