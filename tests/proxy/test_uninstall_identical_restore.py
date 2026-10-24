"""R38 (0.6.1) -- uninstall says "byte-identical" when the end state IS the
original, and warns only when it is not.

Two wraps on one file, uninstalled first-installed-first (FIFO), put the file
back byte for byte, and each uninstall still printed "file not byte-identical:
it changed after the install". The second of those is a false statement to the
user: the file in front of them is exactly what they had before either install.
Measured on main dd3dedd by T8 (t9-fable:3646).

The first FIFO uninstall keeps its warning, and a row below pins that: at that
moment the second install's wrapper is still in the file, so the file really is
not what it was before the first install.

Why the config here is written by `json.dumps(indent=2)` with a trailing
newline: an entry-only restore renders the file that way, so only a config
already in that form CAN come back byte-identical through two entry-only
restores. The odd-format fixture in test_install_transaction.py can never
return identical this way, and the warning there is true.
"""
import json
import os
import pathlib
import subprocess
import sys
import types

import pytest

from sunglasses import install as inst

REPO = str(pathlib.Path(__file__).resolve().parents[2])

CANON = (json.dumps({"mcpServers": {
    "echo": {"command": "echo-server", "args": ["--stdio"]},
    "fetch": {"command": "fetch-server", "args": ["--stdio"]},
}}, indent=2) + "\n").encode("utf-8")

WARNING = "not byte-identical"
CHANGED = "changed after the install"


@pytest.fixture
def cfg(tmp_path):
    p = tmp_path / ".mcp.json"
    p.write_bytes(CANON)
    return p


@pytest.fixture
def home(tmp_path):
    return tmp_path / "sgh"


@pytest.fixture
def artifact(tmp_path):
    a = tmp_path / "artifact" / "proxy_main.py"
    a.parent.mkdir(parents=True)
    a.write_text("# proxy entry point\n", encoding="utf-8")
    return a


def read(p):
    return pathlib.Path(p).read_bytes()


def foreign_edit(p):
    d = json.loads(read(p).decode("utf-8"))
    d["mcpServers"]["added-later"] = {"command": "other", "args": []}
    p.write_bytes((json.dumps(d, indent=2) + "\n").encode("utf-8"))


# ------------------------------------------------------------ library rows

def test_fifo_second_uninstall_reports_identical_when_the_end_state_is_the_original(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)

    first = inst.uninstall(cfg, "echo", home=home)
    last = inst.uninstall(cfg, "fetch", home=home)

    assert read(cfg) == CANON            # the premise, measured, not assumed
    assert first.byte_exact is False     # fetch is still wrapped at that point
    assert last.byte_exact is True


def test_fifo_first_uninstall_still_warns_while_the_other_wrapper_is_in_the_file(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)

    first = inst.uninstall(cfg, "echo", home=home)

    assert read(cfg) != CANON
    assert inst.classify(json.loads(read(cfg))["mcpServers"]["fetch"],
                         artifact=artifact) == "WRAPPED"
    assert first.byte_exact is False


def test_control_a_real_foreign_edit_still_warns_on_fifo(cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    foreign_edit(cfg)

    inst.uninstall(cfg, "echo", home=home)
    last = inst.uninstall(cfg, "fetch", home=home)

    assert read(cfg) != CANON
    assert "added-later" in json.loads(read(cfg))["mcpServers"]
    assert last.byte_exact is False


def test_control_a_real_foreign_edit_still_warns_on_a_single_wrap(cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    foreign_edit(cfg)

    res = inst.uninstall(cfg, "echo", home=home)

    assert read(cfg) != CANON
    assert res.byte_exact is False


def test_a_reformat_only_edit_comes_back_identical_to_this_installs_original(
        cfg, home, artifact):
    """The other half of "compare the final file to the pre-install original":
    an editor that re-indents the wrapped file moves it off the after-image, so
    the restore is entry-only, and it still lands on the exact original."""
    inst.install(cfg, "echo", artifact=artifact, home=home)
    cfg.write_bytes(json.dumps(json.loads(read(cfg)), indent=4).encode("utf-8"))

    res = inst.uninstall(cfg, "echo", home=home)

    assert read(cfg) == CANON
    assert res.byte_exact is True
    assert res.earlier is False


def test_lifo_is_unchanged(cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)

    assert inst.uninstall(cfg, "fetch", home=home).byte_exact is True
    assert inst.uninstall(cfg, "echo", home=home).byte_exact is True
    assert read(cfg) == CANON


def test_single_wrap_is_unchanged(cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    assert inst.uninstall(cfg, "echo", home=home).byte_exact is True
    assert read(cfg) == CANON


def test_an_unreadable_earlier_digest_list_falls_back_to_the_warning(
        cfg, home, artifact):
    """The earlier digests only ever change WORDING, and a record whose list is
    not a list of digests gets the conservative sentence, never the claim."""
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    rec = pathlib.Path(home) / "proxy" / "installs" / "fetch.json"
    body = json.loads(rec.read_text(encoding="utf-8"))
    assert "earlier_sha_before" in body
    body["earlier_sha_before"] = "not a list"
    rec.write_text(json.dumps(body, indent=2), encoding="utf-8")

    inst.uninstall(cfg, "echo", home=home)
    last = inst.uninstall(cfg, "fetch", home=home)

    assert read(cfg) == CANON
    assert last.byte_exact is False


# ---------------------------------------------------------------- CLI rows

def sg(*args, cwd, home):
    env = dict(os.environ, HOME=str(home), SUNGLASSES_HOME=str(home),
               PYTHONPATH=REPO, PYTHONDONTWRITEBYTECODE="1")
    return subprocess.run([sys.executable, "-B", "-m", "sunglasses.cli", *args],
                          cwd=str(cwd), env=env, capture_output=True, text=True)


@pytest.fixture
def project(tmp_path):
    d = tmp_path / "work"
    d.mkdir()
    (d / ".mcp.json").write_bytes(CANON)
    return d


def _run(project, home, *steps):
    out = []
    for step in steps:
        r = sg(*step, cwd=project, home=home)
        assert r.returncode == 0, (step, r.stdout, r.stderr)
        out.append(r.stdout)
    return out


def test_cli_fifo_never_prints_changed_when_the_end_state_is_the_original(
        project, tmp_path):
    home = tmp_path / "h"
    out = _run(project, home, ("install", "echo"), ("install", "fetch"),
               ("uninstall", "echo"), ("uninstall", "fetch"))

    assert read(project / ".mcp.json") == CANON
    assert WARNING not in out[3]
    assert CHANGED not in out[3]
    assert "byte-identical" in out[3]


def test_cli_control_a_foreign_edit_still_prints_the_warning(project, tmp_path):
    home = tmp_path / "h"
    _run(project, home, ("install", "echo"), ("install", "fetch"))
    foreign_edit(project / ".mcp.json")
    out = _run(project, home, ("uninstall", "echo"), ("uninstall", "fetch"))

    assert read(project / ".mcp.json") != CANON
    assert WARNING in out[1]
    assert CHANGED in out[1]


def test_cli_lifo_and_single_wrap_wording_is_unchanged(project, tmp_path):
    home = tmp_path / "h"
    out = _run(project, home, ("install", "echo"), ("install", "fetch"),
               ("uninstall", "fetch"), ("uninstall", "echo"),
               ("install", "echo"), ("uninstall", "echo"))

    assert read(project / ".mcp.json") == CANON
    for printed in (out[2], out[3], out[5]):
        assert "(byte-identical)" in printed
        assert WARNING not in printed


# ------------------------------------- FIFO step 1 names its cause (R38 b)
#
# The first FIFO uninstall is not back at the original because the second
# wrap is still in the file, and that is the only thing between the two. The
# generic "changed after the install" reads as somebody else's edit; the true
# sentence names the later install and what to run.

STACKED = "still wrapped here"


def test_fifo_first_uninstall_names_the_later_install_as_the_cause(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)

    first = inst.uninstall(cfg, "echo", home=home)

    assert first.byte_exact is False
    assert first.later == ("fetch",)


def test_three_stacked_wraps_name_every_later_install(cfg, home, artifact):
    cfg.write_bytes((json.dumps({"mcpServers": {
        **json.loads(CANON)["mcpServers"],
        "third": {"command": "third-server", "args": []}}}, indent=2)
        + "\n").encode("utf-8"))
    for name in ("echo", "fetch", "third"):
        inst.install(cfg, name, artifact=artifact, home=home)

    assert inst.uninstall(cfg, "echo", home=home).later == ("fetch", "third")


def test_control_a_foreign_edit_on_top_is_not_blamed_on_the_later_install(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    foreign_edit(cfg)

    assert inst.uninstall(cfg, "echo", home=home).later == ()


def test_control_a_foreign_edit_between_the_installs_breaks_the_link(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    foreign_edit(cfg)
    inst.install(cfg, "fetch", artifact=artifact, home=home)

    assert inst.uninstall(cfg, "echo", home=home).later == ()


def test_control_every_ordinary_uninstall_names_no_later_install(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    assert inst.uninstall(cfg, "fetch", home=home).later == ()
    assert inst.uninstall(cfg, "echo", home=home).later == ()


def test_cli_fifo_first_uninstall_says_the_later_install_is_still_wrapped(
        project, tmp_path):
    home = tmp_path / "h"
    out = _run(project, home, ("install", "echo"), ("install", "fetch"),
               ("uninstall", "echo"))

    assert STACKED in out[2]
    assert "'fetch'" in out[2]
    assert "sunglasses uninstall --config " in out[2]
    assert "-- fetch" in out[2]
    assert CHANGED not in out[2]


def test_cli_control_a_foreign_edit_keeps_the_generic_warning_on_step_1(
        project, tmp_path):
    home = tmp_path / "h"
    _run(project, home, ("install", "echo"), ("install", "fetch"))
    foreign_edit(project / ".mcp.json")
    out = _run(project, home, ("uninstall", "echo"))

    assert CHANGED in out[0]
    assert STACKED not in out[0]


def test_cli_three_stacked_wraps_name_both_later_installs(project, tmp_path):
    cfg = project / ".mcp.json"
    cfg.write_bytes((json.dumps({"mcpServers": {
        **json.loads(CANON)["mcpServers"],
        "third": {"command": "third-server", "args": []}}}, indent=2)
        + "\n").encode("utf-8"))
    home = tmp_path / "h"
    out = _run(project, home, ("install", "echo"), ("install", "fetch"),
               ("install", "third"), ("uninstall", "echo"))

    assert "later sunglasses installs of 'fetch', 'third' are still wrapped" in out[3]
    assert "-- fetch and sunglasses uninstall --config " in out[3]
    assert out[3].count("sunglasses uninstall --config ") == 2


# --------------------------- the printed undo command, run (round r1 findings)
#
# The hint names a command to run. It is only a hint if running it does what it
# says, so these rows run the printed text through a shell-style split and check
# the wrapper is gone: the config that was named, from any folder, and a server
# name that has a space or starts with a dash.

import re
import shlex


def _printed_commands(stdout):
    found = re.search(r"run (?P<cmds>.+?) to restore the original", stdout)
    assert found, stdout
    return found.group("cmds").split(" and sunglasses ")


@pytest.mark.parametrize("later", ["fetch", "my server", "-dash"])
def test_the_printed_undo_command_runs_against_the_named_config(
        tmp_path, later):
    cfg = tmp_path / "elsewhere" / "custom config.json"
    cfg.parent.mkdir()
    servers = {"echo": {"command": "echo-server", "args": ["--stdio"]},
               later: {"command": "later-server", "args": []}}
    cfg.write_bytes((json.dumps({"mcpServers": servers}, indent=2)
                     + "\n").encode("utf-8"))
    home = tmp_path / "h"
    cwd = tmp_path / "somewhere-else"
    cwd.mkdir()
    for name in ("echo", later):
        r = sg("install", "--config", str(cfg), "--", name, cwd=cwd, home=home)
        assert r.returncode == 0, (name, r.stdout, r.stderr)

    first = sg("uninstall", "--config", str(cfg), "--", "echo",
               cwd=cwd, home=home)
    assert first.returncode == 0, (first.stdout, first.stderr)
    (printed,) = _printed_commands(first.stdout)
    argv = shlex.split(printed)
    assert argv[0] == "sunglasses"

    ran = sg(*argv[1:], cwd=cwd, home=home)

    assert ran.returncode == 0, (printed, ran.stdout, ran.stderr)
    assert json.loads(read(cfg))["mcpServers"] == servers


def test_every_printed_undo_command_names_the_config_it_was_given(tmp_path):
    cfg = tmp_path / "x" / "c.json"
    cfg.parent.mkdir()
    cfg.write_bytes((json.dumps({"mcpServers": {
        **json.loads(CANON)["mcpServers"],
        "third": {"command": "third-server", "args": []}}}, indent=2)
        + "\n").encode("utf-8"))
    home = tmp_path / "h"
    for name in ("echo", "fetch", "third"):
        r = sg("install", "--config", str(cfg), name, cwd=tmp_path, home=home)
        assert r.returncode == 0, (r.stdout, r.stderr)
    out = sg("uninstall", "--config", str(cfg), "echo", cwd=tmp_path, home=home)

    commands = _printed_commands(out.stdout)

    assert len(commands) == 2
    assert all(str(cfg) in shlex.split(c) for c in commands)


# ------------------------ a record's file name is not evidence of what is wrapped

def test_control_a_misplaced_record_does_not_name_a_server_that_is_not_wrapped(
        cfg, home, artifact):
    """Install `echo`, then `fetch`; move fetch's record to the name of a third
    server that is in the file but never wrapped. The digests still chain, and
    the line used to name that third server, which is direct, and omit `fetch`."""
    cfg.write_bytes((json.dumps({"mcpServers": {
        **json.loads(CANON)["mcpServers"],
        "third": {"command": "third-server", "args": []}}}, indent=2)
        + "\n").encode("utf-8"))
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    records = pathlib.Path(home) / "proxy" / "installs"
    (records / "fetch.json").rename(records / "third.json")

    assert inst.uninstall(cfg, "echo", home=home).later == ()


def test_control_the_named_server_must_still_be_the_wrapper_the_record_installed(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    rec = pathlib.Path(home) / "proxy" / "installs" / "fetch.json"
    body = json.loads(rec.read_text(encoding="utf-8"))
    body["installed_entry"] = {"command": "something-else", "args": []}
    rec.write_text(json.dumps(body, indent=2), encoding="utf-8")

    assert inst.uninstall(cfg, "echo", home=home).later == ()


# ------------------------------------------------ the earlier-original qualifier

def test_only_the_final_fifo_uninstall_reports_an_earlier_original(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    first = inst.uninstall(cfg, "echo", home=home)
    last = inst.uninstall(cfg, "fetch", home=home)

    assert (first.byte_exact, first.earlier) == (False, False)
    assert (last.byte_exact, last.earlier) == (True, True)


def test_lifo_uninstalls_report_their_own_original_not_an_earlier_one(
        cfg, home, artifact):
    inst.install(cfg, "echo", artifact=artifact, home=home)
    inst.install(cfg, "fetch", artifact=artifact, home=home)
    top = inst.uninstall(cfg, "fetch", home=home)
    bottom = inst.uninstall(cfg, "echo", home=home)

    assert (top.byte_exact, top.earlier) == (True, False)
    assert (bottom.byte_exact, bottom.earlier) == (True, False)


# ------------------------- a failure while serialising the restore closes the fd

def test_a_failed_restore_serialisation_releases_the_held_authority(
        cfg, home, artifact, monkeypatch):
    """The entry-only restore after an unusable retained copy holds one open
    descriptor as its authority. Serialising the restored document can fail
    before the compare-and-swap is entered, and the descriptor must still be
    closed and no scoped write state left behind."""
    inst.install(cfg, "echo", artifact=artifact, home=home)
    cfg.write_text(json.dumps(json.loads(cfg.read_text()), indent=4))
    before = read(cfg)
    retained = pathlib.Path(home) / "proxy" / "installs" / "echo.original"
    authority = retained.open("rb")

    def unavailable(*args, **kw):
        raise inst._RetainedUnusable(inst.ConfigConflict("injected"))

    monkeypatch.setattr(inst, "_retained_of", unavailable)
    monkeypatch.setattr(inst, "_failed_copy_is_present", lambda *a, **k: True)
    monkeypatch.setattr(inst, "_authorise_from_one_fd", lambda *a, **k: authority)
    real_dumps = inst.json.dumps

    def fail(doc, *args, **kw):
        if isinstance(doc, dict) and "mcpServers" in doc:
            raise ValueError("injected serialization failure")
        return real_dumps(doc, *args, **kw)

    monkeypatch.setattr(inst.json, "dumps", fail)
    try:
        with pytest.raises(ValueError, match="injected serialization"):
            inst.uninstall(cfg, "echo", home=home)
        assert read(cfg) == before
        assert authority.closed
        assert not (inst._AUTHORISED or inst._EXPECTED or inst._HELD
                    or inst._LOCK_FOR)
    finally:
        authority.close()


# ------------- two servers with the same wrapper: the record's name is still evidence

def _three_with_one_command(cfg):
    entry = {"command": "same-server", "args": ["--stdio"]}
    cfg.write_bytes((json.dumps({"mcpServers": {n: dict(entry) for n in "cab"}},
                                indent=2) + "\n").encode("utf-8"))


def test_control_identical_wrappers_still_name_the_actual_later_installs(
        cfg, home, artifact):
    _three_with_one_command(cfg)
    for name in ("c", "a", "b"):
        inst.install(cfg, name, artifact=artifact, home=home)

    assert inst.uninstall(cfg, "c", home=home).later == ("a", "b")


def test_a_moved_record_is_not_taken_for_the_install_of_an_identical_wrapper(
        cfg, home, artifact):
    """Install c, a, b with one original entry, so the three wrappers are equal;
    put b's record under c's name. The digests still chain and the entry under
    that name is exactly the wrapper, so only the record's own retained-original
    path says whose install it was."""
    _three_with_one_command(cfg)
    for name in ("c", "a", "b"):
        inst.install(cfg, name, artifact=artifact, home=home)
    records = pathlib.Path(home) / "proxy" / "installs"
    (records / "b.json").replace(records / "c.json")

    assert inst.uninstall(cfg, "a", home=home).later == ()


def test_a_moved_record_prints_the_generic_warning_and_no_command(tmp_path):
    cfg = tmp_path / "c.json"
    _three_with_one_command(cfg)
    home = tmp_path / "h"
    for name in ("c", "a", "b"):
        assert sg("install", "--config", str(cfg), name, cwd=tmp_path,
                  home=home).returncode == 0
    (b_record,) = home.rglob("installs/b.json")
    b_record.replace(b_record.with_name("c.json"))

    out = sg("uninstall", "--config", str(cfg), "a", cwd=tmp_path, home=home)

    assert out.returncode == 0, (out.stdout, out.stderr)
    assert WARNING in out.stdout and "to restore the original" not in out.stdout


# ----------------------------- a Windows undo hint is printed only for plain words

class _Nt:
    """The `os` module as seen from a Windows platform, for the one name that
    decides the quoting rule."""
    name = "nt"

    def __getattr__(self, attr):
        return getattr(os, attr)


@pytest.fixture
def on_windows(monkeypatch):
    from sunglasses import cli
    monkeypatch.setattr(cli, "os", _Nt())
    return cli


@pytest.mark.parametrize("config,name", [
    ("C:\\Users\\me\\.claude.json", "fetch"),
    ("/home/me/.mcp.json", "my-server_2"),
    ("rel/.mcp.json", "-dash"),
])
def test_windows_prints_a_plain_command_unquoted(on_windows, config, name):
    assert on_windows._uninstall_command(name, config) == (
        f"sunglasses uninstall --config {config} -- {name}")


@pytest.mark.parametrize("config,name", [
    ("C:\\Users\\me\\.mcp.json", "a&b"),
    ("C:\\Users\\me\\.mcp.json", "%PATH%"),
    ("C:\\Users\\me\\.mcp.json", "$env:HOME"),
    ("C:\\Users\\me\\.mcp.json", "it's"),
    ("C:\\Users\\me\\.mcp.json", 'say "x"'),
    ("C:\\Users\\me\\.mcp.json", "a b"),
    ("C:\\Users\\me\\.mcp.json", "a;b"),
    ("C:\\Users\\me\\.mcp.json", "a|b"),
    ("C:\\Users\\me\\.mcp.json", "a^b"),
    ("C:\\Users\\me\\.mcp.json", "a`b"),
    ("C:\\Users\\me\\.mcp.json", "a(b)"),
    ("C:\\Users\\me\\.mcp.json", ""),
    ("C:\\Program Files\\app\\.mcp.json", "fetch"),
    ("C:\\Users\\me\\a&b.json", "fetch"),
])
def test_windows_prints_no_command_for_a_word_a_shell_would_read(
        on_windows, config, name):
    assert on_windows._uninstall_command(name, config) is None


def test_posix_still_quotes_every_word(monkeypatch):
    from sunglasses import cli
    monkeypatch.setattr(cli, "os", types.SimpleNamespace(name="posix"))
    assert cli._uninstall_command("a b", "/x y/c.json") == (
        "sunglasses uninstall --config '/x y/c.json' -- 'a b'")


def test_windows_without_a_command_says_what_to_do(
        on_windows, tmp_path, monkeypatch, capsys):
    cfg = tmp_path / "c.json"
    cfg.write_bytes((json.dumps({"mcpServers": {
        "echo": {"command": "echo-server", "args": []},
        "a&b": {"command": "later-server", "args": []}}}, indent=2)
        + "\n").encode("utf-8"))
    home = tmp_path / "h"
    for name in ("echo", "a&b"):
        assert sg("install", "--config", str(cfg), "--", name, cwd=tmp_path,
                  home=home).returncode == 0
    monkeypatch.setenv("SUNGLASSES_HOME", str(home))
    monkeypatch.setenv("HOME", str(home))

    with pytest.raises(SystemExit) as stop:
        on_windows.cmd_uninstall(types.SimpleNamespace(config=str(cfg), name="echo"))

    printed = capsys.readouterr().out
    assert stop.value.code == 0
    assert "'a&b'" in printed and "--config" in printed
    assert "sunglasses uninstall" not in printed
