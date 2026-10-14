"""install.py rewrites the user's own MCP client config, so these pin four
ways a careful config writer must not misbehave: a server name that reaches the
filesystem, a symbolic-link config, a number that overflows to Infinity, and an
uninstall that overwrites work a second process finished meanwhile.

Nothing here touches the real home: every call passes a fake `home`.
"""
import json
import os
import pathlib
import subprocess
import sys

import pytest

from sunglasses import install as I

ART = I.resolve_artifact()


def fresh(tmp_path, doc=None, raw=None):
    home = tmp_path / "home"
    proj = tmp_path / "proj"
    home.mkdir()
    proj.mkdir()
    cfg = proj / ".mcp.json"
    if raw is None:
        raw = (json.dumps(doc, indent=2) + "\n").encode()
    cfg.write_bytes(raw)
    os.chmod(cfg, 0o600)
    return home, cfg


def wrapped(cfg, name):
    return I.MARKER in json.loads(cfg.read_bytes())["mcpServers"][name]


# --- the server name reaches the filesystem ---------------------------------

def test_name_with_dotdot_never_touches_files_outside_the_records_dir(tmp_path):
    home, cfg = fresh(tmp_path, {"mcpServers": {}})
    victim = tmp_path / "victim"
    victim.mkdir()
    keep = victim / "keep.original"
    keep.write_text("IMPORTANT USER DATA")
    os.chmod(keep, 0o644)
    installs = home / "proxy" / "installs"
    name = os.path.relpath(victim / "keep", installs)
    with pytest.raises(I.ConfigConflict):
        I.install(cfg, name, artifact=ART, home=home, argv=["echo", "hi"])
    assert keep.read_text() == "IMPORTANT USER DATA"


def test_absolute_name_is_refused_before_any_write(tmp_path):
    home, cfg = fresh(tmp_path, {"mcpServers": {}})
    outside = tmp_path / "abs"
    outside.mkdir()
    with pytest.raises(I.ConfigConflict):
        I.install(cfg, str(outside / "target"), artifact=ART, home=home,
                  argv=["echo"])
    assert not (outside / "target.original").exists()


@pytest.mark.parametrize("name", ["", ".", "..", "a/b", "a\\b", "a\x00b"])
def test_unusable_names_are_refused_by_install_and_uninstall(tmp_path, name):
    raw = b'{"mcpServers": {}}\n'
    home, cfg = fresh(tmp_path, raw=raw)
    with pytest.raises(I.ConfigConflict):
        I.install(cfg, name, artifact=ART, home=home, argv=["echo"])
    with pytest.raises(I.ConfigConflict):
        I.uninstall(cfg, name, home=home)
    assert cfg.read_bytes() == raw


def test_an_ordinary_name_still_installs(tmp_path):
    home, cfg = fresh(tmp_path, {"mcpServers": {"gh-2.x_ok": {"command": "npx"}}})
    I.install(cfg, "gh-2.x_ok", artifact=ART, home=home)
    assert wrapped(cfg, "gh-2.x_ok")


# --- a symbolic-link config --------------------------------------------------

def test_symlinked_config_is_refused_and_both_paths_stay_untouched(tmp_path):
    home, cfg = fresh(tmp_path, {"mcpServers": {"gh": {"command": "npx"}}})
    real = tmp_path / "dotfiles" / "mcp.json"
    real.parent.mkdir()
    real.write_bytes(cfg.read_bytes())
    before = real.read_bytes()
    cfg.unlink()
    os.symlink(real, cfg)
    with pytest.raises(I.ConfigConflict) as e:
        I.install(cfg, "gh", artifact=ART, home=home)
    assert str(real) in str(e.value)
    assert cfg.is_symlink() and real.read_bytes() == before
    with pytest.raises(I.ConfigConflict):
        I.uninstall(cfg, "gh", home=home)
    assert cfg.is_symlink() and real.read_bytes() == before


def test_a_config_that_became_a_link_after_install_is_not_replaced(tmp_path):
    home, cfg = fresh(tmp_path, {"mcpServers": {"gh": {"command": "npx"}}})
    real = tmp_path / "dotfiles" / "mcp.json"
    real.parent.mkdir()
    cfg.rename(real)
    I.install(real, "gh", artifact=ART, home=home)
    os.symlink(real, cfg)
    before = real.read_bytes()
    with pytest.raises(I.ConfigConflict) as e:
        I.uninstall(cfg, "gh", home=home)
    assert str(real) in str(e.value)
    assert cfg.is_symlink() and real.read_bytes() == before
    I.uninstall(real, "gh", home=home)
    assert not wrapped(real, "gh")


def test_naming_the_file_behind_the_link_works(tmp_path):
    home, cfg = fresh(tmp_path, {"mcpServers": {"gh": {"command": "npx"}}})
    real = tmp_path / "dotfiles" / "mcp.json"
    real.parent.mkdir()
    real.write_bytes(cfg.read_bytes())
    cfg.unlink()
    os.symlink(real, cfg)
    I.install(real, "gh", artifact=ART, home=home)
    assert wrapped(real, "gh") and cfg.is_symlink()
    I.uninstall(real, "gh", home=home)
    assert not wrapped(real, "gh")


# --- numeric overflow --------------------------------------------------------

@pytest.mark.parametrize("number", [b"1e400", b"-1e400"])
def test_overflowing_number_is_refused_before_any_mutation(tmp_path, number):
    raw = b'{"mcpServers":{"gh":{"command":"npx","timeout":' + number + b'}}}'
    home, cfg = fresh(tmp_path, raw=raw)
    with pytest.raises((I.ConfigConflict, I.ConfigIOError)):
        I.install(cfg, "gh", artifact=ART, home=home)
    assert cfg.read_bytes() == raw


def test_large_but_finite_number_still_installs(tmp_path):
    raw = b'{"mcpServers":{"gh":{"command":"npx","timeout":1e300}}}'
    home, cfg = fresh(tmp_path, raw=raw)
    I.install(cfg, "gh", artifact=ART, home=home)
    out = cfg.read_bytes()
    assert b"Infinity" not in out
    I._strict_loads(out, "config")
    I.uninstall(cfg, "gh", home=home)


# --- uninstall is a compare-and-swap ----------------------------------------

def test_uninstall_does_not_erase_a_concurrent_install(tmp_path):
    home, cfg = fresh(tmp_path, {"mcpServers": {"a": {"command": "cmdA"},
                                                "b": {"command": "cmdB"}}})
    I.install(cfg, "a", artifact=ART, home=home)
    orig_read = I._read_bytes_and_identity
    code = (
        "import pathlib\n"
        "from sunglasses import install as I\n"
        f"I.install(pathlib.Path({str(cfg)!r}), 'b', artifact=I.resolve_artifact(),"
        f" home=pathlib.Path({str(home)!r}))\n"
        "print('second process installed b')\n"
    )
    fired = []

    def read_then_let_the_other_process_install(path):
        data = orig_read(path)
        if not fired:
            fired.append(True)
            r = subprocess.run([sys.executable, "-c", code], capture_output=True,
                               text=True, timeout=60, cwd=str(tmp_path))
            assert "second process installed b" in r.stdout, r.stderr[-500:]
        return data

    I._read_bytes_and_identity = read_then_let_the_other_process_install
    try:
        with pytest.raises(I.ConfigConflict):
            I.uninstall(cfg, "a", home=home)
    finally:
        I._read_bytes_and_identity = orig_read
    assert wrapped(cfg, "b"), "uninstall of 'a' erased the install of 'b'"
    assert wrapped(cfg, "a"), "the refused uninstall must leave 'a' as it was"
    I.uninstall(cfg, "a", home=home)
    I.uninstall(cfg, "b", home=home)
    assert not wrapped(cfg, "a") and not wrapped(cfg, "b")


# --- a fault while looking at the config is one typed refusal ---------------

def _fail_stat_of(monkeypatch, cfg, function):
    real = getattr(os, function)

    def faulting(path, *a, **k):
        if str(path) == str(cfg):
            raise OSError("injected")
        return real(path, *a, **k)

    monkeypatch.setattr(os, function, faulting)


def test_a_fault_inspecting_the_config_is_a_typed_refusal_on_install(tmp_path,
                                                                     monkeypatch):
    home, cfg = fresh(tmp_path, {"mcpServers": {"gh": {"command": "npx"}}})
    before = cfg.read_bytes()
    _fail_stat_of(monkeypatch, cfg, "lstat")
    with pytest.raises(I.ConfigIOError):
        I.install(cfg, "gh", artifact=ART, home=home)
    monkeypatch.undo()
    assert cfg.read_bytes() == before


def test_a_fault_inspecting_the_config_is_a_typed_refusal_on_uninstall(tmp_path,
                                                                       monkeypatch):
    home, cfg = fresh(tmp_path, {"mcpServers": {"gh": {"command": "npx"}}})
    I.install(cfg, "gh", artifact=ART, home=home)
    before = cfg.read_bytes()
    _fail_stat_of(monkeypatch, cfg, "lstat")
    with pytest.raises(I.ConfigIOError):
        I.uninstall(cfg, "gh", home=home)
    monkeypatch.undo()
    assert cfg.read_bytes() == before and wrapped(cfg, "gh")


def test_a_stat_fault_on_the_uninstall_path_is_typed(tmp_path, monkeypatch):
    home, cfg = fresh(tmp_path, {"mcpServers": {"gh": {"command": "npx"}}})
    I.install(cfg, "gh", artifact=ART, home=home)
    before = cfg.read_bytes()
    real = pathlib.Path.stat
    monkeypatch.setattr(pathlib.Path, "stat",
                        lambda p, *a, **k: (_ for _ in ()).throw(OSError("injected"))
                        if p.name == ".mcp.json" else real(p, *a, **k))
    with pytest.raises(I.ConfigIOError):
        I.uninstall(cfg, "gh", home=home)
    monkeypatch.undo()
    assert cfg.read_bytes() == before and wrapped(cfg, "gh")


def test_a_missing_config_is_not_mistaken_for_a_link(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    with pytest.raises((I.ConfigConflict, I.ConfigIOError)) as e:
        I.install(tmp_path / "absent.json", "gh", artifact=ART, home=home)
    assert "symbolic link" not in str(e.value)
