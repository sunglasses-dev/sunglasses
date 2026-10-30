"""test_pin_unreadable_configs.py — `pin` names every config file it could not read.

A config file that cannot be read declares no servers as far as `pin` is
concerned. When it was dropped without a word, `pin` reported a short server
list as if it were complete, and the servers declared in that file were never
pinned. Now each unreadable file is returned with its reason, `pin` prints one
line per file, and the run ends in doubt (exit 3) instead of a clean finish.
A missing file is the normal case and stays silent.
"""
import json
import os
import sys

import pytest

from sunglasses.firewall import discover_plugin_servers

from test_firewall_pin import TOOLS_V1, TOOLS_V2, _cli, _fake_server


def _read(paths):
    from sunglasses.firewall import read_mcp_configs
    return read_mcp_configs(paths)


def _reasons(skipped):
    return {path: reason for path, reason in skipped}


# ── discovery returns what it skipped ───────────────────────────────────────

def test_malformed_json_is_named_with_its_reason(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    servers, skipped = _read([bad])
    assert servers == {}
    assert list(_reasons(skipped)) == [str(bad)]
    assert "not valid JSON" in skipped[0][1]


def test_invalid_utf8_is_named(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_bytes(b'{"mcpServers": {"a": {"command": "\xff\xfe"}}}')
    servers, skipped = _read([bad])
    assert servers == {}
    assert "UTF-8" in _reasons(skipped)[str(bad)]


def test_nesting_too_deep_to_read_is_named(tmp_path, monkeypatch):
    import json as _json

    def too_deep(_text, *args, **kwargs):
        raise RecursionError
    monkeypatch.setattr(_json, "loads", too_deep)
    deep = tmp_path / "deep.json"
    deep.write_text("[" * 10 + "]" * 10)
    servers, skipped = _read([deep])
    assert servers == {}
    assert "too deeply" in _reasons(skipped)[str(deep)]


def test_a_directory_where_a_file_is_expected_is_named(tmp_path):
    folder = tmp_path / ".mcp.json"
    folder.mkdir()
    servers, skipped = _read([folder])
    assert servers == {}
    assert "directory" in _reasons(skipped)[str(folder)]


@pytest.mark.skipif(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs POSIX permissions and a non-root user")
def test_permission_denied_is_named(tmp_path):
    locked = tmp_path / "locked.json"
    locked.write_text(json.dumps({"mcpServers": {"a": {"command": "x"}}}))
    locked.chmod(0)
    try:
        servers, skipped = _read([locked])
    finally:
        locked.chmod(0o600)
    assert servers == {}
    assert "permission denied" in _reasons(skipped)[str(locked)]


def test_a_top_level_that_is_not_an_object_is_named(tmp_path):
    listy = tmp_path / "list.json"
    listy.write_text("[1, 2]")
    servers, skipped = _read([listy])
    assert servers == {}
    assert "list" in _reasons(skipped)[str(listy)]


def test_mcpservers_that_is_not_an_object_is_named(tmp_path):
    odd = tmp_path / "odd.json"
    odd.write_text(json.dumps({"mcpServers": ["a", "b"]}))
    servers, skipped = _read([odd])
    assert servers == {}
    assert "mcpServers" in _reasons(skipped)[str(odd)]


def test_an_absent_file_stays_silent(tmp_path):
    servers, skipped = _read([tmp_path / "nope.json", tmp_path / "no" / "dir" / "x.json"])
    assert servers == {} and skipped == []


def test_an_object_that_declares_no_servers_stays_silent(tmp_path):
    """`~/.claude.json` is full of unrelated settings and often declares none."""
    other = tmp_path / "claude.json"
    other.write_text(json.dumps({"theme": "dark", "projects": {}}))
    servers, skipped = _read([other])
    assert servers == {} and skipped == []


def test_one_bad_file_does_not_hide_the_others(tmp_path):
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"mcpServers": {"alpha": {"command": "a"}}}))
    bad = tmp_path / "bad.json"
    bad.write_text("{nope")
    servers, skipped = _read([good, bad])
    assert set(servers) == {"alpha"}
    assert list(_reasons(skipped)) == [str(bad)]


def test_the_reason_never_carries_the_file_contents(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"env": {"TOKEN": "sk-live-do-not-echo-this"} oops')
    _, skipped = _read([bad])
    assert "sk-live-do-not-echo-this" not in skipped[0][1]


def test_discover_mcp_servers_still_returns_just_the_servers(tmp_path):
    from sunglasses.firewall import discover_mcp_servers
    good = tmp_path / "good.json"
    good.write_text(json.dumps({"mcpServers": {"alpha": {"command": "a"}}}))
    assert set(discover_mcp_servers([good, tmp_path / "absent.json"])) == {"alpha"}


# ── plugin discovery names its own unreadable files ─────────────────────────

def test_an_unreadable_plugin_manifest_is_named(tmp_path):
    from sunglasses.firewall import read_plugin_servers
    manifest = tmp_path / "installed_plugins.json"
    manifest.write_text("{not json")
    servers, skipped = read_plugin_servers(manifest)
    assert servers == {}
    assert list(_reasons(skipped)) == [str(manifest)]


def test_a_plugin_manifest_that_is_not_an_object_does_not_crash(tmp_path):
    from sunglasses.firewall import read_plugin_servers
    manifest = tmp_path / "installed_plugins.json"
    manifest.write_text("[]")
    servers, skipped = read_plugin_servers(manifest)
    assert servers == {} and len(skipped) == 1


def test_an_unreadable_plugin_mcp_file_is_named(tmp_path):
    from sunglasses.firewall import read_plugin_servers
    install = tmp_path / "cache" / "vision" / "1.0.0"
    install.mkdir(parents=True)
    (install / ".mcp.json").write_text("{broken")
    manifest = tmp_path / "installed_plugins.json"
    manifest.write_text(json.dumps({"plugins": {"vision@mkt": [{"installPath": str(install)}]}}))
    servers, skipped = read_plugin_servers(manifest)
    assert servers == {}
    assert list(_reasons(skipped)) == [str(install / ".mcp.json")]


@pytest.mark.skipif(sys.platform == "win32" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="needs POSIX permissions and a non-root user")
def test_a_plugin_install_folder_that_cannot_be_read_is_named(tmp_path):
    from sunglasses.firewall import read_plugin_servers
    install = tmp_path / "cache" / "vision" / "1.0.0"
    install.mkdir(parents=True)
    (install / ".mcp.json").write_text(json.dumps({"a": {"command": "x"}}))
    manifest = tmp_path / "installed_plugins.json"
    manifest.write_text(json.dumps({"plugins": {"vision@mkt": [{"installPath": str(install)}]}}))
    install.chmod(0)
    try:
        servers, skipped = read_plugin_servers(manifest)
    finally:
        install.chmod(0o700)
    assert servers == {}
    assert "permission denied" in _reasons(skipped)[str(install / ".mcp.json")]


def test_a_plugin_install_folder_without_an_mcp_file_stays_silent(tmp_path):
    from sunglasses.firewall import read_plugin_servers
    install = tmp_path / "cache" / "plain" / "1.0.0"
    install.mkdir(parents=True)
    manifest = tmp_path / "installed_plugins.json"
    manifest.write_text(json.dumps({"plugins": {"plain@mkt": [{"installPath": str(install)},
                                                              {"installPath": str(tmp_path / "gone")}]}}))
    assert read_plugin_servers(manifest) == ({}, [])


def test_a_missing_manifest_stays_silent(tmp_path):
    from sunglasses.firewall import read_plugin_servers
    assert read_plugin_servers(tmp_path / "absent.json") == ({}, [])
    assert discover_plugin_servers(tmp_path / "absent.json") == {}


# ── the CLI ─────────────────────────────────────────────────────────────────

def _setup(tmp_path, project_config):
    """A good server in the user config, `project_config` written as the project's .mcp.json."""
    home = tmp_path / "home"
    project = tmp_path / "proj"
    project.mkdir()
    home.mkdir()
    (home / ".claude.json").write_text(json.dumps(
        {"mcpServers": {"github": _fake_server(tmp_path, TOOLS_V1, "good.py")}}))
    if isinstance(project_config, str):
        (project / ".mcp.json").write_text(project_config)
    elif project_config == "directory":
        (project / ".mcp.json").mkdir()
    return home, project


def test_pin_names_the_unreadable_file_pins_the_rest_and_ends_in_doubt(tmp_path):
    home, project = _setup(tmp_path, "{not json")
    proc = _cli(["pin"], home, cwd=str(project))
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert str(project / ".mcp.json") in proc.stdout
    assert "not valid JSON" in proc.stdout
    assert "NOT pinned" in proc.stdout
    pins = json.loads((home / "pins.json").read_text())
    assert "mcp__github__create_issue" in pins["tools"]
    last = [line for line in proc.stdout.splitlines() if line.strip()][-1]
    assert "Incomplete" in last


def test_pin_with_only_an_unreadable_file_does_not_say_nothing_to_pin(tmp_path):
    home = tmp_path / "home"
    project = tmp_path / "proj"
    home.mkdir()
    project.mkdir()
    (project / ".mcp.json").mkdir()
    proc = _cli(["pin"], home, cwd=str(project))
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert str(project / ".mcp.json") in proc.stdout
    assert "Nothing to pin" not in proc.stdout


def test_pin_with_no_config_files_at_all_is_unchanged(tmp_path):
    home = tmp_path / "home"
    project = tmp_path / "proj"
    home.mkdir()
    project.mkdir()
    proc = _cli(["pin"], home, cwd=str(project))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "No MCP servers configured" in proc.stdout
    assert "Incomplete" not in proc.stdout


def test_pin_check_clean_but_with_an_unreadable_file_ends_in_doubt(tmp_path):
    home, project = _setup(tmp_path, None)
    assert _cli(["pin"], home, cwd=str(project)).returncode == 0
    (project / ".mcp.json").write_text("{not json")
    proc = _cli(["pin", "--check"], home, cwd=str(project))
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert str(project / ".mcp.json") in proc.stdout


def test_drift_outranks_doubt(tmp_path):
    home, project = _setup(tmp_path, None)
    assert _cli(["pin"], home, cwd=str(project)).returncode == 0
    (home / ".claude.json").write_text(json.dumps(
        {"mcpServers": {"github": _fake_server(tmp_path, TOOLS_V2, "drift.py")}}))
    (project / ".mcp.json").write_text("{not json")
    proc = _cli(["pin", "--check"], home, cwd=str(project))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert str(project / ".mcp.json") in proc.stdout


def test_quiet_speaks_up_about_an_unreadable_file(tmp_path):
    home, project = _setup(tmp_path, "{not json")
    proc = _cli(["pin", "--quiet"], home, cwd=str(project))
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "could not be read" in proc.stdout
    assert len([line for line in proc.stdout.splitlines() if line.strip()]) == 1


def test_quiet_drift_with_an_unreadable_file_is_one_line(tmp_path):
    home, project = _setup(tmp_path, None)
    assert _cli(["pin"], home, cwd=str(project)).returncode == 0
    (home / ".claude.json").write_text(json.dumps(
        {"mcpServers": {"github": _fake_server(tmp_path, TOOLS_V2, "drift.py")}}))
    (project / ".mcp.json").write_text("{not json")
    proc = _cli(["pin", "--check", "--quiet"], home, cwd=str(project))
    assert proc.returncode == 1, proc.stdout + proc.stderr
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    assert len(lines) == 1, proc.stdout
    assert "drift" in lines[0] and "could not be read" in lines[0]


def test_a_clean_run_has_no_doubt_line(tmp_path):
    home, project = _setup(tmp_path, None)
    proc = _cli(["pin"], home, cwd=str(project))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Incomplete" not in proc.stdout


def test_pin_help_lists_the_exit_codes(tmp_path):
    proc = _cli(["pin", "--help"], tmp_path)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = [ln.strip() for ln in proc.stdout.splitlines()]
    assert "0  done, no drift (may mean nothing was read or pinned)" in lines
    assert "1  drift or no usable pins file (--check), or an error" in lines
    assert "2  consent refused, or a usage error" in lines
    assert "3  a config file could not be read" in lines
