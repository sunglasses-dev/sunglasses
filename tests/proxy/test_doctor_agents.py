"""`sunglasses doctor --agents`: which other agents have MCP servers configured.

The flag lists the MCP config files of Cursor, Codex, Gemini CLI and Windsurf (and the
two Claude Code files) beside the normal report. These tests pin what the list is
allowed to say:

* A file that is not there is `absent`. A file that is there and cannot be read, or
  is not what its format says, is UNREADABLE with a reason. The two are never mixed.
* Nothing but a server's name, how it is reached, the command's file name or the URL's
  host is shown. `env`, `args` and `headers` values and a URL's query and user name
  never reach stdout or `--json`.
* Without the flag the output is byte for byte what it was.
* The flag does not move the exit code: the headline is about the Claude route.

Every test runs against a throwaway home and project folder.
"""
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)

from sunglasses.proxy import agent_discovery  # noqa: E402

SECRET = "sk-live-0123456789SECRETVALUE"


def _doctor(*args, home, cwd):
    env = {**os.environ, "PYTHONPATH": REPO, "HOME": str(home)}
    env.pop("XDG_CONFIG_HOME", None)
    return subprocess.run([sys.executable, "-m", "sunglasses.cli", "doctor", *args],
                          capture_output=True, text=True, cwd=str(cwd), env=env)


@pytest.fixture
def world(tmp_path):
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    return home, project


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text if isinstance(text, str) else json.dumps(text))
    return path


def _rows(home, project):
    return {(r["agent"], r["scope"], r["label"]): r for r in agent_discovery.discover(home=home, cwd=project)}


def _servers(home, project, agent, scope, label=""):
    return _rows(home, project)[(agent, scope, label)]


# 1. What it finds ---------------------------------------------------------

def test_each_agents_file_is_read_and_each_server_is_listed(world):
    home, project = world
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {
        "files": {"command": "/usr/local/bin/npx", "args": ["-y", "x"]},
        "remote": {"url": "https://api.example.com/mcp"}}})
    _write(project / ".gemini" / "settings.json", {"theme": "x", "mcpServers": {
        "g": {"httpUrl": "https://g.example.org/stream"}}})
    _write(home / ".codeium" / "windsurf" / "mcp_config.json", {"mcpServers": {"w": {"command": "uvx"}}})
    _write(home / ".codeium" / "windsurf-next" / "mcp_config.json", {"mcpServers": {"n": {"serverUrl": "http://n.example.net/x"}}})

    cursor = _servers(home, project, "cursor", "user")
    assert cursor["state"] == "present"
    assert [(s["name"], s["transport"], s["via"], s["state"]) for s in cursor["servers"]] == [
        ("files", "stdio", "npx", "DIRECT"), ("remote", "remote", "api.example.com", "DIRECT")]
    assert [s["via"] for s in _servers(home, project, "gemini-cli", "project")["servers"]] == ["g.example.org"]
    assert [s["name"] for s in _servers(home, project, "windsurf", "user", "editor discovery, stable")["servers"]] == ["w"]
    assert [s["name"] for s in _servers(home, project, "windsurf", "user", "editor discovery, next")["servers"]] == ["n"]


@pytest.mark.skipif(agent_discovery._tomllib is None, reason="no TOML reader on this Python")
def test_codex_toml_servers_are_listed(world):
    home, project = world
    _write(home / ".codex" / "config.toml",
           'model = "x"\n[mcp_servers.docs]\ncommand = "node"\nargs = ["a"]\n'
           '[mcp_servers.web]\nurl = "https://web.example.com/mcp"\n')
    row = _servers(home, project, "codex", "user")
    assert [(s["name"], s["via"]) for s in row["servers"]] == [("docs", "node"), ("web", "web.example.com")]


def test_a_file_with_no_servers_key_is_present_with_none_and_says_so(world):
    home, project = world
    _write(home / ".gemini" / "settings.json", {"theme": "dark"})
    row = _servers(home, project, "gemini-cli", "user")
    assert (row["state"], row["servers"], row["reason"]) == ("present", [], "no mcpServers key")


def test_an_entry_with_no_command_and_no_url_is_listed_unverified_not_dropped(world):
    home, project = world
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"odd": {"note": "x"}, "bad": 7}})
    assert [(s["name"], s["state"]) for s in _servers(home, project, "cursor", "user")["servers"]] == [
        ("bad", "UNVERIFIED"), ("odd", "UNVERIFIED")]


def test_nothing_configured_is_absent_everywhere(world):
    home, project = world
    assert {r["state"] for r in agent_discovery.discover(home=home, cwd=project)} == {"absent"}


def test_the_shared_file_is_listed_once_when_the_project_is_the_home_folder(world):
    home, _ = world
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {}})
    rows = [r for r in agent_discovery.discover(home=home, cwd=home) if r["agent"] == "cursor"]
    assert [(r["scope"], r["path"]) for r in rows] == [("user", "~/.cursor/mcp.json")]


def test_the_order_is_fixed(world):
    home, project = world
    keys = [(r["agent"], r["scope"], r["path"]) for r in agent_discovery.discover(home=home, cwd=project)]
    assert keys == sorted(keys)


def test_the_windsurf_devin_path_the_current_docs_no_longer_name_is_not_read(world):
    home, project = world
    _write(home / ".config" / "devin" / "mcp_config.json", {"mcpServers": {"ghost": {"command": "x"}}})
    assert "ghost" not in json.dumps(agent_discovery.discover(home=home, cwd=project))


# 2. Absent is not unreadable ----------------------------------------------

@pytest.mark.parametrize("name, content, reason", [
    ("invalid", "{not json", "not valid JSON"),
    ("comment", '{\n // note\n "mcpServers": {}}', "not valid JSON"),
    ("list", "[]", "the top level is not an object"),
    ("wrongtype", json.dumps({"mcpServers": []}), "mcpServers is not an object"),
    ("binary", b"\xff\xfe\x00\x01", "not valid JSON"),
])
def test_a_present_file_that_is_not_usable_is_unreadable_with_its_reason(world, name, content, reason):
    home, project = world
    path = home / ".cursor" / "mcp.json"
    path.parent.mkdir(parents=True)
    path.write_bytes(content if isinstance(content, bytes) else content.encode())
    row = _servers(home, project, "cursor", "user")
    assert row["state"] == "UNREADABLE" and reason in row["reason"], row


@pytest.mark.skipif(os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
                    reason="permission bits are not enforced here")
def test_a_denied_file_is_unreadable_not_absent(world):
    home, project = world
    path = _write(home / ".cursor" / "mcp.json", {"mcpServers": {"a": {"command": "x"}}})
    path.chmod(0)
    try:
        row = _servers(home, project, "cursor", "user")
    finally:
        path.chmod(0o600)
    assert (row["state"], row["reason"], row["servers"]) == ("UNREADABLE", "permission denied", [])


def test_a_folder_where_the_file_belongs_is_unreadable(world):
    home, project = world
    (home / ".cursor" / "mcp.json").mkdir(parents=True)
    row = _servers(home, project, "cursor", "user")
    assert (row["state"], row["reason"]) == ("UNREADABLE", "a folder, not a file")


def test_a_parent_that_is_a_file_is_unreadable_not_absent(world):
    home, project = world
    (home / ".cursor").write_text("x")
    assert _servers(home, project, "cursor", "user")["state"] == "UNREADABLE"


def test_an_oversized_file_is_unreadable_and_not_parsed(world):
    home, project = world
    _write(home / ".cursor" / "mcp.json", '{"mcpServers": {}, "pad": "' + "x" * (agent_discovery.MAX_BYTES + 10) + '"}')
    row = _servers(home, project, "cursor", "user")
    assert (row["state"], row["reason"]) == ("UNREADABLE", "larger than 1 MiB")


def test_without_a_toml_reader_codex_is_unreadable_never_skipped(world, monkeypatch):
    home, project = world
    _write(home / ".codex" / "config.toml", '[mcp_servers.a]\ncommand = "x"\n')
    monkeypatch.setattr(agent_discovery, "_tomllib", None)
    row = _servers(home, project, "codex", "user")
    assert (row["state"], row["reason"]) == ("UNREADABLE", "toml parser unavailable on this Python")


@pytest.mark.skipif(agent_discovery._tomllib is None, reason="no TOML reader on this Python")
def test_a_broken_toml_file_is_unreadable(world):
    home, project = world
    _write(home / ".codex" / "config.toml", "[mcp_servers\nx =")
    assert _servers(home, project, "codex", "user")["reason"] == "not valid TOML"


def test_the_claude_files_keep_doctors_rule_for_a_missing_key(world):
    home, project = world
    _write(project / ".mcp.json", {"other": 1})
    row = _servers(home, project, "claude-code", "project")
    assert (row["state"], row["reason"]) == ("UNREADABLE", "no mcpServers object")


# 3. Links -----------------------------------------------------------------

@pytest.mark.skipif(os.name == "nt", reason="links need privileges on Windows")
def test_a_link_out_of_home_and_project_is_unreadable(world, tmp_path):
    home, project = world
    outside = _write(tmp_path / "elsewhere" / "mcp.json", {"mcpServers": {"x": {"command": "y"}}})
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").symlink_to(outside)
    row = _servers(home, project, "cursor", "user")
    assert row["state"] == "UNREADABLE" and "leaves the home folder" in row["reason"] and row["servers"] == []


@pytest.mark.skipif(os.name == "nt", reason="links need privileges on Windows")
def test_a_link_that_stays_inside_home_is_followed(world):
    home, project = world
    target = _write(home / "dotfiles" / "cursor.json", {"mcpServers": {"x": {"command": "y"}}})
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").symlink_to(target)
    assert [s["name"] for s in _servers(home, project, "cursor", "user")["servers"]] == ["x"]


# 4. What is never shown ---------------------------------------------------

def test_no_secret_in_a_file_reaches_stdout_or_json(world):
    home, project = world
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {
        "a": {"command": "/bin/run", "args": ["--token", SECRET], "env": {"AWS_SECRET_ACCESS_KEY": SECRET}},
        "b": {"url": f"https://user:{SECRET}@host.example.com/p?key={SECRET}", "headers": {"Authorization": f"Bearer {SECRET}"}},
        "c": {"command": f"API_KEY={SECRET} npx --flag"}}})
    for extra in ([], ["--json"]):
        proc = _doctor("--agents", *extra, home=home, cwd=project)
        assert SECRET not in proc.stdout + proc.stderr
        assert "host.example.com" in proc.stdout


def test_a_server_name_with_control_characters_is_escaped(world):
    home, project = world
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"evil\x1b[31mred": {"command": "x"}}})
    proc = _doctor("--agents", home=home, cwd=project)
    assert "\x1b" not in proc.stdout and "evil\\x1b[31mred" in proc.stdout


# 5. The command -----------------------------------------------------------

def test_the_flag_exists_and_prints_the_block(world):
    home, project = world
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"files": {"command": "npx"}}})
    proc = _doctor("--agents", home=home, cwd=project)
    assert "unrecognized arguments" not in proc.stderr, proc.stderr
    assert "Other agents' MCP configs" in proc.stdout
    assert "not routed through Sunglasses" in proc.stdout
    assert "~/.cursor/mcp.json" in proc.stdout and "DIRECT" in proc.stdout and "files" in proc.stdout
    assert "absent" in proc.stdout


def test_without_the_flag_the_output_is_unchanged_whatever_the_agents_hold(world):
    home, project = world
    before = _doctor(home=home, cwd=project)
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"files": {"command": "npx"}}})
    after = _doctor(home=home, cwd=project)
    assert (before.stdout, before.returncode) == (after.stdout, after.returncode)
    assert "Other agents" not in after.stdout
    assert "agents" not in json.loads(_doctor("--json", home=home, cwd=project).stdout)


def test_the_flag_does_not_change_the_exit_code(world):
    home, project = world
    _write(home / ".cursor" / "mcp.json", "{broken")
    assert _doctor("--agents", home=home, cwd=project).returncode == _doctor(home=home, cwd=project).returncode


def test_json_carries_the_same_rows(world):
    home, project = world
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"files": {"command": "npx"}}})
    _write(home / ".gemini" / "settings.json", "{broken")
    doc = json.loads(_doctor("--agents", "--json", home=home, cwd=project).stdout)
    by = {(r["agent"], r["scope"]): r for r in doc["agents"]}
    assert by[("cursor", "user")]["servers"][0]["name"] == "files"
    assert by[("gemini-cli", "user")]["state"] == "UNREADABLE"
    assert by[("codex", "user")]["state"] in ("absent",)
    assert set(by[("cursor", "user")]) == {"agent", "scope", "label", "path", "state", "reason", "servers"}


def test_the_flag_refuses_to_be_combined_with_config(world):
    home, project = world
    cfg = _write(project / "c.json", {"mcpServers": {}})
    proc = _doctor("--agents", "--config", str(cfg), home=home, cwd=project)
    assert proc.returncode == 2 and "cannot be combined" in proc.stdout


def test_the_discovery_writes_nothing(world):
    home, project = world
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"a": {"command": "x"}}})

    def tree():
        return sorted((str(p), p.stat().st_mtime_ns) for root in (home, project) for p in root.rglob("*"))

    before = tree()
    _doctor("--agents", home=home, cwd=project)
    assert tree() == before


def test_an_unreadable_file_is_never_reported_as_absent_by_the_command(world):
    home, project = world
    _write(home / ".gemini" / "settings.json", "{broken")
    out = _doctor("--agents", home=home, cwd=project).stdout
    line = next(l for l in out.splitlines() if "~/.gemini/settings.json" in l)
    assert "UNREADABLE" in line and "absent" not in line
