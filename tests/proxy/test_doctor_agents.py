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
import re
import os
import subprocess
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO)

from sunglasses.proxy import agent_discovery  # noqa: E402

SECRET = "sk-live-0123456789SECRETVALUE"


def _doctor(*args, home, cwd):
    env = {**os.environ, "PYTHONPATH": REPO, "HOME": str(home), "USERPROFILE": str(home)}
    env.pop("XDG_CONFIG_HOME", None)
    return subprocess.run([sys.executable, "-m", "sunglasses.cli", "doctor", *args],
                          capture_output=True, text=True, cwd=str(cwd), env=env, timeout=60)


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


def test_an_entry_with_no_command_and_no_url_is_listed_not_dropped(world):
    home, project = world
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"odd": {"note": "x"}, "bad": 7}})
    assert [(s["name"], s["state"]) for s in _servers(home, project, "cursor", "user")["servers"]] == [
        ("bad", "UNVERIFIED"), ("odd", "DIRECT")]


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


def test_the_older_windsurf_path_the_current_docs_no_longer_name_is_not_read(world):
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
    assert "only a WRAPPED server runs through Sunglasses" in proc.stdout
    assert "not routed through" not in proc.stdout
    assert "~/.cursor/mcp.json" in proc.stdout and "DIRECT" in proc.stdout and "files" in proc.stdout
    assert "absent" in proc.stdout


def test_without_the_flag_the_output_is_unchanged_whatever_the_agents_hold(world):
    home, project = world
    before = _doctor(home=home, cwd=project)
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"files": {"command": "npx"}}})
    after = _doctor(home=home, cwd=project)
    # the live self-test's measured figure differs run to run; nothing else may
    def steady(out):
        return re.sub(r"deadline \d+ ms", "deadline N ms", out)
    assert (steady(before.stdout), before.returncode) == (steady(after.stdout), after.returncode)
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


# 6. Round-2 repairs: what the reader may open ----------------------------------

@pytest.mark.parametrize("command, shown", [
    ("/private/SECRET folder/run", "?"),
    ("C:\\SECRET\\bin\\run.exe", "run.exe"),
    ("C:\\Program Files\\SECRET\\run.exe", "?"),
    ('"C:\\SECRET\\bin\\run.exe"', "?"),
    ("'/opt/SECRET/bin/run'", "?"),
    ("/usr/local/bin/npx", "npx"),
    ("C:run.exe", "run.exe"),
    ("/usr/bin/", "?"),
    ("API_KEY=sk-0123 npx", "?"),
])
def test_the_command_shown_is_a_file_name_or_a_question_mark(world, command, shown):
    home, project = world
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"a": {"command": command}}})
    for extra in ([], ["--json"]):
        out = _doctor("--agents", *extra, home=home, cwd=project).stdout
        assert "SECRET" not in out and "sk-0123" not in out and "Program Files" not in out
    assert _servers(home, project, "cursor", "user")["servers"][0]["via"] == shown


@pytest.mark.skipif(os.name == "nt", reason="links need privileges on Windows")
def test_a_link_in_a_parent_folder_that_leaves_home_is_unreadable(world, tmp_path):
    home, project = world
    outside = tmp_path / "elsewhere" / "cursor"
    _write(outside / "mcp.json", {"mcpServers": {"OUTSIDE": {"command": "x"}}})
    (home / ".cursor").symlink_to(outside)
    for extra in ([], ["--json"]):
        assert "OUTSIDE" not in _doctor("--agents", *extra, home=home, cwd=project).stdout
    row = _servers(home, project, "cursor", "user")
    assert (row["state"], row["servers"]) == ("UNREADABLE", [])


@pytest.mark.skipif(os.name == "nt", reason="links need privileges on Windows")
def test_a_file_swapped_for_an_outside_link_just_before_it_is_opened_is_not_read(world, tmp_path, monkeypatch):
    home, project = world
    path = _write(home / ".cursor" / "mcp.json", {"mcpServers": {"safe": {"command": "x"}}})
    outside = _write(tmp_path / "elsewhere.json", {"mcpServers": {"OUTSIDE": {"command": "x"}}})
    real_open = os.open

    def swap_then_open(target, *args, **kwargs):
        if str(target).endswith("mcp.json") and not os.path.islink(path):
            os.unlink(path)
            os.symlink(outside, path)
        return real_open(target, *args, **kwargs)

    monkeypatch.setattr(agent_discovery.os, "open", swap_then_open)
    row = _servers(home, project, "cursor", "user")
    assert "OUTSIDE" not in json.dumps(row)
    assert row["state"] == "UNREADABLE"


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
def test_a_pipe_in_place_of_the_file_is_reported_and_never_waited_on(world):
    home, project = world
    (home / ".cursor").mkdir()
    os.mkfifo(home / ".cursor" / "mcp.json")
    proc = _doctor("--agents", home=home, cwd=project)  # a hang would raise on the harness timeout
    line = next(l for l in proc.stdout.splitlines() if "~/.cursor/mcp.json" in l)
    assert "UNREADABLE" in line and "not a regular file" in line


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")
def test_a_link_to_a_pipe_is_reported_and_never_waited_on(world):
    home, project = world
    os.mkfifo(home / "pipe")
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").symlink_to(home / "pipe")
    proc = _doctor("--agents", "--json", home=home, cwd=project)  # the child has a kill deadline
    row = next(r for r in json.loads(proc.stdout)["agents"] if r["path"] == "~/.cursor/mcp.json")
    assert row["state"] == "UNREADABLE" and row["reason"] == "not a regular file"


@pytest.mark.skipif(os.name == "nt", reason="links need privileges on Windows")
def test_a_link_loop_is_unreadable_on_every_python(world):
    home, project = world
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").symlink_to(home / ".cursor" / "mcp.json")
    row = _servers(home, project, "cursor", "user")
    assert row["state"] == "UNREADABLE" and row["servers"] == []


@pytest.mark.skipif(agent_discovery._tomllib is None, reason="no TOML reader on this Python")
def test_deeply_nested_toml_is_unreadable_not_a_crash(world):
    home, project = world
    _write(home / ".codex" / "config.toml", "x = " + "[" * 5000 + "]" * 5000 + "\n")
    proc = _doctor("--agents", home=home, cwd=project)
    assert "Traceback" not in proc.stderr
    assert _servers(home, project, "codex", "user")["state"] == "UNREADABLE"


def test_a_path_with_a_nul_is_unreadable_not_a_crash(world):
    home, project = world
    raw, reason, ident = agent_discovery._read(home / "a\0b", home, project)
    assert raw is None and reason and ident is None


# 7. Round-2 repairs: classification, duplicates, size ----------------------------

def test_every_state_is_installs_own_classification(world, tmp_path):
    from sunglasses import install as inst
    home, project = world
    artifact = tmp_path / "proxy_main.py"
    artifact.write_text("print('proxy')\n")
    cfg = _write(home / ".cursor" / "mcp.json", {"mcpServers": {"files": {"command": "npx", "args": ["x"]}}})
    inst.install(cfg, "files", artifact=artifact, home=home)
    entries = json.loads(cfg.read_text())["mcpServers"]
    entries["marker-no-command"] = {inst.MARKER: {"artifact": str(artifact), "sha256": "0" * 64}, "command": "npx"}
    entries["plain"] = {"command": "npx"}
    entries["listed"] = {"command": ["a", "b"]}
    entries["empty"] = {}
    entries["scalar"] = "x"
    cfg.write_text(json.dumps({"mcpServers": entries}))
    row = [r for r in agent_discovery.discover(home=home, cwd=project, artifact=artifact)
           if r["agent"] == "cursor" and r["scope"] == "user"][0]
    got = {s["name"]: s["state"] for s in row["servers"]}
    assert got == {name: inst.classify(spec, artifact=artifact) for name, spec in entries.items()}
    assert got["files"] == "WRAPPED" and "WRAPPED" not in (got["plain"], got["marker-no-command"])


def test_a_second_name_for_the_same_file_is_one_row(world, tmp_path):
    home, project = world
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"a": {"command": "x"}}})
    alias = tmp_path / "alias"
    if os.name == "nt":
        pytest.skip("links need privileges on Windows")
    alias.symlink_to(home)
    rows = [r for r in agent_discovery.discover(home=home, cwd=alias) if r["agent"] == "cursor"]
    assert len(rows) == 1 and rows[0]["state"] == "present"


def test_each_listed_path_is_read_once(world, monkeypatch):
    home, project = world
    seen = []
    real = agent_discovery._read
    monkeypatch.setattr(agent_discovery, "_read", lambda p, h, c: seen.append(str(p)) or real(p, h, c))
    agent_discovery.discover(home=home, cwd=home)
    assert len(seen) == len(set(seen)) == 7


def test_two_long_names_that_share_their_start_stay_two_rows(world):
    home, project = world
    stem = "n" * 100
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {stem + "a": {"command": "x"}, stem + "b": {"command": "x"}}})
    names = [s["name"] for s in _servers(home, project, "cursor", "user")["servers"]]
    assert len(names) == len(set(names)) == 2 and all(len(n) <= agent_discovery._NAME_LIMIT for n in names)


def test_a_file_with_thousands_of_servers_lists_a_bounded_number_and_says_so(world):
    home, project = world
    many = {f"s{i:05d}": {"command": "x"} for i in range(agent_discovery.MAX_SERVERS + 25)}
    _write(home / ".cursor" / "mcp.json", {"mcpServers": many})
    row = _servers(home, project, "cursor", "user")
    assert len(row["servers"]) == agent_discovery.MAX_SERVERS and row["reason"] == "25 more servers not listed"


@pytest.mark.skipif(os.name == "nt", reason="replacing an open path differs on Windows")
def test_a_file_replaced_by_another_file_between_the_check_and_the_open_is_not_read(world, monkeypatch):
    home, project = world
    path = _write(home / ".cursor" / "mcp.json", {"mcpServers": {"first": {"command": "x"}}})
    other = _write(home / "other.json", {"mcpServers": {"second": {"command": "x"}}})
    real_open = os.open

    def replace_then_open(target, *args, **kwargs):
        if str(target).endswith("mcp.json") and not getattr(replace_then_open, "done", False):
            replace_then_open.done = True
            os.replace(other, path)
        return real_open(target, *args, **kwargs)

    monkeypatch.setattr(agent_discovery.os, "open", replace_then_open)
    row = _servers(home, project, "cursor", "user")
    assert (row["state"], row["reason"], row["servers"]) == ("UNREADABLE", "changed while it was being opened", [])


# 7. Round-3 repairs: what a row may show --------------------------------------------

_L63 = "a" * 63

@pytest.mark.parametrize("url, shown", [
    # a host name is shown
    ("https://api.example.com/mcp", "api.example.com"),
    ("https://API.Example.com:8443/mcp", "api.example.com"),
    ("http://[::1]:9000/x", "::1"),
    ("https://127.0.0.1/mcp", "127.0.0.1"),
    ("https://b\u00fccher.example/x", "xn--bcher-kva.example"),
    ("https://example.com./x", "example.com"),
    (f"https://{_L63}.example/x", f"{_L63}.example"),
    ("https://" + ".".join([_L63] * 3 + ["a" * 61]) + "/x", ".".join([_L63] * 3 + ["a" * 61])),
    ("https://h.example/a b", "h.example"),
    ("https://xn--bcher-kva.example/x", "xn--bcher-kva.example"),
    # anything else is a question mark
    ("https://host\\SECRET/path", "?"),
    ("https://host%2fSECRET/path", "?"),
    ("https://KEY=SECRET/x", "?"),
    ("https://ho st/SECRET", "?"),
    ("https://host\tSECRET/x", "?"),
    ("https://host\nSECRET/x", "?"),
    ("https://host\rSECRET/x", "?"),
    ("https://my_SECRET.example/x", "?"),
    ("https://a..SECRET/x", "?"),
    ("https://-bad-.example.com/x", "?"),
    ("https://a-.example.com/x", "?"),
    (f"https://{'a' * 64}.example/x", "?"),
    ("https://" + ".".join([_L63] * 3 + ["a" * 62]) + "/x", "?"),
    ("https://\u202ehost.example/x", "?"),
    ("http://[::1%eth0]/x", "?"),
    ("http://[zzz]/x", "?"),
    ("https://[SECRET@host.example/x", "?"),
    ("https://", "?"),
    # a control character anywhere refuses the whole string (the parser would erase it)
    ("https://h.example/a\tb", "?"),
    ("https:/\t/host\tSECRET/PATHSECRET", "?"),
    ("https:/\n/host\nSECRET/PATHSECRET", "?"),
    ("https:/\r/host\rSECRET/PATHSECRET", "?"),
    ("https:/\t/host\tSECRET/path//safe", "?"),
    ("https://h.example/a\x00b", "?"),
    (" https://h.example/x", "?"),
    ("https://h.example/x ", "?"),
    # a later "//" never lends its words to the host
    ("https:/host\tSECRET/path//safe.example/x", "?"),
    # an xn-- label is checked by decoding it back
    ("https://xn--a.example/x", "?"),
    ("https://xn--.example/x", "?"),
    ("https://xn--bcher-kvb.example/x", "?"),
])
def test_a_host_is_shown_only_when_it_is_a_host_name(world, url, shown):
    home, project = world
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"a": {"url": url}}})
    row = _servers(home, project, "cursor", "user")["servers"][0]
    assert row["via"] == shown
    for extra in ([], ["--json"]):
        assert "SECRET" not in _doctor("--agents", *extra, home=home, cwd=project).stdout


def test_a_bracket_in_the_user_part_never_makes_the_host_an_address(world):
    from urllib.parse import urlsplit
    home, project = world
    url = "https://u[ser]:SECRET@host.example/x"
    try:
        urlsplit(url)
        expected = "host.example"  # this Python reads it; the host is what follows the last @
    except ValueError:
        expected = "?"             # this Python refuses it
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"a": {"url": url}}})
    assert _servers(home, project, "cursor", "user")["servers"][0]["via"] == expected


def test_the_address_branch_is_chosen_from_the_host_part_only(monkeypatch):
    """Whatever the URL parser accepts, a `[` before the last `@` is user name, not an address."""
    from urllib.parse import SplitResult
    monkeypatch.setattr(agent_discovery, "urlsplit",
                        lambda url: SplitResult("https", "u[ser]:pw@host.example", "/x", "", ""))
    assert agent_discovery._host("https://u[ser]:pw@host.example/x") == "host.example"
    monkeypatch.setattr(agent_discovery, "urlsplit",
                        lambda url: SplitResult("https", "u@[::1]:80", "/x", "", ""))
    assert agent_discovery._host("https://u@[::1]:80/x") == "::1"


def test_two_long_names_with_the_same_digest_stay_two_rows(world):
    home, project = world
    a, b = "n" * 100 + "3662", "n" * 100 + "4356"
    assert agent_discovery._safe(a) == agent_discovery._safe(b)  # the digest is short on purpose
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {a: {"command": "x"}, b: {"command": "y"}}})
    names = [r["name"] for r in _servers(home, project, "cursor", "user")["servers"]]
    assert len(names) == 2 and len(set(names)) == 2
    again = [r["name"] for r in _servers(home, project, "cursor", "user")["servers"]]
    assert names == again


def test_a_control_character_and_its_spelling_stay_two_rows(world):
    home, project = world
    _write(home / ".cursor" / "mcp.json",
           {"mcpServers": {"x\n": {"command": "a"}, "x\\x0a": {"command": "b"}}})
    rows = _servers(home, project, "cursor", "user")["servers"]
    assert len({r["name"] for r in rows}) == 2
    assert {r["via"] for r in rows} == {"a", "b"}


def test_a_numbered_name_never_takes_the_place_of_a_real_one(world):
    home, project = world
    a, b = "n" * 100 + "3662", "n" * 100 + "4356"
    taken = agent_discovery._safe(a) + " #1"
    _write(home / ".cursor" / "mcp.json",
           {"mcpServers": {a: {"command": "x"}, b: {"command": "y"}, taken: {"command": "z"}}})
    names = [r["name"] for r in _servers(home, project, "cursor", "user")["servers"]]
    assert len(names) == 3 and len(set(names)) == 3


def _case_insensitive(tmp):
    probe = tmp / "CaseProbe"
    probe.write_text("")
    return (tmp / "caseprobe").exists()


@pytest.mark.skipif(os.name == "nt", reason="links need privileges on Windows")
def test_a_link_to_the_home_folder_under_another_spelling_is_not_a_false_outside(world, tmp_path):
    home, project = world
    if not _case_insensitive(tmp_path):
        pytest.skip("this storage tells upper and lower case apart")
    other = home.parent / "HOME"
    assert other != home and other.exists()
    (home / "a.json").write_text(json.dumps({"mcpServers": {"s": {"command": "npx"}}}))
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").symlink_to(other / "a.json")
    row = _servers(home, project, "cursor", "user")
    assert row["state"] == agent_discovery.PRESENT and row["servers"][0]["name"] == "s"


@pytest.mark.skipif(os.name == "nt", reason="links need privileges on Windows")
def test_a_link_to_a_file_outside_is_still_outside_after_the_same_folder_test(world, tmp_path):
    home, project = world
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "a.json").write_text(json.dumps({"mcpServers": {"OUTSIDE": {"command": "npx"}}}))
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").symlink_to(outside / "a.json")
    row = _servers(home, project, "cursor", "user")
    assert row["state"] == "UNREADABLE" and "OUTSIDE" not in json.dumps(row)
