"""Two different names never print the same line, and a name that is data never reaches a terminal as it stands.

A name that holds a character `str.isprintable()` refuses is written between $'...' (`receipts._shown.shown_name`),
every such character as an escape of fixed width and a backslash twice. A name with none of them is shown as it is,
a Windows path included. So the name `a<ESC>b` and the name that spells it out (`a\\x1bb`) are two different lines,
which matters where a person judges a row by what it shows: the `proxy approve` tool list has no numbering that
tells two rows apart.

The second half is the places that print a name or a path somebody else chose: the doctor Servers row, the
install and uninstall lines, and the line that names a linked config. Every name below was written for this file.
"""
import io
import itertools
import json
import os
import pathlib
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))

from sunglasses import cli  # noqa: E402
from sunglasses.proxy import agent_discovery, approvals, commands  # noqa: E402
from sunglasses.receipts._shown import name_is_escaped, shown_name  # noqa: E402

SHA = "a" * 64
DIGEST = "b" * 64
ESC, CR, LF, BIDI = "\x1b", "\r", "\n", "‮"
HOSTILE = "evil" + ESC + "[2J" + LF + "FORGED approved" + CR + BIDI

# Each symbol is a character, a character an escape is spelled with, or a character that gets one.
ALPHABET = ["a", "\\", "x", "u", "0", "$", "'", ESC, LF, BIDI, "\U000e0001", " "]


def test_no_two_different_names_print_the_same_up_to_length_four():
    seen = {}
    for length in range(0, 5):
        for combo in itertools.product(ALPHABET, repeat=length):
            name = "".join(combo)
            shown = shown_name(name)
            assert shown not in seen, (name.encode("unicode_escape"), seen[shown].encode("unicode_escape"))
            seen[shown] = name
    assert len(seen) == sum(len(ALPHABET) ** n for n in range(0, 5))


def test_the_output_holds_no_character_a_terminal_would_act_on():
    for combo in itertools.product(ALPHABET, repeat=3):
        shown = shown_name("".join(combo))
        assert all(ch.isprintable() for ch in shown)


@pytest.mark.parametrize("name", [
    "read_file", "my server", "", "corp\\tool", "C:\\proj\\a.md", "\\\\host\\share\\a b.md", "a\\x1bb", "it's", "naïve",
])
def test_a_name_with_nothing_to_escape_is_shown_as_it_is(name):
    assert shown_name(name) == name and not name_is_escaped(name)
    assert cli._printable(name) == name and agent_discovery._safe(name) == name


def test_a_name_that_needs_an_escape_is_written_between_dollar_quotes():
    assert shown_name("a" + ESC + "b") == "$'a\\x1bb'"
    assert shown_name(BIDI) == "$'\\u202e'"
    assert shown_name("\U000e0001") == "$'\\U000e0001'"          # eight digits: never  then a 1
    assert shown_name("a\\b" + LF) == "$'a\\\\b\\x0a'"            # backslash twice
    assert shown_name("it's" + CR) == "$'it\\'s\\x0d'"            # quote escaped
    assert shown_name("$'a'") == "$'$\\'a\\''"                    # a plain name that looks like the form


@pytest.mark.parametrize("pair", [
    ("a" + ESC + "b", "a\\x1bb"),
    ("a" + LF + "b", "a\\x0ab"),
    ("a" + BIDI + "b", "a\\u202eb"),
    ("a\\b", "a\\\\b"),
    ("a" + ESC + "b", "$'a\\x1bb'"),
])
def test_the_renderers_keep_a_name_and_its_spelling_apart(pair):
    first, second = pair
    assert agent_discovery._safe(first) != agent_discovery._safe(second)
    assert cli._printable(first) != cli._printable(second)
    assert cli._printable_match(first) != cli._printable_match(second)


def test_the_two_name_renderers_are_one_rule_and_the_match_renderer_is_unchanged():
    for name in ("plain", "tab\there", "a\\b", HOSTILE, "\U000e0001x", "naïve", "C:\\proj\\a.md"):
        assert agent_discovery._safe(name) == cli._printable(name) == shown_name(name)
    assert cli._printable_match("a\\b") == "a\\\\b"          # a quoted match keeps its own rule


def test_a_long_name_is_still_cut_with_a_digest():
    first, second = "\\" * 100 + "3662", "\\" * 100 + "4356"
    a, b = agent_discovery._safe(first), agent_discovery._safe(second)
    assert len(a) <= agent_discovery._NAME_LIMIT and len(b) <= agent_discovery._NAME_LIMIT
    assert a != b
    held = "a" + ESC + "x" * 200
    assert len(agent_discovery._safe(held)) <= agent_discovery._NAME_LIMIT


# ── proxy approve ──────────────────────────────────────────────────────────

def _approve(root):
    out, err = io.StringIO(), io.StringIO()
    code = commands._approve("srv", {"snapshot": SHA, "state-root": str(root)}, out, err,
                             confirm=lambda: False)
    return code, out.getvalue(), err.getvalue()


def _capture(root, tools):
    store = approvals.Store(root, server_id="srv")
    store.capture(SHA, {"sha256": SHA, "tools_by_name": {n: {"descriptor_sha256": DIGEST} for n in tools}})


def test_approve_shows_a_name_and_its_spelling_as_two_different_rows(tmp_path):
    held, spelled = "a" + ESC + "b", "a\\x1bb"
    _capture(tmp_path, [held, spelled])
    _code, out, _err = _approve(tmp_path)
    rows = [ln for ln in out.splitlines() if ln.startswith("  a") or ln.startswith("  $'a")]
    assert len(rows) == 2 and rows[0] != rows[1]
    assert "  $'a\\x1bb' [escaped]  " in out                   # the character, written out
    assert "  a\\x1bb  " in out and "  a\\x1bb [" not in out   # the name that spells it out: as it is


def test_approve_marks_an_escape_and_a_cut_and_leaves_a_backslash_name_alone(tmp_path):
    _capture(tmp_path, ["corp\\tool", "n" * 200, "read_file", "bell" + chr(7)])
    _code, out, _err = _approve(tmp_path)
    lines = out.splitlines()
    assert any(ln.startswith("  corp\\tool  ") and "[" not in ln for ln in lines)
    assert any(ln.startswith("  nnn") and "[shortened]" in ln and "[escaped]" not in ln for ln in lines)
    assert any(ln.startswith("  read_file  ") and "[" not in ln for ln in lines)
    assert any(ln.startswith("  $'bell\\x07' [escaped]") for ln in lines)


# ── the CLI lines that print a name or a path somebody else chose ─────────────

def _run(args, cwd, home):
    env = {k: v for k, v in os.environ.items() if k not in ("NO_COLOR", "FORCE_COLOR", "CLICOLOR_FORCE")}
    env.update({"PYTHONPATH": str(REPO), "HOME": str(home), "PYTHONDONTWRITEBYTECODE": "1"})
    proc = subprocess.run([sys.executable, "-m", "sunglasses.cli", *args], cwd=str(cwd), env=env,
                          capture_output=True, text=True, timeout=240)
    return proc.returncode, proc.stdout + "\n" + proc.stderr


def _dirty(text):
    """Characters a terminal acts on (colour is off on a pipe), and a forged line."""
    return [ch for ch in text if not ch.isprintable() and ch != "\n"] + \
        [ln for ln in text.split("\n") if ln.startswith("FORGED")]


def _mcp(path, name):
    path.write_text(json.dumps({"mcpServers": {name: {"command": "python3", "args": ["x.py"]}}}))


@pytest.fixture
def world(tmp_path):
    (tmp_path / "home").mkdir()
    return tmp_path


def test_doctor_servers_row_shows_a_hostile_config_key_as_text_and_exits_as_before(world):
    clean, hostile = world / "clean.json", world / "hostile.json"
    _mcp(clean, "demo")
    _mcp(hostile, HOSTILE)
    code_c, _ = _run(["doctor", "--config", str(clean)], world, world / "home")
    code_h, out = _run(["doctor", "--config", str(hostile)], world, world / "home")
    assert _dirty(out) == []
    assert code_h == code_c
    assert "$'evil\\x1b[2J\\x0aFORGED approved\\x0d\\u202e'" in out


def test_doctor_names_an_unreadable_source_without_a_raw_control_character(world):
    folder = world / ("proj" + HOSTILE)
    folder.mkdir()
    (folder / ".mcp.json").write_text("{not json")
    code, out = _run(["doctor"], folder, world / "home")
    assert _dirty(out) == []
    assert "source could not be read" in out and code == 2


def test_install_and_uninstall_name_a_hostile_folder_as_text(world):
    folder = world / ("proj" + HOSTILE)
    folder.mkdir()
    code, out = _run(["install", "demo"], folder, world / "home")          # no config in the folder
    assert code == 2 and _dirty(out) == [] and "no MCP config file was found" in out
    (folder / ".mcp.json").write_text("{}")
    code, out = _run(["install", "demo"], folder, world / "home")          # ConfigIOError text carries the path
    assert code == 2 and _dirty(out) == []
    _mcp(folder / ".mcp.json", "demo")
    code, out = _run(["install", "demo"], folder, world / "home")
    assert code == 0 and _dirty(out) == [] and "Wrapped" in out
    code, out = _run(["uninstall", "demo"], folder, world / "home")
    assert code == 0 and _dirty(out) == [] and "Restored" in out


def test_shown_path_for_a_linked_config(world):
    """The path the doctor line names for a linked config is text: one line, no terminal control character."""
    proj = world / "proj"
    proj.mkdir()
    (proj / ".mcp.json").symlink_to(world / ("target" + HOSTILE + ".json"))
    code, out = _run(["doctor"], proj, world / "home")
    assert _dirty(out) == []
    assert "is a link to" in out and code == 3


def test_a_plain_path_prints_as_before_in_the_install_lines(world):
    proj = world / "proj"
    proj.mkdir()
    _mcp(proj / ".mcp.json", "demo")
    code, out = _run(["install", "demo"], proj, world / "home")
    assert code == 0
    assert f"Wrapped 'demo' in {proj / '.mcp.json'}" in out


def test_a_path_with_a_space_is_quoted_so_the_person_can_paste_it(world):
    proj = world / "my proj"
    proj.mkdir()
    _mcp(proj / ".mcp.json", "demo")
    code, out = _run(["install", "demo"], proj, world / "home")
    assert code == 0
    assert f"Wrapped 'demo' in '{proj / '.mcp.json'}'" in out


# ── names that are not hostile stay as they were ───────────────────────────────

def test_a_windows_style_scan_name_prints_as_before():
    assert cli._printable("C:\\proj\\a.md") == "C:\\proj\\a.md"
    assert cli._printable("src\\deep\\file name.py") == "src\\deep\\file name.py"


def _agents_json(home, names):
    (home / ".cursor").mkdir()
    (home / ".cursor" / "mcp.json").write_text(json.dumps(
        {"mcpServers": {n: {"command": "python3", "args": ["x.py"]} for n in names}}))
    code, out = _run(["doctor", "--agents", "--json"], home, home)
    doc = json.loads(out[out.index("{"):out.rindex("}") + 1])
    return [s["name"] for a in doc["agents"] for s in a["servers"]]


def test_doctor_agents_json_carries_a_backslash_name_unchanged(world):
    names = _agents_json(world / "home", ["corp\\tool", "C:\\proj\\srv", "plain"])
    assert sorted(names) == sorted(["corp\\tool", "C:\\proj\\srv", "plain"])


def test_doctor_agents_json_tells_a_held_character_from_its_spelling(world):
    names = _agents_json(world / "home", ["a" + ESC + "b", "a\\x1bb"])
    assert sorted(names) == sorted(["$'a\\x1bb'", "a\\x1bb"])
