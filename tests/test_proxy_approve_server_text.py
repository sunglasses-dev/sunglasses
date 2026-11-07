"""`sunglasses proxy approve` prints text the SERVER chose (tool names). It is data, not terminal input.

Printed raw, an escape sequence redraws the terminal, a carriage return draws one name over another,
and a line feed prints a second line that reads as another tool. The person approving is judging
descriptors by what this view shows, so the view must show every character of a hostile name as
text, keep one line per tool, and say when a line differs from the name. The approval still binds
the descriptor digest and the capture sha; none of that goes through the display.

Every name below was written for this file.
"""
import io
import json
import os
import sys
import pathlib

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from sunglasses.proxy import approvals, commands  # noqa: E402

SHA = "a" * 64
DIGEST = "b" * 64
HEADER_LINES = 4            # server+snapshot (2), folder (1), tool count (1)
ESC, BEL, CR, NUL, LF = (chr(c) for c in (27, 7, 13, 0, 10))

HOSTILE = {
    "escape_clear_screen": "tool" + ESC + "[2J" + "x",
    "escape_window_title": "tool" + ESC + "]0;renamed" + BEL,
    "carriage_return_overwrite": "approve_me" + CR + "harmless_name",
    "line_feed_forged_tool_line": "tool" + LF + "  readme_reader  0000000000000000",
    "nul": "tool" + NUL + "x",
    "c1_control": "tool" + chr(0x9B) + "2J",
    "bidi_override": "tool" + chr(0x202E) + "txt.exe",
    "zero_width": "tool" + chr(0x200B) + "x",
}


def _capture(root, tools):
    store = approvals.Store(root, server_id="srv")
    store.capture(SHA, {"sha256": SHA, "tools_by_name": {n: {"descriptor_sha256": DIGEST} for n in tools}})
    return store


def _approve(root, answer=False):
    out, err = io.StringIO(), io.StringIO()
    code = commands._approve("srv", {"snapshot": SHA, "state-root": str(root)}, out, err,
                             confirm=lambda: answer)
    return code, out.getvalue(), err.getvalue()


def _unprintable(text):
    return [ch for ch in text if not ch.isprintable() and ch != LF]


@pytest.mark.parametrize("label", sorted(HOSTILE))
def test_a_hostile_tool_name_prints_no_raw_control_character_and_one_line(tmp_path, label):
    _capture(tmp_path, [HOSTILE[label], "read_file"])
    _code, out, _err = _approve(tmp_path)
    assert _unprintable(out) == []
    assert len(out.splitlines()) == HEADER_LINES + 2        # exactly one line per tool: nothing forged
    assert "[escaped]" in out                                # the line says it is not the whole name


def test_a_plain_name_prints_unchanged_with_no_marker(tmp_path):
    _capture(tmp_path, ["read_file", "write_file"])
    _code, out, _err = _approve(tmp_path)
    assert f"  read_file  {DIGEST[:16]}\n" in out
    assert f"  write_file  {DIGEST[:16]}\n" in out
    assert "[escaped]" not in out and "[shortened]" not in out


def test_the_escape_shows_the_characters_as_text_so_the_person_can_see_them(tmp_path):
    _capture(tmp_path, [HOSTILE["escape_clear_screen"]])
    _code, out, _err = _approve(tmp_path)
    assert "tool\\x1b[2Jx [escaped]" in out


def test_a_very_long_name_is_cut_and_two_long_names_with_one_start_stay_two_lines(tmp_path):
    first, second = "n" * 200 + "a", "n" * 200 + "b"
    _capture(tmp_path, [first, second])
    _code, out, _err = _approve(tmp_path)
    lines = [ln for ln in out.splitlines() if ln.startswith("  n")]
    assert len(lines) == 2 and lines[0] != lines[1]
    assert all("[shortened]" in ln and len(ln) < 160 for ln in lines)


def test_the_approval_still_binds_the_real_name_and_digest(tmp_path):
    name = HOSTILE["carriage_return_overwrite"]
    _capture(tmp_path, [name])
    code, _out, _err = _approve(tmp_path, answer=True)
    assert code == commands.EXIT_OK
    record = json.loads((tmp_path / "approvals" / "srv.json").read_text())
    assert record["tools"] == {name: {"descriptor_sha256": DIGEST}}


def test_a_digest_that_is_not_hex_text_is_escaped_too(tmp_path):
    store = approvals.Store(tmp_path, server_id="srv")
    store.capture(SHA, {"sha256": SHA, "tools_by_name": {"t": {"descriptor_sha256": ESC + "[2J" + "c" * 20}}})
    _code, out, _err = _approve(tmp_path)
    assert _unprintable(out) == []
