"""
WO-B / audit finding H2 — receipts must not replay attacker-controlled text.

`sunglasses receipts` stored and re-rendered `tool_name` verbatim. That field is
supplied by MCP servers — the same untrusted party `sunglasses pin` exists to defend
against. The audit drove a name carrying ANSI escapes through the hook and made the
audit view clear the screen and print a forged all-clear; an embedded newline forged
an extra row; a 300-character name destroyed the table.

An audit trail that the audited party can write into is not an audit trail. The
sanitize runs on WRITE (so a poisoned line never reaches the jsonl) and on RENDER (so
a jsonl written by an older build, or tampered with on disk, still cannot paint the
terminal).
"""

import json
import os
import subprocess
import sys

import pytest

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, REPO)

from sunglasses.firewall import sanitize_receipt_field, write_receipt  # noqa: E402

ESC = chr(27)
# Fixtures are built from parts so the literal escape sequence is assembled at
# runtime rather than sitting in the file as a paste-able screen-clearing string.
FORGED_ALL_CLEAR = ESC + "[2J" + ESC + "[H" + ESC + "[92m  ALL CLEAR - 0 threats" + ESC + "[0m"
BIDI_OVERRIDE = "safe" + chr(0x202E) + "yldneirf"


class TestSanitizeField:
    def test_strips_every_escape_introducer(self):
        """The security property is that NO byte a terminal treats as an escape
        introducer survives. The residual literal text ("[2J") is inert once the
        ESC is gone, and stripping it would mean mangling any legitimate name that
        contains a bracket — so this asserts the property that actually matters,
        across the whole C0/C1 range rather than the one sequence in the fixture.
        """
        out = sanitize_receipt_field(FORGED_ALL_CLEAR)
        assert ESC not in out, "ESC (0x1b) survived"
        assert chr(0x9B) not in out, "C1 CSI (0x9b) survived"
        assert not any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in out), (
            "a C0/C1 control character survived the sanitize"
        )
        # And the identity is still legible — a scrubbed-to-nothing audit line
        # would be its own kind of failure.
        assert "ALL CLEAR" in out

    def test_strips_newlines_so_one_record_stays_one_line(self):
        out = sanitize_receipt_field("line1\nline2-FORGED\r\nline3")
        assert "\n" not in out and "\r" not in out

    def test_strips_c1_controls(self):
        out = sanitize_receipt_field("a" + chr(0x9B) + "b" + chr(0x85) + "c")
        assert chr(0x9B) not in out and chr(0x85) not in out

    def test_strips_bidi_override(self):
        assert chr(0x202E) not in sanitize_receipt_field(BIDI_OVERRIDE)

    def test_truncates_long_values(self):
        out = sanitize_receipt_field("A" * 5000)
        assert len(out) <= 128

    def test_truncation_is_visible_not_silent(self):
        out = sanitize_receipt_field("A" * 5000)
        assert out.endswith("…"), "a trimmed value must say it was trimmed"

    def test_ordinary_names_pass_through_untouched(self):
        for name in ("Bash", "WebFetch", "mcp__github__create_issue", "NotebookEdit"):
            assert sanitize_receipt_field(name) == name

    def test_non_string_input_survives(self):
        assert sanitize_receipt_field(None) is None
        assert sanitize_receipt_field(123) == "123"


class TestWritePath:
    def test_poisoned_tool_name_never_reaches_the_jsonl(self, tmp_path):
        write_receipt(
            {"ts": "2026-08-30T00:00:00", "tool_name": FORGED_ALL_CLEAR,
             "session_id": "s", "decision": "defer", "lane": "deterministic",
             "rule_id": "GLS-FW-CLEAN"},
            home=tmp_path,
        )
        written = list((tmp_path / "receipts").glob("*.jsonl"))[0].read_text()
        assert ESC not in written
        record = json.loads(written.strip())
        assert ESC not in record["tool_name"]

    def test_newline_cannot_forge_a_second_record(self, tmp_path):
        write_receipt(
            {"ts": "2026-08-30T00:00:00", "tool_name": "a\nb", "session_id": "s",
             "decision": "defer", "lane": "deterministic", "rule_id": "GLS-FW-CLEAN"},
            home=tmp_path,
        )
        text = list((tmp_path / "receipts").glob("*.jsonl"))[0].read_text()
        assert len([ln for ln in text.splitlines() if ln.strip()]) == 1

    def test_session_id_and_error_are_sanitized_too(self, tmp_path):
        write_receipt(
            {"ts": "2026-08-30T00:00:00", "tool_name": "Bash",
             "session_id": FORGED_ALL_CLEAR, "decision": "defer", "lane": "error",
             "rule_id": "GLS-FW-ERROR", "error": FORGED_ALL_CLEAR},
            home=tmp_path,
        )
        record = json.loads(list((tmp_path / "receipts").glob("*.jsonl"))[0].read_text().strip())
        assert ESC not in record["session_id"]
        assert ESC not in record["error"]

    def test_receipt_still_records_the_useful_part(self, tmp_path):
        """Sanitizing must not destroy the audit value — the name stays readable."""
        write_receipt(
            {"ts": "2026-08-30T00:00:00", "tool_name": ESC + "[92mmcp__evil__tool",
             "session_id": "s", "decision": "deny", "lane": "deterministic",
             "rule_id": "GLS-FW-SEC-AWS"},
            home=tmp_path,
        )
        record = json.loads(list((tmp_path / "receipts").glob("*.jsonl"))[0].read_text().strip())
        assert "mcp__evil__tool" in record["tool_name"]
        assert record["rule_id"] == "GLS-FW-SEC-AWS"


class TestRenderPath:
    def _render(self, tmp_path, raw_line):
        directory = tmp_path / ".sunglasses" / "receipts"
        directory.mkdir(parents=True)
        (directory / "2026-08-30.jsonl").write_text(raw_line + "\n")
        env = dict(os.environ, HOME=str(tmp_path))
        env.pop("SUNGLASSES_HOME", None)
        return subprocess.run(
            [sys.executable, "-m", "sunglasses.cli", "receipts"],
            capture_output=True, text=True, cwd=REPO, env=env,
        )

    def test_render_defuses_a_pre_existing_poisoned_line(self, tmp_path):
        """A jsonl written by an older build must not paint the terminal today."""
        line = json.dumps({
            "ts": "2026-08-30T18:10:04", "tool_name": FORGED_ALL_CLEAR,
            "session_id": "s", "decision": "defer", "lane": "deterministic",
            "rule_id": "GLS-FW-CLEAN",
        })
        proc = self._render(tmp_path, line)

        # No screen-control sequence from the receipt reaches the terminal.
        for seq in (ESC + "[2J", ESC + "[H", ESC + "[92m", chr(0x9B)):
            assert seq not in proc.stdout, f"{seq!r} survived rendering"

        # The poisoned name occupies exactly one row — no forged second line.
        rows = [ln for ln in proc.stdout.splitlines()
                if "deterministic" in ln and "defer" in ln]
        assert len(rows) == 1, f"poisoned name produced {len(rows)} rows"

        # Our OWN colour codes are still emitted — proving the render was not simply
        # stripped of all escapes, which would have passed the checks above for the
        # wrong reason.
        assert ESC + "[2m" in proc.stdout

    def test_render_truncates_a_layout_breaking_name(self, tmp_path):
        line = json.dumps({
            "ts": "2026-08-30T18:10:04", "tool_name": "A" * 300, "session_id": "s",
            "decision": "defer", "lane": "deterministic", "rule_id": "GLS-FW-CLEAN",
        })
        proc = self._render(tmp_path, line)
        assert "A" * 200 not in proc.stdout
