"""`sunglasses check` and `sunglasses doctor` on a machine that was just installed.

A first-run report (C101, gaps 1 and 7) found that a correct install looked broken:
`check` put a cross next to Whisper and pyzbar with no word saying they are optional,
and `doctor` printed five NOT RUN lines and `exit 1` with nothing saying that nothing
had failed. The reports below must say what each cross and each exit 1 means. Exit
codes keep their meaning: `check` still exits 0, `doctor` still exits 1 on this build.

Each case runs the real CLI entry point in a child interpreter. The "fresh install"
shape is made, not assumed: PATH holds no tesseract or ffmpeg, and `whisper` and
`pyzbar` are blocked from importing, so the result does not depend on what the machine
running the tests has installed.
"""
import json
import os
import pathlib
import re
import stat
import subprocess
import sys

import pytest

from sunglasses import cli
from sunglasses.proxy import doctor

ROOT = pathlib.Path(__file__).resolve().parent.parent
_ANSI = re.compile(r"\x1b\[[0-9;]*m")

# Run main() as the console script does, with the named optional modules unimportable.
_CHILD = """
import sys
for name in sys.argv[1].split(","):
    if name:
        sys.modules[name] = None   # `import name` raises ImportError
sys.argv = ["sunglasses"] + sys.argv[2:]
from sunglasses.cli import main
main()
"""


def _run(tmp_path, args, blocked="whisper,pyzbar", path_dirs=(), pythonpath=()):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    empty = tmp_path / "emptybin"
    empty.mkdir(exist_ok=True)
    env = {
        "HOME": str(home), "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PATH": os.pathsep.join([str(p) for p in path_dirs] + [str(empty)]),
        "PYTHONPATH": os.pathsep.join([str(ROOT)] + [str(p) for p in pythonpath]),
    }
    return subprocess.run([sys.executable, "-c", _CHILD, blocked, *args],
                          capture_output=True, text=True, cwd=str(tmp_path), env=env)


def _fake_tool(directory, name, body="echo fake"):
    directory.mkdir(exist_ok=True)
    path = directory / name
    path.write_text(f"#!/bin/sh\n{body}\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)


# ---------------------------------------------------------------------------
# check
# ---------------------------------------------------------------------------

def test_check_on_a_fresh_install_labels_every_cross_optional_and_counts_them(tmp_path):
    proc = _run(tmp_path, ["check"])
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    out = proc.stdout
    crosses = [line for line in out.splitlines() if "✗" in line]
    assert len(crosses) == 4, out
    assert all("(optional)" in line for line in crosses), crosses
    assert "4 optional extras not installed (Tesseract, Whisper, FFmpeg, pyzbar)." in out
    assert "Core text scanning is ready." in out
    assert "Some optional features unavailable" not in out
    assert "All systems ready" not in out


def test_check_names_only_what_is_missing_and_uses_the_singular(tmp_path):
    bin_dir = tmp_path / "bin"
    _fake_tool(bin_dir, "tesseract")
    _fake_tool(bin_dir, "ffmpeg", "echo 'ffmpeg version 9.9 Copyright'")
    mods = tmp_path / "mods"
    (mods / "whisper").mkdir(parents=True)
    (mods / "whisper" / "__init__.py").write_text("")
    proc = _run(tmp_path, ["check"], blocked="pyzbar", path_dirs=[bin_dir], pythonpath=[mods])
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    out = proc.stdout
    assert "1 optional extra not installed (pyzbar)." in out
    assert [line for line in out.splitlines() if "✗" in line] == [
        line for line in out.splitlines() if "✗" in line and "pyzbar (optional)" in line]
    assert "extras not installed" not in out


def test_check_with_everything_present_has_no_optional_wording(tmp_path):
    bin_dir = tmp_path / "bin"
    _fake_tool(bin_dir, "tesseract")
    _fake_tool(bin_dir, "ffmpeg", "echo 'ffmpeg version 9.9 Copyright'")
    mods = tmp_path / "mods"
    for name in ("whisper", "pyzbar"):
        (mods / name).mkdir(parents=True)
        (mods / name / "__init__.py").write_text("")
    proc = _run(tmp_path, ["check"], blocked="", path_dirs=[bin_dir], pythonpath=[mods])
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert "All systems ready" in proc.stdout
    assert "✗" not in proc.stdout and "optional" not in proc.stdout


def test_check_help_says_a_cross_is_not_a_failure_and_documents_the_exit(tmp_path):
    proc = _run(tmp_path, ["check", "--help"])
    assert proc.returncode == 0, proc.stderr
    assert "OPTIONAL" in proc.stdout and "not a failure" in proc.stdout
    assert re.search(r"EXIT CODES\s+0\s+it ran and printed the list", proc.stdout), proc.stdout


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------

def test_doctor_on_a_fresh_install_says_nothing_failed_and_still_exits_one(tmp_path):
    proc = _run(tmp_path, ["doctor"])
    assert proc.returncode == 1, (proc.stdout, proc.stderr)
    out = proc.stdout
    assert "No check failed, and none could run." in out
    assert 'Exit 1 here means "not proven", not "failed".' in out
    # the five lines and the aggregate are all still there: the sentence adds, it removes nothing
    assert out.count(": NOT RUN") == 5
    assert "ROUTE_UNVERIFIED  exit 1" in out
    assert out.index("No check failed") < out.index("ROUTE_UNVERIFIED")


def test_doctor_json_is_byte_for_byte_the_report_it_was(tmp_path):
    proc = _run(tmp_path, ["doctor", "--json"])
    data = json.loads(proc.stdout)
    assert proc.returncode == 1 and data["exit_code"] == 1
    assert data["aggregate"] == "ROUTE_UNVERIFIED"
    assert set(data) == {"self_test", "per_wrapper", "inventory", "aggregate",
                         "route_checks", "receipts_key", "exit_code"}


def test_doctor_help_still_documents_exit_one_as_not_proven(tmp_path):
    proc = _run(tmp_path, ["doctor", "--help"])
    assert 'Exit 1 here means "I could not prove it"' in proc.stdout


def _unavailable_report(tmp_path):
    (tmp_path / "home").mkdir(exist_ok=True)
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"demo": {"command": "python3", "args": ["x.py"]}}}))
    return doctor.run(sources=[("project", cfg)], home=tmp_path / "home")


def _text(report, monkeypatch, capsys, mutate=None):
    real = doctor.render

    def render(r):
        rendered = real(r)
        if mutate:
            mutate(rendered)
        return rendered

    monkeypatch.setattr(doctor, "render", render)
    args = type("A", (), {"config": None, "json": False})()
    with pytest.raises(SystemExit):
        cli.cmd_doctor(args, _run=lambda **kw: report)
    return _ANSI.sub("", capsys.readouterr().out)


def _fail_a_route(rendered):
    rendered["per_wrapper"].append({"name": "demo", "source": "project", "result": "FAIL"})


def _an_unusable_signing_key(rendered):
    rendered["receipts_key"] = {"status": "KEY_UNUSABLE", "cause": "x"}


def _an_unreadable_source(rendered):
    rendered["inventory"][0]["detail"] = "could not open"


def _a_failed_self_test_check(rendered):
    rendered["self_test"]["failed"] = ["initialized"]


def test_the_sentence_is_printed_when_that_is_the_whole_story(tmp_path, monkeypatch, capsys):
    out = _text(_unavailable_report(tmp_path), monkeypatch, capsys)
    assert "No check failed, and none could run." in out


@pytest.mark.parametrize("mutate", [_fail_a_route, _an_unusable_signing_key,
                                    _an_unreadable_source, _a_failed_self_test_check])
def test_the_sentence_is_never_printed_beside_a_real_failure(tmp_path, monkeypatch, capsys, mutate):
    """Reassurance is only true when the unavailable self-test is the only reason for exit 1."""
    out = _text(_unavailable_report(tmp_path), monkeypatch, capsys, mutate)
    assert "No check failed" not in out
    assert "exit" in out
