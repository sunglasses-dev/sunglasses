"""`sunglasses check` and `sunglasses doctor` on a machine that was just installed.

A first-run report (C101, gaps 1 and 7) found that a correct install looked broken:
`check` put a cross next to Whisper and pyzbar with no word saying they are optional,
and `doctor` printed five NOT RUN lines and `exit 1` with nothing saying that nothing
had failed. The reports below must say what each cross and each exit 1 means. Exit
codes keep their meaning: `check` still exits 0, `doctor` exits 3 (not verifiable) on this build.

Seven cases run the real CLI entry point in a child interpreter; five call `cmd_doctor`
with an injected report. The "fresh install" shape of the child is made, not assumed: PATH
holds no tesseract or ffmpeg, and `whisper` and `pyzbar` are blocked from importing, so the
result does not depend on what the machine running the tests has installed. Two cases
deliberately supply some or all of the extras.
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


# The same child with the monotonic clock held at zero, for output that prints a measured duration.
_CHILD_CLOCK_AT_ZERO = "import time\ntime.monotonic_ns = lambda: 0\n" + _CHILD


def _run(tmp_path, args, blocked="whisper,pyzbar", path_dirs=(), pythonpath=(), child=_CHILD, text=True):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    empty = tmp_path / "emptybin"
    empty.mkdir(exist_ok=True)
    env = {
        "HOME": str(home), "NO_COLOR": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "PATH": os.pathsep.join([str(p) for p in path_dirs] + [str(empty)]),
        "PYTHONPATH": os.pathsep.join([str(ROOT)] + [str(p) for p in pythonpath]),
    }
    return subprocess.run([sys.executable, "-c", child, blocked, *args],
                          capture_output=True, text=text, cwd=str(tmp_path), env=env)


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

def test_doctor_on_a_fresh_install_says_nothing_failed_and_exits_three(tmp_path):
    proc = _run(tmp_path, ["doctor"])
    assert proc.returncode == 3, (proc.stdout, proc.stderr)
    out = proc.stdout
    assert "No check failed, and none could run." in out
    assert 'Exit 3 here means "not proven", not "failed".' in out
    # the five lines and the aggregate are all still there: the sentence adds, it removes nothing
    assert out.count(": NOT RUN") == 5
    assert "ROUTE_UNVERIFIED  exit 3" in out
    assert out.index("No check failed") < out.index("ROUTE_UNVERIFIED")


def test_doctor_with_no_servers_names_the_next_step_and_exits_three(tmp_path):
    # A cold user saw "No server entries found." and nothing to do next.
    proc = _run(tmp_path, ["doctor"])
    assert proc.returncode == 3, (proc.stdout, proc.stderr)
    out = proc.stdout
    assert "No server entries found." in out
    step = ("The configs checked list no MCP servers, so nothing in them is wrapped. "
            "Add a server to ./.mcp.json, then run: sunglasses install <name>")
    assert step in out
    assert out.index("No server entries found.") < out.index(step)


def test_doctor_with_a_dangling_default_config_link_names_the_file_install_will_write(tmp_path):
    # C498: ./.mcp.json was a link to a file that is not there. doctor read nothing and
    # suggested a bare `install`, which refuses any link (exit 2). The step names the
    # destination with --config instead, and the bare suggestion is not printed.
    gone = tmp_path / "elsewhere" / "gone.json"
    (tmp_path / ".mcp.json").symlink_to(gone)
    proc = _run(tmp_path, ["doctor"])
    assert proc.returncode == 3, (proc.stdout, proc.stderr)
    out = proc.stdout
    assert "No server entries found." in out
    behind = (tmp_path / ".mcp.json").resolve()
    assert f"./.mcp.json is a link to {behind}, which does not exist." in out
    assert f"create {behind} with a server in it, then run: " \
           f"sunglasses install <name> --config {behind}" in out
    assert "Add a server to ./.mcp.json" not in out
    # the bare step really is refused by install, so it must not be the advice
    bare = _run(tmp_path, ["install", "demo"])
    assert bare.returncode == 2 and "is a symbolic link" in bare.stdout + bare.stderr
    assert not gone.exists() and (tmp_path / ".mcp.json").is_symlink()


def test_doctor_with_a_default_config_link_to_an_empty_file_names_that_file(tmp_path):
    # Same refusal for a link that resolves: install never writes through ./.mcp.json.
    real = tmp_path / "real.json"
    real.write_text('{"mcpServers":{}}')
    (tmp_path / ".mcp.json").symlink_to(real)
    proc = _run(tmp_path, ["doctor"])
    assert proc.returncode == 3, (proc.stdout, proc.stderr)
    out = proc.stdout
    behind = real.resolve()
    assert f"./.mcp.json is a link to {behind}." in out
    assert f"add a server to {behind}, then run: " \
           f"sunglasses install <name> --config {behind}" in out
    assert "Add a server to ./.mcp.json" not in out


def test_doctor_scoped_to_an_empty_config_speaks_only_of_that_file(tmp_path):
    # A project config with a server in it is NOT what was asked about: the line names the
    # file --config named, and the next step keeps --config so it edits that same file.
    (tmp_path / ".mcp.json").write_text(json.dumps(
        {"mcpServers": {"demo": {"command": "echo", "args": ["ok"]}}}))
    empty = tmp_path / "empty.json"
    empty.write_text('{"mcpServers":{}}')
    proc = _run(tmp_path, ["doctor", "--config", str(empty)])
    assert proc.returncode == 3, (proc.stdout, proc.stderr)
    out = proc.stdout
    assert f"{empty} lists no MCP servers, so nothing in it is wrapped." in out
    assert f"sunglasses install <name> --config {empty}" in out
    assert "The configs checked" not in out and "Nothing is wrapped yet" not in out


def test_doctor_onboarding_line_is_never_printed_beside_a_failed_self_test(tmp_path, monkeypatch, capsys):
    # An empty inventory is not a "nothing failed" predicate: a failed check keeps the stage.
    (tmp_path / "home").mkdir(exist_ok=True)
    report = doctor.run(sources=[], home=tmp_path / "home")
    out, _ = _text(report, monkeypatch, capsys)
    assert "The configs checked list no MCP servers" in out      # control: same report, no failure
    out, code = _text(report, monkeypatch, capsys, _a_failed_self_test_check)
    assert code == 3        # the mutation edits the rendered report; it does not recompute the exit
    assert "No server entries found." in out
    assert "no MCP servers" not in out and "Nothing is wrapped" not in out


# ---------------------------------------------------------------------------
# install with no MCP config in the folder (C491)
# ---------------------------------------------------------------------------

def test_install_with_no_mcp_config_says_so_plainly_and_changes_nothing(tmp_path):
    proc = _run(tmp_path, ["install", "filesystem"])
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    out = proc.stdout + proc.stderr
    assert "no MCP config file was found at " + str(tmp_path / ".mcp.json") in out
    assert "This command changed nothing." in out
    assert "--config <path>" in out
    assert "Errno" not in out and "No such file or directory" not in out
    assert not (tmp_path / ".mcp.json").exists()


def test_install_lock_failure_with_a_config_present_is_not_called_a_missing_config(tmp_path):
    # A dangling link at the transaction lock path is ENOENT too, raised after the
    # config was found. It must keep naming the lock, never claim the config is absent.
    import hashlib
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"demo": {"command": "echo", "args": ["ok"]}}}))
    before = cfg.read_bytes()
    locks = tmp_path / "home" / ".sunglasses" / "proxy" / "locks"
    locks.mkdir(parents=True)
    lock = locks / (hashlib.sha256(str(cfg.resolve()).encode()).hexdigest() + ".lock")
    lock.symlink_to(locks / "absent-dir" / "lock")
    proc = _run(tmp_path, ["install", "demo"])
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    out = proc.stdout + proc.stderr
    assert "no MCP config file was found" not in out and "changed nothing" not in out
    assert "lock" in out
    assert cfg.read_bytes() == before


def test_install_config_gone_after_the_first_look_keeps_the_failed_operation(tmp_path, monkeypatch, capsys):
    # Absent at the locked re-read, after state was prepared: an ordinary read error, not
    # the first-run sentence, because "changed nothing" would not be true of it.
    from sunglasses import install as inst
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(json.dumps({"mcpServers": {"demo": {"command": "echo", "args": ["ok"]}}}))

    def vanished(path):
        raise inst.ConfigIOError(f"cannot read {path}: no such file") from FileNotFoundError(2, "gone")

    monkeypatch.setattr(inst, "_read_bytes", vanished)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("SUNGLASSES_HOME", str(tmp_path / "home" / ".sunglasses"))
    args = type("A", (), {"config": str(cfg), "name": "demo", "argv": None})()
    with pytest.raises(SystemExit) as raised:
        cli.cmd_install(args)
    out = _ANSI.sub("", capsys.readouterr().out)
    assert raised.value.code == 2
    assert "no MCP config file was found" not in out and "changed nothing" not in out
    assert f"cannot read {cfg}" in out


def test_install_read_errors_other_than_absent_keep_their_own_wording(tmp_path):
    # A config that exists but is not JSON is not "no config": its own message stays.
    (tmp_path / ".mcp.json").write_text("{not json")
    proc = _run(tmp_path, ["install", "filesystem"])
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    out = proc.stdout + proc.stderr
    assert "no MCP config file was found" not in out
    assert "is not usable JSON" in out


# What `doctor --json` prints on a fresh install, byte for byte (it differs from the earlier
# release only in `exit_code`: 3, where it was 1). The report carries a measured duration, so the test
# below runs the child with its monotonic clock held at zero; nothing else in it depends on the
# machine.
_DOCTOR_JSON_FRESH = """{
  "self_test": {
    "valid": false,
    "controls": {},
    "checks": {
      "initialized": "NOT_RUN",
      "s1_forward_byte_equal": "NOT_RUN",
      "s2_block_schema": "NOT_RUN",
      "deadline": "NOT_RUN",
      "disconnect": "NOT_RUN"
    },
    "failed": [],
    "failure_class": "SELF_TEST_UNAVAILABLE",
    "detail": "SELF_TEST_UNAVAILABLE",
    "measured_ms": 0,
    "bound_ms": 2250,
    "deadline": "deadline 0 ms measured against a 2250 ms bound"
  },
  "per_wrapper": [],
  "inventory": [],
  "aggregate": "ROUTE_UNVERIFIED",
  "route_checks": {},
  "receipts_key": {
    "status": "OFF",
    "cause": ""
  },
  "exit_code": 3
}
"""


def test_doctor_json_is_byte_for_byte_the_report_it_was(tmp_path):
    # text=False: the bytes the process wrote, not text with its line endings translated
    proc = _run(tmp_path, ["doctor", "--json"], child=_CHILD_CLOCK_AT_ZERO, text=False)
    assert proc.returncode == 3
    assert proc.stdout == _DOCTOR_JSON_FRESH.encode("utf-8")


def test_doctor_help_documents_exit_three_as_not_proven(tmp_path):
    proc = _run(tmp_path, ["doctor", "--help"])
    assert 'Exit 3 here means "I could not prove it"' in proc.stdout


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
    with pytest.raises(SystemExit) as raised:
        cli.cmd_doctor(args, _run=lambda **kw: report)
    return _ANSI.sub("", capsys.readouterr().out), raised.value.code


def _fail_a_route(rendered):
    rendered["per_wrapper"].append({"name": "demo", "source": "project", "result": "FAIL"})


def _an_unusable_signing_key(rendered):
    rendered["receipts_key"] = {"status": "KEY_UNUSABLE", "cause": "x"}


def _an_unreadable_source(rendered):
    rendered["inventory"][0]["detail"] = "could not open"


def _a_failed_self_test_check(rendered):
    rendered["self_test"]["failed"] = ["initialized"]


def test_the_sentence_is_printed_when_that_is_the_whole_story(tmp_path, monkeypatch, capsys):
    out, code = _text(_unavailable_report(tmp_path), monkeypatch, capsys)
    assert code == 3
    assert "No check failed, and none could run." in out


@pytest.mark.parametrize("mutate", [_fail_a_route, _an_unusable_signing_key,
                                    _an_unreadable_source, _a_failed_self_test_check])
def test_the_sentence_is_never_printed_beside_a_real_failure(tmp_path, monkeypatch, capsys, mutate):
    """Reassurance is only true when the unavailable self-test is the only reason for the exit code."""
    out, code = _text(_unavailable_report(tmp_path), monkeypatch, capsys, mutate)
    assert code == 3        # the mutation edits the rendered report; it does not recompute the exit
    assert "No check failed" not in out
    assert "exit 3" in out
