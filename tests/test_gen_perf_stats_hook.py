"""hook_speed: the one dated source for a per-tool-call hook time.

A README or page that quotes how long the firewall hook takes must cite a block that names
its scope, its build and its date, never a number typed by hand. These tests pin that the
generator emits those keys, that a hook-only refresh leaves every other key as it was, and
that the committed stats file carries the block. They assert shape, never a duration.
"""
import importlib.util
import json
import os
import pathlib
import shlex
import sys
from datetime import datetime

from sunglasses.firewall import HOOK_MARKER, build_hook_entry

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATS = ROOT / "stats" / "current.json"

_spec = importlib.util.spec_from_file_location("gen_perf_stats", ROOT / "tools" / "gen_perf_stats.py")
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

TIMING_CASES = ("hook_lane_off", "hook_lane_on", "python_start")
REQUIRED = {"repeats", "command_shape", "scope", "version", "measured_on", "measured_at", "generated_by"}


def _check_block(block):
    assert REQUIRED <= set(block)
    for case in TIMING_CASES:
        low, mid = block[f"{case}_min_ms"], block[f"{case}_median_ms"]
        assert isinstance(low, float) and isinstance(mid, float)
        assert 0 < low <= mid
    datetime.fromisoformat(block["measured_at"])  # a real date, with a zone
    assert block["generated_by"] == "tools/gen_perf_stats.py"
    assert "interpreter start" in block["scope"]


def test_measure_hook_emits_scoped_dated_keys():
    block = gen.measure_hook(repeats=2)
    _check_block(block)
    assert block["repeats"] == 2
    assert block["version"] == gen.SUNGLASSES_VERSION


def test_hook_only_write_touches_nothing_else(tmp_path):
    path = tmp_path / "current.json"
    before = {"scan_speed": {"quickstart_median_ms": 1.5}, "keywords": 7,
              "hook_speed": {"stale": True}}
    path.write_text(json.dumps(before), encoding="utf-8")
    gen.write_hook_only(str(path), {"fresh": True})
    after = json.loads(path.read_text(encoding="utf-8"))
    assert after["hook_speed"] == {"fresh": True}
    assert {k: v for k, v in after.items() if k != "hook_speed"} == \
        {k: v for k, v in before.items() if k != "hook_speed"}


def test_committed_stats_file_carries_the_block():
    _check_block(json.loads(STATS.read_text(encoding="utf-8"))["hook_speed"])


def test_measured_command_is_the_one_the_installer_writes():
    """The timed argv is the installed hook command, not a sibling entry point.

    The installer registers `<python> -m <HOOK_MARKER>`. An earlier version timed the hidden
    `sunglasses firewall-hook` CLI subcommand, which imports the whole engine first and so is a
    different (slower) command. Pin the generator to the installer's own marker.
    """
    entry = build_hook_entry(interpreter=sys.executable)
    installed = shlex.split(entry["hooks"][0]["command"])
    assert gen.hook_argv() == installed
    assert gen.hook_argv()[-2:] == ["-m", HOOK_MARKER]
    assert "firewall-hook" not in gen.hook_argv()


def test_block_names_the_command_it_timed():
    block = json.loads(STATS.read_text(encoding="utf-8"))["hook_speed"]
    assert block["command"] == f"python -m {HOOK_MARKER}"


def test_measure_hook_runs_the_installed_command_in_both_lanes(monkeypatch):
    """What measure_hook actually hands to the timer is the installed command, and the ledger says so.

    Pinning hook_argv() alone guards the helper, not the call site: a measure_hook that typed its
    own argv, or timed `python -c pass` as the hook, would stay green. Capture the argv at the
    timer and compare it with the installed command; the recorded `command` is derived from
    the argv that ran, never a literal.
    """
    seen = []
    lane_marker = []  # per call: does the HOME the child would get hold the warn-lane marker?

    def fake_process_ms(argv, env, stdin, repeats):
        seen.append((list(argv), stdin))
        lane_marker.append(os.path.exists(os.path.join(env["HOME"], "warn-lane")))
        return 1.0, 2.0

    monkeypatch.setattr(gen, "_process_ms", fake_process_ms)
    block = gen.measure_hook(repeats=2)
    installed = shlex.split(build_hook_entry(interpreter=sys.executable)["hooks"][0]["command"])
    assert [argv for argv, _ in seen] == [installed, installed, [sys.executable, "-c", "pass"]]
    assert seen[0][1] is not None and seen[0][1] == seen[1][1]  # the same benign Bash call in both lanes
    assert block["command"] == "python " + " ".join(installed[1:])
    assert block["command"] == f"python -m {HOOK_MARKER}"
    # lane off is timed in a HOME without the marker, lane on in a HOME with it: two lanes timed
    # in the same HOME would measure one thing twice (the interpreter-floor call is lane-less).
    assert lane_marker[:2] == [False, True]
