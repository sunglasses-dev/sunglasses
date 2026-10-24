"""scripts/pattern_perf_gate.py: the dynamic tripwire for a pattern change that makes a regex slower.

The shape lint is static. This gate times the regexes a pull request changes, base against head,
and fails on superlinear growth, on a large head/base jump, on a run that hits the cap, on a waiver
that no longer trips, on work the wall budget left undone and on a table it cannot read. The tests drive it with synthetic rule tables and, for the end-to-end
cases, a regex that is quadratic on purpose next to one that is linear, at sizes small enough to run
in a fraction of a second.
"""
import importlib.util
import json
import os
import pathlib
import re
import subprocess
import sys
import time

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "pattern_perf_gate.py"
spec = importlib.util.spec_from_file_location("pattern_perf_gate", SCRIPT)
g = importlib.util.module_from_spec(spec)
sys.modules["pattern_perf_gate"] = g
spec.loader.exec_module(g)

SMALL = (1000, 2000, 4000)
SMALL_ADDED = (1000, 2000)
QUADRATIC = r"a+b"               # no `b` in the text: every start walks to the end of the run
LINEAR = r"read\s+token"


_NONE = object()


def run(base, head, waivers_base=_NONE, waivers_head=None, **kw):
    kw.setdefault("sizes", SMALL)
    kw.setdefault("added_sizes", SMALL_ADDED)
    kw.setdefault("repeats", 1)
    kw.setdefault("growth_floor", 0)
    kw.setdefault("ratio_floor", 0)
    return g.gate(base, head, {} if waivers_base is _NONE else waivers_base, waivers_head or {}, **kw)


# ---------------------------------------------------------------- changed ids

def test_changed_ids_splits_added_changed_removed_and_unchanged():
    base = {"A": ("x",), "B": ("y",), "C": ("z",)}
    head = {"A": ("x",), "B": ("y2",), "D": ("w",)}
    changed, added = g.changed_ids(base, head)
    assert changed == {"B"}
    assert added == {"D"}


def test_a_rule_with_no_regex_is_not_timed():
    changed, added = g.changed_ids({}, {"A": ()})
    assert not changed and not added


PAT = 'PATTERNS = [{"id": "P1", "regex": ["a", "b"]}, {"id": "P2"}]\n'
MECH = 'MECHANISM_PATTERNS = [{"id": "M1", "regex": ["c"]}]\n'


def test_rules_from_sources_reads_both_tables():
    out = g.rules_from_sources({"sunglasses/patterns.py": PAT, "sunglasses/mechanisms.py": MECH})
    assert out == {"P1": ("a", "b"), "P2": (), "M1": ("c",)}


def test_a_missing_table_file_fails_closed():
    with pytest.raises(g.GateError, match="not readable"):
        g.rules_from_sources({"sunglasses/patterns.py": PAT, "sunglasses/mechanisms.py": None})


def test_an_empty_table_fails_closed():
    with pytest.raises(g.GateError, match="empty"):
        g.rules_from_sources({"sunglasses/patterns.py": "PATTERNS = []\n", "sunglasses/mechanisms.py": MECH})


def test_a_duplicate_id_fails_closed_inside_a_table_and_across_tables():
    dup = 'PATTERNS = [{"id": "X", "regex": ["a"]}, {"id": "X", "regex": ["b"]}]\n'
    with pytest.raises(g.GateError, match="more than once"):
        g.rules_from_sources({"sunglasses/patterns.py": dup, "sunglasses/mechanisms.py": MECH})
    across = 'MECHANISM_PATTERNS = [{"id": "P1", "regex": ["c"]}]\n'
    with pytest.raises(g.GateError, match="more than once"):
        g.rules_from_sources({"sunglasses/patterns.py": PAT, "sunglasses/mechanisms.py": across})


def _src(prelude):
    return {"sunglasses/patterns.py": prelude + PAT, "sunglasses/mechanisms.py": MECH}


@pytest.mark.parametrize("prelude", [
    "import sys\nsys.exit(0)\n",                         # a clean exit before the table is read
    "import os\nos._exit(0)\n",                          # the hardest exit there is
    "raise SystemExit(0)\n",
    "exit(0)\n",
    "import sys\nif 'perf' in sys.argv[0] or 'result' in sys.argv[3]:\n    sys.exit(0)\n",   # a conditional exit
    # a source that writes the loader's own result file for the table it likes, then leaves
    "import json, sys\njson.dump({'ok': True, 'table': 'PATTERNS', 'rules': [['P1', ['a']]]}, open(sys.argv[3], 'w'))\nsys.exit(0)\n",
    "import json, sys\njson.dump({'ok': True}, open(sys.argv[3], 'w'))\nsys.exit(7)\n",
    # a source that replaces the serializer the loader would use
    "import json\njson.dump = lambda *a, **k: None\n",
    "__import__('os')._exit(0)\n",
    "x = ().__class__.__bases__\n",                       # a way out through an object's own attributes
    "x = open('/nonexistent')\n",                          # an I/O call
    "import time\ntime.sleep(30)\n",
    "while True:\n    pass\n",
    "f = lambda: 1\n",
    "class C:\n    pass\n",
    "@staticmethod\ndef f():\n    return 1\n",
    "import_me = [].append(1)\n",                          # a method that is not on the list
    "def f():\n    raise SystemExit(0)\n",
    "def f():\n    for x in y:\n        pass\n",
    "x = __builtins__\n",                                  # the interpreter's own namespace
    "x = []\nx[0] = 1\n",                                 # an assignment to something that is not a name
    "str(1)\n",                                            # a statement that is a call, not a docstring
    "import os\n",                                         # an import, even one nothing uses
])
def test_a_table_source_that_runs_anything_but_plain_assignments_is_refused_not_run(prelude, tmp_path):
    marker = tmp_path / "ran"
    src = _src(prelude.replace("/nonexistent", str(marker)))
    with pytest.raises(g.GateError, match="without running them"):
        g.rules_from_sources(src)
    assert not marker.exists()


def test_a_source_that_does_not_parse_or_names_no_table_is_a_failure():
    with pytest.raises(g.GateError, match="does not parse"):
        g.rules_from_sources(_src("this is not python (\n"))
    with pytest.raises(g.GateError, match="no PATTERNS list"):
        g.rules_from_sources({"sunglasses/patterns.py": "X = 1\n", "sunglasses/mechanisms.py": MECH})
    with pytest.raises(g.GateError, match="string id"):
        g.rules_from_sources({"sunglasses/patterns.py": 'PATTERNS = [{"id": 1, "regex": ["a"]}]\n',
                              "sunglasses/mechanisms.py": MECH})
    with pytest.raises(g.GateError, match="string id"):
        g.rules_from_sources({"sunglasses/patterns.py": 'PATTERNS = [{"id": "A", "regex": [1]}]\n',
                              "sunglasses/mechanisms.py": MECH})


def test_a_source_that_fails_while_being_evaluated_is_a_failure():
    for prelude in ("x = undefined_name\n", "def f():\n    return f()\ny = f()\n", "x = 1 + 'a'\n"):
        with pytest.raises(g.GateError, match="could not be read"):
            g.rules_from_sources(_src(prelude))


def test_the_constructs_the_real_tables_use_are_read():
    src = _src(
        "_A = 'x'\n_B = f'(?:{_A})y'\n"
        "def _j(*s: str) -> str:\n    \"\"\"doc\"\"\"\n    return '|'.join(f'{t}s?' for t in s)\n"
        "_C = _j('a', 'b') + r'|c'\n")
    src["sunglasses/patterns.py"] = src["sunglasses/patterns.py"].replace('["a", "b"]', '[_B, _C]')
    out = g.rules_from_sources(src)
    assert out["P1"] == ("(?:x)y", "as?|bs?|c")


def test_a_slow_evaluation_is_cut_off_by_the_time_left():
    big = "[" + ", ".join(["'q'"] * 300) + "]"
    slow = f"_L = {big}\n_N = len([1 for a in _L for b in _L for c in _L for d in _L if a == b and c == d and a == 'z'])\n"
    with pytest.raises(g.GateError, match="did not finish in the time left"):
        g.rules_from_sources(_src(slow), g.Budget(1.0))


def test_the_budget_runs_through_reading_and_a_spent_budget_fails_before_a_table_is_read():
    spent = g.Budget(10, clock=lambda: 100.0, started=0.0)
    with pytest.raises(g.GateError, match="wall budget was spent"):
        g.rules_from_sources(_src(""), spent)
    # and reading hands the table no more than the time that is left
    seen = []
    real = g._within
    g._within = lambda seconds, what, fn: (seen.append(seconds), real(seconds, what, fn))[1]
    try:
        g.rules_from_sources(_src(""), g.Budget(5.0))
    finally:
        g._within = real
    assert seen and all(0 < x <= 5.0 for x in seen)


def test_the_real_tables_load_standalone():
    sources = {p: (ROOT / p).read_text(encoding="utf-8") for p, _ in g.TABLES}
    rules = g.rules_from_sources(sources)
    assert len(rules) > 1000 and any(i.startswith("GLS-EX-") for i in rules)


# ---------------------------------------------------------------- verdict logic

def _t(a, b, c):
    return dict(zip(g.SIZES, (a, b, c)))


def test_linear_growth_passes():
    growth, ratio, why = g.judge(_t(.1, .2, .4), _t(.1, .2, .4), g.SIZES)
    assert why == [] and round(growth, 2) == 2.0 and round(ratio, 2) == 1.0


def test_superlinear_growth_fails():
    _, _, why = g.judge(None, _t(.1, .2, .9), g.SIZES)
    assert why and "growth" in why[0]


def test_growth_under_the_floor_never_flaps():
    _, _, why = g.judge(None, _t(.001, .002, .009), g.SIZES)
    assert why == []


def test_a_large_head_over_base_jump_fails_only_above_the_floor():
    assert g.judge(_t(.1, .2, .4), _t(.2, .4, .8), g.SIZES)[2][0].startswith("head/base")
    assert g.judge(_t(.01, .02, .04), _t(.02, .04, .08), g.SIZES)[2] == []


def test_a_head_run_that_hit_the_cap_fails():
    assert "cap" in g.judge(None, _t(.1, .2, None), g.SIZES)[2][0]


def test_a_base_run_that_hit_the_cap_is_reported():
    assert "base" in g.judge(_t(.1, .2, None), _t(.1, .2, .4), g.SIZES)[2][0]


# ---------------------------------------------------------------- waivers

def test_a_waiver_needs_a_dated_reason_and_a_real_id():
    probs = g.check_waivers({"A": "2026-10-24 bounded by the engine window", "B": "no date", "Z": "2026-10-24 x"},
                            {"A": ("a",), "B": ("b",)})
    assert len(probs) == 2
    assert any("B" in p and "dated" in p for p in probs) and any("Z" in p and "not in the rules" in p for p in probs)


# ---------------------------------------------------------------- end to end, small sizes

def test_a_quadratic_head_regex_fails():
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
    assert failures and any(r["verdict"] == "FAIL" for r in rows)
    assert any("growth" in f or "head/base" in f for f in failures)


def test_a_linear_head_regex_passes():
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (r"read\s+tokens?",)}, growth_floor=1, ratio_floor=1)
    assert failures == [] and rows and all(r["verdict"] == "ok" for r in rows)


def test_an_unchanged_table_times_nothing():
    rows, failures, notes = run({"R": (QUADRATIC,)}, {"R": (QUADRATIC,)})
    assert rows == [] and failures == [] and "timing 0 + 0 new" in notes[0]


def test_a_new_quadratic_id_is_caught_by_growth_alone():
    rows, failures, _ = run({}, {"N": (QUADRATIC,)})
    assert failures and rows[0]["base"] is None and rows[0]["sizes"] == SMALL_ADDED


def test_a_waived_quadratic_prints_and_passes():
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)},
                            waivers_head={"R": "2026-10-24 the engine bounds this window"})
    assert failures == [] and any(r["verdict"] == "WAIVED" for r in rows)


def test_a_stale_waiver_fails():
    _, failures, _ = run({"R": (LINEAR,)}, {"R": (r"read\s+tokens?",)},
                         waivers_base={"R": "2026-10-24 old"}, waivers_head={"R": "2026-10-24 old"},
                         growth_floor=1, ratio_floor=1)
    assert any("no longer trips" in f for f in failures)


def test_a_waiver_removed_in_the_pull_request_is_retimed_even_if_the_regex_is_unchanged():
    rows, failures, notes = run({"R": (QUADRATIC,)}, {"R": (QUADRATIC,)},
                                waivers_base={"R": "2026-10-24 old"}, waivers_head={})
    assert "waiver removed 1" in notes[0] and failures


def test_the_wall_cap_fails_closed_and_names_what_was_not_run():
    clock = iter(range(0, 10_000, 100))
    rows, failures, _ = run({"A": (LINEAR,), "B": (LINEAR,)}, {"A": (QUADRATIC,), "B": (QUADRATIC,)},
                            wall_cap=150, clock=lambda: next(clock))
    assert any(r["verdict"] == "NOT-RUN" for r in rows)
    assert any("wall cap" in f for f in failures)


def test_the_run_cap_counts_as_a_failure(monkeypatch):
    monkeypatch.setattr(g, "time_once", lambda rxs, text, cap=g.RUN_CAP_S: None)
    _, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
    assert failures and any("cap" in f for f in failures)


# ---------------------------------------------------------------- the timer is given back

@pytest.mark.skipif(not hasattr(__import__("signal"), "setitimer"), reason="no interval timer here")
def test_timing_leaves_the_alarm_signal_as_it_found_it():
    import signal
    before = signal.getsignal(signal.SIGALRM)
    assert g.time_once([__import__("re").compile("a")], "aaa") is not None
    assert signal.getsignal(signal.SIGALRM) == before
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)
    run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})          # a whole gate run, cut or not, does the same
    assert signal.getsignal(signal.SIGALRM) == before


@pytest.mark.skipif(not hasattr(__import__("signal"), "setitimer"), reason="no interval timer here")
def test_a_gate_run_does_not_make_the_firewall_budget_lane_unavailable():
    # The firewall gives its pattern scan a SIGALRM budget only while the handler is the default.
    # A gate run that left its own handler behind turned every later firewall check into an "ask".
    run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
    from sunglasses import firewall as fw
    finished, _ = fw._run_within_budget(lambda: 1, 5)
    assert finished is True


# ---------------------------------------------------------------- sampler

def test_the_sampler_cuts_short_of_the_whole_match_and_adds_the_generic_units():
    units = g.sampled_units([r"read.{0,100}\.env.{0,220}paste.{0,100}issue"])
    assert any(u.startswith("read") and "paste" not in u for u in units)
    assert all(u in units for u in g.GENERIC_UNITS)
    assert len(units) == len(set(units))


def test_the_sampler_is_deterministic_and_survives_a_bad_regex():
    assert g.sampled_units([r"a+b"]) == g.sampled_units([r"a+b"])
    assert g.sampled_units(["("]) == list(g.GENERIC_UNITS)


# ---------------------------------------------------------------- command line

def _git(repo, *a):
    return subprocess.run(["git", "-C", str(repo), *a], capture_output=True, text=True, check=True).stdout.strip()


def _repo(tmp_path, base_regex, head_regex, waivers=None, head_mech=MECH):
    repo = tmp_path / "r"
    (repo / "sunglasses").mkdir(parents=True)
    _git(tmp_path, "init", "-q", str(repo))
    _git(repo, "config", "user.email", "t@example.invalid")
    _git(repo, "config", "user.name", "t")
    table = lambda rx: f'PATTERNS = [{{"id": "R1", "regex": [{rx!r}]}}]\n'
    (repo / "sunglasses" / "patterns.py").write_text(table(base_regex))
    (repo / "sunglasses" / "mechanisms.py").write_text(MECH)
    _git(repo, "add", "sunglasses/patterns.py", "sunglasses/mechanisms.py")
    _git(repo, "commit", "-qm", "base")
    base = _git(repo, "rev-parse", "HEAD")
    (repo / "sunglasses" / "patterns.py").write_text(table(head_regex))
    (repo / "sunglasses" / "mechanisms.py").write_text(head_mech)
    add = ["sunglasses/patterns.py", "sunglasses/mechanisms.py"]
    if waivers is not None:
        (repo / "tests").mkdir()
        (repo / "tests" / "pattern_perf_waivers.json").write_text(json.dumps(waivers))
        add.append("tests/pattern_perf_waivers.json")
    _git(repo, "add", *add)
    _git(repo, "commit", "-q", "--allow-empty", "-m", "head")
    return repo, base, _git(repo, "rev-parse", "HEAD")


def _env(**extra):
    env = {k: v for k, v in os.environ.items() if k != "GITHUB_STEP_SUMMARY"}
    env.update(extra)
    return env


def _cli(repo, *args, **env):
    return subprocess.run([sys.executable, str(SCRIPT), "--repo", str(repo), *args], capture_output=True,
                          text=True, env=_env(**env))


def test_cli_without_a_pull_request_exits_zero():
    r = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True)
    assert r.returncode == 0 and "not a pull request" in r.stdout


def test_cli_rejects_a_ref_that_is_not_a_full_sha(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR)
    r = _cli(repo, "--base", "main", "--head", head)
    assert r.returncode == 2


def test_cli_passes_when_nothing_changed(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR)
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 0 and "pattern-perf: pass" in r.stdout


def test_cli_writes_the_step_summary(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR)
    out = tmp_path / "summary.md"
    r = _cli(repo, "--base", base, "--head", head, GITHUB_STEP_SUMMARY=str(out))
    assert "## pattern-perf" in out.read_text() and r.returncode == 0


def test_cli_rejects_a_malformed_waiver_file(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR, waivers=["R1"])
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 1 and "JSON object" in r.stderr


def test_the_committed_waiver_file_is_valid_and_every_entry_is_dated():
    path = ROOT / g.WAIVERS
    waivers = g.read_waivers(path.read_text(encoding="utf-8"))
    rules = g.rules_from_sources({p: (ROOT / p).read_text(encoding="utf-8") for p, _ in g.TABLES})
    assert g.check_waivers(waivers, rules) == []


# ---------------------------------------------------------------- r2: the workload, per regex

def test_a_new_id_is_timed_at_the_larger_size_pair():
    assert g.ADDED_SIZES == g.SIZES[-2:]


def test_every_regex_of_a_new_id_is_judged_on_its_own_units():
    rows, failures, _ = run({}, {"N": (LINEAR, QUADRATIC)})
    cases = {r["case"].split("/")[0] for r in rows}
    assert cases == {"r0", "r1"}
    assert failures and all(f.startswith("N r1/") for f in failures)


def test_a_slow_second_expression_is_not_diluted_by_a_heavier_linear_first_one():
    heavy_linear = r"(?:read\s+token\s*){1,40}x"
    rows, failures, _ = run({"R": (LINEAR, LINEAR)}, {"R": (heavy_linear, QUADRATIC)})
    assert any(f.startswith("R r1/") for f in failures)


def test_only_the_regexes_that_changed_are_timed_for_a_changed_id():
    rows, failures, _ = run({"R": (LINEAR, LINEAR)}, {"R": (LINEAR, QUADRATIC)})
    assert {r["case"].split("/")[0] for r in rows} == {"r1"}


def test_reordering_the_same_regexes_times_nothing_and_is_not_a_failure():
    rows, failures, _ = run({"R": (LINEAR, QUADRATIC)}, {"R": (QUADRATIC, LINEAR)})
    assert rows == [] and failures == []


def test_a_row_names_a_case_not_the_input_and_the_table_hides_the_input_by_default():
    rows, _, _ = run({}, {"N": (QUADRATIC,)})
    assert all(r["case"].startswith("r0/u") for r in rows)
    assert all(r["unit"] not in g.table(rows) for r in rows if len(r["unit"]) > 2)


# ---------------------------------------------------------------- r2: waivers

def test_a_waiver_added_in_the_pull_request_is_retimed_and_must_trip():
    rows, failures, notes = run({"R": (LINEAR,)}, {"R": (LINEAR,)}, waivers_base={},
                                waivers_head={"R": "2026-10-24 reviewed"}, growth_floor=1, ratio_floor=1)
    assert "waiver added 1" in notes[0] and any("no longer trips" in f for f in failures)


def test_a_waiver_added_for_a_real_quadratic_passes_and_is_printed():
    rows, failures, _ = run({"R": (QUADRATIC,)}, {"R": (QUADRATIC,)}, waivers_base={},
                            waivers_head={"R": "2026-10-24 reviewed"})
    assert failures == [] and any(r["verdict"] == "WAIVED" for r in rows)


def test_a_waiver_on_a_new_id_must_trip_too():
    _, failures, _ = run({}, {"N": (LINEAR,)}, waivers_head={"N": "2026-10-24 reviewed"},
                         growth_floor=1, ratio_floor=1)
    assert any("no longer trips" in f for f in failures)


def test_a_waiver_nobody_touched_is_not_retimed():
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (LINEAR,)}, waivers_base={"R": "2026-10-24 old"},
                            waivers_head={"R": "2026-10-24 old"})
    assert rows == [] and failures == []


def test_the_pull_request_that_creates_the_waiver_file_seeds_it_without_retiming_it():
    rows, failures, notes = run({"R": (LINEAR,)}, {"R": (LINEAR,)}, waivers_base=None,
                                waivers_head={"R": "2026-10-24 seed"})
    assert rows == [] and failures == [] and "seed" in notes[1]


def test_cli_seeds_when_the_base_has_no_waiver_file_and_retimes_added_waivers_after(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR, waivers={"R1": "2026-10-24 seed"})
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 0 and "not retimed" in r.stdout
    (repo / "tests" / "pattern_perf_waivers.json").write_text(json.dumps({"R1": "2026-10-24 seed", "R9": "2026-10-24 x"}))
    _git(repo, "add", "-A")
    _git(repo, "commit", "-qm", "again")
    r2 = _cli(repo, "--base", head, "--head", _git(repo, "rev-parse", "HEAD"))
    assert "waiver added" in r2.stdout and "not retimed" not in r2.stdout


# ---------------------------------------------------------------- r2: the budget

class _Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t


def _slow_timer(monkeypatch, clock, step):
    def fake(rxs, text, cap=g.RUN_CAP_S):
        clock.t += step
        return 0.001
    monkeypatch.setattr(g, "time_once", fake)


def test_work_that_finishes_past_the_wall_cap_fails_even_for_the_last_item(monkeypatch):
    clock = _Clock()
    _slow_timer(monkeypatch, clock, 60.0)
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (r"read\s+tokens?",)}, wall_cap=150, clock=clock,
                            repeats=1)
    assert failures and any("wall cap" in f for f in failures)


def test_a_measurement_cut_short_by_the_budget_is_not_a_verdict(monkeypatch):
    clock = _Clock()
    _slow_timer(monkeypatch, clock, 60.0)
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, wall_cap=150, clock=clock, repeats=1)
    assert all(r["verdict"] in ("NOT-RUN", "ok", "FAIL", "WAIVED") for r in rows)
    assert any(r["verdict"] == "NOT-RUN" for r in rows) and any("wall cap" in f for f in failures)


def test_the_pre_pass_stops_when_the_budget_is_spent():
    b = g.Budget(cap=10, clock=lambda: 100.0, started=0.0)
    assert b.over() and g.pick_units([QUADRATIC], 3, b) == []


def test_a_run_never_gets_more_than_the_time_left(monkeypatch):
    caps = []
    monkeypatch.setattr(g, "time_once", lambda rxs, text, cap=g.RUN_CAP_S: caps.append(cap) or 0.001)
    clock = _Clock()
    clock.t = 148.0
    g.median_time([], "x", 1, g.Budget(cap=150, clock=clock, started=0.0))
    assert caps and max(caps) <= 2.0 + 1e-9


def test_a_zero_wall_cap_runs_nothing_and_fails(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, QUADRATIC)
    r = _cli(repo, "--base", base, "--head", head, "--wall-cap", "0")
    assert r.returncode == 1 and "wall" in r.stdout + r.stderr


def test_a_budget_spent_in_the_pre_pass_is_not_run_not_silently_untimed(monkeypatch):
    clock = _Clock()
    _slow_timer(monkeypatch, clock, 40.0)
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, wall_cap=100, clock=clock, repeats=1)
    assert failures and rows and all(r["verdict"] == "NOT-RUN" for r in rows)


def test_a_regex_with_no_units_to_judge_it_on_is_not_run_not_passed(monkeypatch):
    monkeypatch.setattr(g, "pick_units", lambda regexes, keep, budget=None: [])
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
    assert [r["verdict"] for r in rows] == ["NOT-RUN"] and any("not run" in f for f in failures)


def test_a_last_measurement_that_ends_past_the_budget_is_not_a_pass(monkeypatch):
    clock = _Clock()
    monkeypatch.setattr(g, "pick_units", lambda regexes, keep, budget=None: ["read token "])

    def slow_once(rxs, text, repeats, budget=None):
        clock.t += 200.0
        return 0.001

    monkeypatch.setattr(g, "median_time", slow_once)
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)}, wall_cap=150, clock=clock, growth_floor=1,
                            ratio_floor=1)
    assert [r["verdict"] for r in rows] == ["NOT-RUN"] and any("wall cap" in f for f in failures)


@pytest.mark.parametrize("cap", range(5, 400, 17))
def test_a_pass_never_comes_from_a_run_that_outlived_its_budget(monkeypatch, cap):
    clock = _Clock()

    def tick():
        clock.t += 1.0
        return clock.t

    def fake(rxs, text, cap_=g.RUN_CAP_S):
        clock.t += 3.0
        return 0.001

    monkeypatch.setattr(g, "time_once", fake)
    start = clock.t
    rows, failures, _ = run({"A": (LINEAR,), "B": (LINEAR,)}, {"A": (r"read\s+tokens?",), "B": (r"read\s+tokens",)},
                            wall_cap=cap, clock=tick, repeats=1, growth_floor=1, ratio_floor=1)
    if not failures:
        assert clock.t - start <= cap


# ---------------------------------------------------------------- r2: noise

def _seq(values):
    it = iter(values)
    calls = []
    def fake(rxs, text, cap=g.RUN_CAP_S):
        calls.append(1)
        return next(it, values[-1])
    return fake, calls


def test_a_short_run_is_repeated_until_the_sample_is_worth_trusting(monkeypatch):
    fake, calls = _seq([0.001])
    monkeypatch.setattr(g, "time_once", fake)
    assert g.median_time([], "x", 3) == pytest.approx(0.001)
    assert len(calls) == g.MAX_REPEATS


def test_a_medium_run_gets_enough_repeats_to_total_about_half_a_second(monkeypatch):
    fake, calls = _seq([0.1])
    monkeypatch.setattr(g, "time_once", fake)
    g.median_time([], "x", 3)
    assert len(calls) == 5


def test_one_slow_outlier_among_short_runs_does_not_move_the_median(monkeypatch):
    fake, _ = _seq([0.02, 0.021, 0.30, 0.022, 0.02, 0.02, 0.021])
    monkeypatch.setattr(g, "time_once", fake)
    assert g.median_time([], "x", 3) < 0.03


def test_a_long_first_run_is_confirmed_and_the_lower_stands(monkeypatch):
    fake, calls = _seq([0.9, 0.3])
    monkeypatch.setattr(g, "time_once", fake)
    assert g.median_time([], "x", 3) == pytest.approx(0.3)
    assert len(calls) == 2


def test_a_run_near_the_cap_stands_alone(monkeypatch):
    fake, calls = _seq([g.RUN_CAP_S * 0.6])
    monkeypatch.setattr(g, "time_once", fake)
    g.median_time([], "x", 3)
    assert len(calls) == 1


def test_a_cap_in_any_repeat_is_a_cap(monkeypatch):
    fake, _ = _seq([0.001, 0.001, None])
    monkeypatch.setattr(g, "time_once", fake)
    assert g.median_time([], "x", 3) is None


# ---------------------------------------------------------------- r2: the log carries no numbers

def test_in_a_job_the_table_goes_to_the_summary_and_the_log_carries_verdict_words_only(tmp_path, monkeypatch):
    summary = tmp_path / "s.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    rows, failures, notes = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
    log = g.report(rows, failures, notes)
    assert "| id | case |" in summary.read_text() and "|" not in log
    assert "FAIL: R r0/u" in log and "superlinear growth" in log
    assert not re.search(r"\d+\.\d+", log)
    assert "job summary" in log


def test_with_no_summary_file_the_log_carries_the_table(monkeypatch):
    monkeypatch.delenv("GITHUB_STEP_SUMMARY", raising=False)
    rows, failures, notes = run({"R": (LINEAR,)}, {"R": (QUADRATIC,)})
    assert "| id | case |" in g.report(rows, failures, notes)


# ---------------------------------------------------------------- r2: inputs that cannot be judged

def test_cli_fails_closed_when_the_base_commit_is_not_in_the_checkout(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR)
    r = _cli(repo, "--base", "0" * 40, "--head", head)
    assert r.returncode == 1 and "not in the checkout" in r.stderr


def test_cli_fails_closed_when_the_head_commit_is_not_in_the_checkout(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR)
    r = _cli(repo, "--base", base, "--head", "1" * 40)
    assert r.returncode == 1 and "not in the checkout" in r.stderr


def test_cli_fails_closed_when_the_second_table_is_missing_at_the_base(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR)
    _git(repo, "rm", "-q", "sunglasses/mechanisms.py")
    _git(repo, "commit", "-qm", "drop")
    r = _cli(repo, "--base", base, "--head", _git(repo, "rev-parse", "HEAD"))
    assert r.returncode == 1 and "not readable" in r.stderr


def test_cli_fails_closed_on_an_empty_head_table(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR, head_mech="MECHANISM_PATTERNS = []\n")
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 1 and "empty" in r.stderr


def test_cli_fails_closed_on_a_head_table_that_exits_before_it_is_read(tmp_path):
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR, head_mech="import sys\nsys.exit(0)\n" + MECH)
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 1 and "without running them" in r.stderr


def test_cli_fails_closed_on_a_head_table_that_forges_the_loaders_result_and_leaves(tmp_path):
    forged = ("import json, sys\njson.dump({'ok': True, 'table': 'MECHANISM_PATTERNS', 'rules': [['M1', ['c']]]}, "
              "open(sys.argv[3], 'w'))\nsys.exit(0)\n")
    repo, base, head = _repo(tmp_path, LINEAR, QUADRATIC, head_mech=forged + MECH)
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 1 and "without running them" in r.stderr


def test_cli_cuts_a_table_that_takes_longer_to_read_than_the_time_left(tmp_path):
    big = "[" + ", ".join(["'q'"] * 400) + "]"
    slow = f"_L = {big}\n_N = len([1 for a in _L for b in _L for c in _L for d in _L if a == b and c == d and a == 'z'])\n"
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR, head_mech=slow + MECH)
    start = time.monotonic()
    r = _cli(repo, "--base", base, "--head", head, "--wall-cap", "2")
    assert r.returncode == 1 and "did not finish in the time left" in r.stderr
    assert time.monotonic() - start < 20


def test_cli_fails_closed_on_a_duplicate_id_hidden_behind_an_unchanged_row(tmp_path):
    dup = 'MECHANISM_PATTERNS = [{"id": "M1", "regex": ["c"]}, {"id": "M1", "regex": ["d"]}]\n'
    repo, base, head = _repo(tmp_path, LINEAR, LINEAR, head_mech=dup)
    r = _cli(repo, "--base", base, "--head", head)
    assert r.returncode == 1 and "more than once" in r.stderr


# ---------------------------------------------------------------- r2: public prose

def test_the_waiver_reasons_carry_no_branch_name_workload_or_speed_claim():
    waivers = g.read_waivers((ROOT / g.WAIVERS).read_text(encoding="utf-8"))
    bad = {k: v for k, v in waivers.items()
           if re.search(r"\bmain\b|\d+\s*(?:k|kb|ms|s|seconds?)\b|\bunder a second\b|\bshape\b", v, re.I)}
    assert bad == {}


# ---------------------------------------------------------------- r3: deadline, confirmation, waivers

def test_a_budget_spent_while_the_tables_were_read_fails_even_if_each_read_finished(monkeypatch):
    clock = _Clock()

    def slow_read(source, path, table):
        clock.t += 100.0
        return [("A" + table, ("x",))]
    monkeypatch.setattr(g, "_read_table", slow_read)
    with pytest.raises(g.GateError, match="wall budget was spent"):
        g.rules_from_sources({"sunglasses/patterns.py": "", "sunglasses/mechanisms.py": ""},
                             g.Budget(150, clock=clock, started=0.0))


def test_an_empty_worklist_after_the_budget_is_spent_is_not_a_pass():
    rules = {"R": (LINEAR,)}
    rows, failures, _ = run(rules, rules, wall_cap=150, clock=lambda: 200.0, started=0.0)
    assert rows == [] and any("wall cap was reached before the run finished" in f for f in failures)


def test_an_empty_worklist_inside_the_budget_still_passes():
    rules = {"R": (LINEAR,)}
    rows, failures, _ = run(rules, rules, wall_cap=150, clock=lambda: 10.0, started=0.0)
    assert rows == [] and failures == []


def test_a_capped_confirmation_is_a_cap_not_the_earlier_sample(monkeypatch):
    fake, calls = _seq([0.9, None])
    monkeypatch.setattr(g, "time_once", fake)
    assert g.median_time([], "x", 3) is None
    assert len(calls) == 2


def test_a_capped_confirmation_fails_the_whole_gate(monkeypatch):
    monkeypatch.setattr(g, "pick_units", lambda regexes, keep, budget=None: ["read token "])
    state = {"n": 0}

    def fake(rxs, text, cap=g.RUN_CAP_S):
        state["n"] += 1
        return 0.9 if state["n"] % 2 else None      # every long first sample is followed by a capped one
    monkeypatch.setattr(g, "time_once", fake)
    rows, failures, _ = run({"R": (LINEAR,)}, {"R": (r"read\s+tokens?",)})
    assert failures and any("run cap" in f for f in failures)
    assert all(r["verdict"] != "ok" for r in rows)


def test_a_waived_id_whose_unchanged_expression_still_trips_is_not_stale_after_a_harmless_sibling_edit():
    waiver = {"R": "2026-10-24 the engine bounds this window"}
    rows, failures, _ = run({"R": (QUADRATIC, LINEAR)}, {"R": (QUADRATIC, r"read\s+tokens?")},
                            waivers_base=waiver, waivers_head=waiver)
    assert failures == []
    assert {r["case"][:2] for r in rows} == {"r0", "r1"}          # the whole id was timed, not the edit
    assert any(r["verdict"] == "WAIVED" for r in rows)


def test_a_waived_id_whose_every_expression_is_now_linear_is_still_stale():
    waiver = {"R": "2026-10-24 old"}
    _, failures, _ = run({"R": (QUADRATIC, LINEAR)}, {"R": (LINEAR, r"read\s+tokens?")},
                         waivers_base=waiver, waivers_head=waiver, growth_floor=1, ratio_floor=1)
    assert any("no longer trips" in f for f in failures)


def test_a_changed_id_without_a_waiver_is_still_timed_on_the_changed_expression_only():
    rows, _, _ = run({"R": (QUADRATIC, LINEAR)}, {"R": (QUADRATIC, r"read\s+tokens?")})
    assert {r["case"][:2] for r in rows} == {"r1"}


@pytest.mark.parametrize("mode", ["pull_request", "all"])
def test_main_hands_one_budget_to_the_reader_and_the_gate(tmp_path, monkeypatch, mode):
    repo, base, head = _repo(tmp_path, LINEAR, QUADRATIC)
    seen = {"read": [], "gate": []}
    real_read = g.rules_from_sources
    monkeypatch.setattr(g, "rules_from_sources",
                        lambda src, budget=None: (seen["read"].append(budget), real_read(src, budget))[1])
    monkeypatch.setattr(g, "gate", lambda *a, **k: (seen["gate"].append(k.get("budget")), ([], [], []))[1])
    before = time.monotonic()
    args = ["--repo", str(repo), "--wall-cap", "100"]
    args += ["--all"] if mode == "all" else ["--base", base, "--head", head]
    assert g.main(args) == 0
    (gate_budget,) = seen["gate"]
    assert isinstance(gate_budget, g.Budget) and seen["read"] and all(b is gate_budget for b in seen["read"])
    assert before <= gate_budget.started <= time.monotonic() and gate_budget.cap == 100


# ---------------------------------------------------------------- r2: head against base

def _by_pattern(monkeypatch, per_char_ms):
    """time_once that answers from the regex's pattern: linear in the text, with the slope given."""
    def fake(rxs, text, cap=g.RUN_CAP_S):
        return sum(per_char_ms[rx.pattern] for rx in rxs) * len(text) / 1e6
    monkeypatch.setattr(g, "time_once", fake)


def test_a_linear_but_much_slower_head_regex_fails_on_the_ratio_alone(monkeypatch):
    _by_pattern(monkeypatch, {"aaa": 1.0, "bbb": 3.0})
    rows, failures, _ = run({"R": ("aaa",)}, {"R": ("bbb",)})
    assert failures and all("head/base jump" in f and "growth" not in f for f in failures)
    assert all(r["base"] is not None for r in rows)


def test_a_slightly_slower_linear_head_regex_passes(monkeypatch):
    _by_pattern(monkeypatch, {"aaa": 1.0, "bbb": 1.5})
    rows, failures, _ = run({"R": ("aaa",)}, {"R": ("bbb",)})
    assert failures == [] and rows


def test_a_changed_second_regex_is_compared_with_the_base_second_regex(monkeypatch):
    _by_pattern(monkeypatch, {"aaa": 1.0, "bbb": 3.0, "ccc": 1.0})
    rows, failures, _ = run({"R": ("aaa", "ccc")}, {"R": ("aaa", "bbb")})
    assert {r["case"].split("/")[0] for r in rows} == {"r1"}
    assert failures and all(f.startswith("R r1/") for f in failures)
