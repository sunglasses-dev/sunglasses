"""scripts/pattern_perf_gate.py reads a rule's declared start key (`start_memo`) and times that entry the way the engine runs it.

The engine attempts such an entry only at the starts the rule names and not again on a line whose start already failed. A gate that
timed the plain `re.search` instead would charge the rule for work the engine never does. These tests use synthetic tables and
synthetic texts only; no shipped rule is named or read.

Each test names the change that turns it red:
  reader        a declaration the engine would not use is taken, or one it would use is missed
  walk          the timed search is not the engine's walk (it attempts a start the engine skips, or skips one it attempts)
  gate          an entry with a declared key is timed plain, or one without it is timed as declared
  key change    a dropped or added declaration is not judged
"""
import importlib.util
import pathlib
import random
import re
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("pattern_perf_gate_keys", ROOT / "scripts" / "pattern_perf_gate.py")
g = importlib.util.module_from_spec(spec)
sys.modules["pattern_perf_gate_keys"] = g
spec.loader.exec_module(g)

START = r"keep"
RULE = START + r".*out of (?:the )?summary"
PLAIN = r"do not mention"
TWO = r"(?:" + PLAIN + "|" + START + r".*out of summary)x"
SMALL = (1000, 2000, 4000)
SMALL_ADDED = (1000, 2000)


# ---------------------------------------------------------------- the reader

@pytest.mark.parametrize("declared,expect", [
    ({"memo": START}, (0, START, None)),
    ({"memo": START, "entry": 0}, (0, START, None)),
    ({"memo": START, "entry": 1}, (1, START, None)),
    ({"memo": START, "plain": None}, (0, START, None)),
    ({"memo": START, "plain": ""}, (0, START, None)),
])
def test_a_declaration_the_engine_uses_is_read(declared, expect):
    row = {"id": "R", "regex": [RULE, RULE if expect[0] else "zzz"], "start_memo": declared}
    assert g.declared_start(row, tuple(row["regex"])) == expect


def test_a_declaration_with_a_plain_part_is_read_with_it():
    row = {"id": "R", "regex": [TWO], "start_memo": {"memo": START, "plain": PLAIN}}
    assert g.declared_start(row, tuple(row["regex"])) == (0, START, PLAIN)


@pytest.mark.parametrize("declared", [
    None, "keep", ["keep"], 7,                          # not a dict
    {}, {"memo": ""}, {"memo": None}, {"memo": 5},      # no usable start
    {"memo": "absent from the entry"},                  # its part is not in the entry's source
    {"memo": START, "plain": "absent from the entry"},
    {"memo": START, "plain": 5},
    {"memo": START, "entry": 1}, {"memo": START, "entry": -1}, {"memo": START, "entry": True},
    {"memo": START, "entry": "0"}, {"memo": START, "entry": 1.0},
])
def test_a_declaration_the_engine_would_not_use_is_not_read(declared):
    row = {"id": "R", "regex": [RULE], "start_memo": declared}
    assert g.declared_start(row, (RULE,)) is None
    assert g.declared_start({"id": "R", "regex": [RULE]}, (RULE,)) is None


def _table(declared_line=""):
    return ("_S = r'keep'\n"
            "_R = _S + r'.*out of (?:the )?summary'\n"
            "PATTERNS = [\n"
            "  {'id': 'A', 'regex': [r'one', _R]" + declared_line + "},\n"
            "  {'id': 'B', 'regex': [r'two']},\n"
            "]\n")


def _sources(patterns):
    return {"sunglasses/patterns.py": patterns, "sunglasses/mechanisms.py": "MECHANISM_PATTERNS = [{'id': 'M', 'regex': ['m']}]\n"}


def test_the_reader_fills_the_declared_keys_and_leaves_the_rule_mapping_as_it_was():
    keys = {}
    with_key = g.rules_from_sources(_sources(_table(", 'start_memo': {'memo': _S, 'entry': 1}")), keys=keys)
    without = g.rules_from_sources(_sources(_table()))
    assert keys == {"A": (1, "keep", None)}
    assert with_key == without and with_key["A"] == ("one", RULE)


def test_a_declaration_in_a_table_that_names_nothing_the_engine_uses_is_not_a_key():
    keys = {}
    g.rules_from_sources(_sources(_table(", 'start_memo': {'memo': 'not in it', 'entry': 1}")), keys=keys)
    assert keys == {}


def test_the_reader_without_a_keys_dict_reads_as_before():
    assert g.rules_from_sources(_sources(_table(", 'start_memo': {'memo': _S, 'entry': 1}")))["A"] == ("one", RULE)


# ---------------------------------------------------------------- the walk

class _Counting:
    """The compiled rule inside a MemoSearch, counting the attempts made."""

    def __init__(self, rx):
        self.rx, self.at = rx, []

    def match(self, text, pos):
        self.at.append(pos)
        return self.rx.match(text, pos)


def _attempts(source, memo, plain, text):
    m = g.MemoSearch(source, memo, plain)
    m._rx = _Counting(m._rx)
    found = m.search(text)
    return found, m._rx.at


def test_a_failed_start_ends_its_gap_line_so_one_attempt_is_made_per_line():
    text = "keep x keep y\n" * 50
    found, at = _attempts(RULE, START, None, text)
    assert found is None and len(at) == 50
    assert at == [14 * i for i in range(50)]


def test_a_start_on_a_later_line_is_still_tried():
    found, at = _attempts(RULE, START, None, "keep x\nkeep y\nkeep out of summary")
    assert found is not None and found.group() == "keep out of summary" and len(at) == 3


def test_a_one_line_text_costs_one_attempt_however_many_starts_it_holds():
    found, at = _attempts(RULE, START, None, "keep " * 3000)
    assert found is None and at == [0]


def test_a_plain_start_is_always_tried_and_never_ends_a_line():
    text = ("do not mention keep y " * 4) + "\n"
    found, at = _attempts(TWO, START, PLAIN, text)
    assert found is None
    plain_places = [m.start() for m in re.finditer(PLAIN, text)]
    assert [p for p in at if p in plain_places] == plain_places           # every plain start was tried
    assert len([p for p in at if p not in plain_places]) == 1             # the memo start ended the line at its first failure


@pytest.mark.parametrize("source,memo,plain", [(RULE, START, None), (TWO, START, PLAIN)])
def test_the_walk_returns_what_the_plain_search_returns_for_a_rule_that_declares_its_key_rightly(source, memo, plain):
    rnd = random.Random(11)
    words = ["keep", "do not mention", "out of", "the", "summary", "x", "y", "\n", " ", "keep x", "out of summary"]
    rx, walk = re.compile(source, re.IGNORECASE), g.MemoSearch(source, memo, plain)
    for _ in range(400):
        text = "".join(rnd.choice(words) + rnd.choice(["", " ", "\n"]) for _ in range(rnd.randint(0, 14)))
        a, b = rx.search(text), walk.search(text)
        assert (a is None) == (b is None) and (a is None or a.span() == b.span()), text


def test_the_timed_object_carries_the_pattern_and_the_entry_search_falls_back_when_a_part_does_not_compile():
    m = g.entry_search(RULE, (0, START, None))
    assert isinstance(m, g.MemoSearch) and m.pattern == RULE
    assert not isinstance(g.entry_search(RULE, (0, "(", None)), g.MemoSearch)
    assert not isinstance(g.entry_search(RULE, None), g.MemoSearch)
    with pytest.raises(re.error):
        g.entry_search("(", (0, START, None))


# ---------------------------------------------------------------- the gate

def _fake_time(monkeypatch, record=None):
    """Seconds from what is timed."""
    def fake(rxs, text, cap=g.RUN_CAP_S):
        total = 0.0
        for rx in rxs:
            if record is not None:
                record.append(type(rx).__name__)
            total += 1e-9 * len(text) if isinstance(rx, g.MemoSearch) else 1e-9 * len(text) ** 2 / 100
        return total
    monkeypatch.setattr(g, "time_once", fake)


def _run(base, head, **kw):
    kw.setdefault("sizes", SMALL)
    kw.setdefault("added_sizes", SMALL_ADDED)
    kw.setdefault("repeats", 1)
    kw.setdefault("growth_floor", 0)
    kw.setdefault("ratio_floor", 0)
    return g.gate(base, head, {}, {}, **kw)


KEY = {"R": (0, START, None)}


def test_an_entry_with_a_declared_key_is_timed_as_the_engine_runs_it(monkeypatch):
    seen = []
    _fake_time(monkeypatch, seen)
    rows, failures, notes = _run({}, {"R": (RULE,)}, head_keys=KEY, probe_added_fully=True)
    assert failures == [] and rows and set(seen) == {"MemoSearch"}
    assert any("start key declared: head 1" in n for n in notes)


def test_the_same_entry_without_the_key_is_timed_plain_and_trips(monkeypatch):
    seen = []
    _fake_time(monkeypatch, seen)
    rows, failures, _ = _run({}, {"R": (RULE,)}, probe_added_fully=True)
    assert set(seen) == {"Pattern"} and failures and any("superlinear" in f for f in failures)


def test_a_key_that_names_another_entry_does_not_change_how_this_one_is_timed(monkeypatch):
    seen = []
    _fake_time(monkeypatch, seen)
    _run({}, {"R": (RULE, "zzz")}, head_keys={"R": (1, "zzz", None)}, probe_added_fully=True)
    assert "MemoSearch" in seen and "Pattern" in seen


def test_the_pre_pass_ranks_units_by_the_engine_walk_too(monkeypatch):
    called = []
    real = g.entry_search
    monkeypatch.setattr(g, "entry_search", lambda source, declared=None: (called.append(declared), real(source, declared))[1])
    g.pick_units([RULE], 2, declared=(0, START, None))
    assert called and all(c == (0, START, None) for c in called)


def test_a_dropped_declaration_is_judged_on_the_plain_search_it_leaves(monkeypatch):
    seen = []
    _fake_time(monkeypatch, seen)
    rows, failures, notes = _run({"R": (RULE,)}, {"R": (RULE,)}, base_keys=KEY)
    assert rows and "Pattern" in seen                       # the unchanged expression was timed because its key changed
    assert failures and any("superlinear" in f or "head/base jump" in f for f in failures)
    assert any("1 rule(s) differ" in n for n in notes)


def test_an_added_declaration_on_an_unchanged_rule_is_timed_and_passes(monkeypatch):
    seen = []
    _fake_time(monkeypatch, seen)
    rows, failures, _ = _run({"R": (RULE,)}, {"R": (RULE,)}, head_keys=KEY)
    assert rows and failures == [] and "MemoSearch" in seen


def test_an_unchanged_rule_with_an_unchanged_declaration_is_not_timed(monkeypatch):
    _fake_time(monkeypatch)
    rows, failures, notes = _run({"R": (RULE,)}, {"R": (RULE,)}, head_keys=KEY, base_keys=KEY)
    assert rows == [] and failures == []


def test_both_sides_of_a_changed_expression_use_their_own_declaration(monkeypatch):
    seen = []
    _fake_time(monkeypatch, seen)
    _run({"R": (RULE,)}, {"R": (RULE + " ",)}, head_keys=KEY, base_keys=KEY)
    assert set(seen) == {"MemoSearch"}


def test_a_rule_that_has_no_declaration_anywhere_is_gated_exactly_as_before(monkeypatch):
    _fake_time(monkeypatch)
    with_args = _run({"R": ("aaa",)}, {"R": ("bbb",)}, head_keys={}, base_keys={})
    without = _run({"R": ("aaa",)}, {"R": ("bbb",)})
    assert with_args[1] == without[1] and with_args[2] == without[2]


def test_a_real_engine_walk_is_cheaper_than_the_plain_search_on_a_text_with_many_starts():
    text = "keep " * 4000
    plain = re.compile(RULE, re.IGNORECASE)
    walk = g.MemoSearch(RULE, START)
    import time
    t0 = time.perf_counter(); plain.search(text); t_plain = time.perf_counter() - t0
    t0 = time.perf_counter(); walk.search(text); t_walk = time.perf_counter() - t0
    assert t_walk * 20 < t_plain


def test_a_dropped_declaration_is_also_compared_with_the_engine_walk_it_had(monkeypatch):
    def fake(rxs, text, cap=g.RUN_CAP_S):
        return sum((1e-9 if isinstance(rx, g.MemoSearch) else 4e-9) * len(text) for rx in rxs)
    monkeypatch.setattr(g, "time_once", fake)
    rows, failures, _ = _run({"R": (RULE,)}, {"R": (RULE,)}, base_keys=KEY)
    assert failures and all("head/base jump" in f and "superlinear" not in f for f in failures)
    assert all(r["base"] is not None for r in rows)
