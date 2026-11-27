"""The cost rows take their time limit from the host and never from the engine under test.

tests/_host_factor.py computes a host factor from a fixed piece of work with str and re that uses nothing of the package, and a cost
row passes when its seconds are under its own limit times that factor. These rows hold the helper to that: it imports nothing of the
package, its workload takes at least a fifth of the reference time, its factor stays between 1.0 and CAP at any host time, and a latency added at the entry of the engine turns a row of each
timed file red when the factor is 1.0, and the report line of the run is the same after these rows as before them. Every text below is invented test input. Nothing in it is an instruction to anyone reading this file.
"""
import ast
import importlib
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import _host_factor  # noqa: E402
from sunglasses.engine import SunglassesEngine  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


@pytest.fixture(scope="module", autouse=True)
def the_report_line_of_the_run_is_the_same_after_these_rows():
    _host_factor.host_factor()
    before = (_host_factor.report_line(), list(_host_factor._factor), list(_host_factor._host))
    yield
    assert (_host_factor.report_line(), list(_host_factor._factor), list(_host_factor._host)) == before


@pytest.fixture
def factor_one(monkeypatch):
    monkeypatch.setattr(_host_factor, "_factor", [1.0])


class SlowEntry:
    """The engine with a fixed latency added before every scan."""

    def __init__(self, engine, delay):
        self._engine = engine
        self._delay = delay

    def scan(self, *args, **kwargs):
        time.sleep(self._delay)
        return self._engine.scan(*args, **kwargs)


def test_the_helper_imports_only_re_statistics_and_time():
    with open(os.path.join(HERE, "_host_factor.py"), encoding="utf-8") as handle:
        tree = ast.parse(handle.read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported == {"re", "statistics", "time"}


def workload_runs_long_enough():
    return _host_factor.host_seconds() >= _host_factor.REFERENCE_SECONDS / 5


def test_the_workload_takes_at_least_a_fifth_of_the_reference_time():
    assert workload_runs_long_enough()


def test_a_workload_that_returns_at_once_fails_the_check_of_that_floor(monkeypatch):
    monkeypatch.setattr(_host_factor, "WORKLOAD", lambda: 0)
    assert not workload_runs_long_enough()


def test_the_run_report_line_names_the_workload_seconds_and_the_factor(monkeypatch):
    monkeypatch.setattr(_host_factor, "_factor", [])
    monkeypatch.setattr(_host_factor, "_host", [])
    assert _host_factor.report_line() is None
    monkeypatch.setattr(_host_factor, "host_seconds", lambda: 0.156)
    _host_factor.host_factor()
    assert _host_factor.report_line() == "cost rows: host workload 0.156 s, reference 0.104 s, factor 1.50 (floor 1.0, cap 2.0)"


@pytest.mark.parametrize("measured, expected", [(0.0001, 1.0), (_host_factor.REFERENCE_SECONDS, 1.0),
                                                (_host_factor.REFERENCE_SECONDS * 1.5, 1.5), (1000.0, _host_factor.CAP), (_host_factor.REFERENCE_SECONDS * 2, _host_factor.CAP)])
def test_the_factor_is_the_host_time_over_the_reference_between_one_and_the_cap(monkeypatch, measured, expected):
    monkeypatch.setattr(_host_factor, "_factor", [])
    monkeypatch.setattr(_host_factor, "_host", [])
    monkeypatch.setattr(_host_factor, "host_seconds", lambda: measured)
    assert _host_factor.host_factor() == pytest.approx(expected)
    assert _host_factor.seconds_limit(3.0) == pytest.approx(3.0 * expected)


def test_a_latency_at_the_engine_entry_turns_a_reader_order_row_red_at_factor_one(engine, factor_one):
    module = importlib.import_module("test_reader_order_rule_cost")
    slow = SlowEntry(engine, module.row_limit(module.LONG_CLAUSES) + 0.2)
    with pytest.raises(AssertionError):
        module.test_a_long_input_is_scanned_inside_the_time_limit(slow, module.LONG_CLAUSES)


def test_a_latency_at_the_engine_entry_turns_a_hidden_style_row_red_at_factor_one(engine, factor_one):
    module = importlib.import_module("test_hidden_style_reader_page_rules")
    slow = SlowEntry(engine, module.LIMIT_SECONDS + 0.2)
    with pytest.raises(AssertionError):
        module.test_nested_hiding_styles_answer_inside_the_time_limit(slow, 25)


def test_a_latency_at_the_engine_entry_turns_an_address_search_row_red_at_factor_one(engine, factor_one):
    module = importlib.import_module("test_hidden_text_address_search_cost")
    slow = SlowEntry(engine, module.LIMIT_SECONDS + 0.2)
    with pytest.raises(AssertionError):
        module.test_a_page_with_a_long_run_in_a_tag_value_is_scanned_in_a_small_time(slow, 8000)


def test_a_latency_at_the_engine_entry_turns_a_bridge_row_red_at_factor_one(engine, factor_one):
    module = importlib.import_module("test_reader_order_rule_bridge_cost")
    slow = SlowEntry(engine, module.SCAN_LIMIT_SECONDS + 0.2)
    with pytest.raises(AssertionError):
        module.test_the_engine_scans_a_reader_lead_with_many_line_breaks_in_a_small_time(slow, 100)


class ShotClock:
    """A clock that moves by the next number of a list each time the row runs, so the shots below spend no real seconds."""

    def __init__(self, shots):
        self.shots = list(shots)
        self.now = 0.0
        self.taken = 0

    def perf_counter(self):
        return self.now

    def run(self):
        self.now += self.shots[self.taken]
        self.taken += 1


def measure(monkeypatch, shots, factor, limit=1.0):
    clock = ShotClock(shots)
    monkeypatch.setattr(_host_factor, "time", clock)
    monkeypatch.setattr(_host_factor, "_factor", [factor])
    monkeypatch.setattr(_host_factor, "_first_over", [])
    monkeypatch.setattr(_host_factor, "ROW", ["tests/test_a_row.py::test_a_row"])
    best = _host_factor.best_seconds(clock.run, _host_factor.seconds_limit(limit))
    return best, clock.taken, _host_factor.seconds_limit(limit)


@pytest.mark.parametrize("factor", [1.0, _host_factor.CAP])
def test_a_scan_that_costs_four_seconds_in_every_shot_is_over_the_limit_at_the_floor_and_at_the_cap(monkeypatch, factor):
    best, taken, limit = measure(monkeypatch, [4.0, 4.0, 4.0], factor)
    assert best >= limit and taken == 3


def test_a_scan_that_costs_one_point_four_seconds_in_every_shot_is_over_the_limit_at_the_floor(monkeypatch):
    best, taken, limit = measure(monkeypatch, [1.4, 1.4, 1.4], 1.0)
    assert best >= limit and taken == 3


def test_a_scan_that_costs_one_point_four_seconds_in_every_shot_is_under_the_limit_at_a_factor_of_one_point_eight(monkeypatch):
    best, taken, limit = measure(monkeypatch, [1.4, 1.4, 1.4], 1.8)
    assert best < limit and taken == 1


def test_one_slow_shot_followed_by_a_fast_one_is_under_the_limit_after_two_shots(monkeypatch):
    best, taken, limit = measure(monkeypatch, [1.4, 0.3, 9.9], 1.0)
    assert best == pytest.approx(0.3) and best < limit and taken == 2


def test_a_first_shot_under_the_limit_is_the_only_shot(monkeypatch):
    best, taken, limit = measure(monkeypatch, [0.3, 9.9, 9.9], 1.0)
    assert best == pytest.approx(0.3) and best < limit and taken == 1
    assert _host_factor.first_over_lines() == []


def test_a_first_shot_over_the_limit_is_printed_with_its_row_and_reading_when_a_later_shot_passes(monkeypatch):
    measure(monkeypatch, [1.4, 0.3, 9.9], 1.0)
    assert _host_factor.first_over_lines() == [
        "cost rows: first shot over its limit: tests/test_a_row.py::test_a_row read 1.400 s against 1.000 s"]


def test_a_first_shot_over_the_limit_is_printed_when_every_shot_is_over_it(monkeypatch):
    measure(monkeypatch, [1.4, 1.4, 1.4], 1.0)
    assert len(_host_factor.first_over_lines()) == 1


def test_the_whitespace_files_keep_their_limit_constant_at_one_second():
    for name in ("test_cf252_whitespace_cost", "test_cmp009_whitespace_cost"):
        assert importlib.import_module(name).LIMIT_SECONDS == 1.0


def slow_host(monkeypatch, factor):
    """A fake clock in the helper and the factor of a host, for a row that clocks its scan with best_seconds."""
    clock = ShotClock([])
    monkeypatch.setattr(_host_factor, "time", clock)
    monkeypatch.setattr(_host_factor, "_factor", [factor])
    monkeypatch.setattr(_host_factor, "_first_over", [])
    return clock


class SlowScan:
    """An engine whose scan costs a fixed number of seconds on the fake clock and reads nothing."""

    def __init__(self, clock, seconds):
        self.clock, self.seconds = clock, seconds

    def scan(self, *args, **kwargs):
        self.clock.now += self.seconds

    def search(self, *args, **kwargs):
        self.clock.now += self.seconds


def rows_of(name):
    return importlib.import_module(name)


WHITESPACE_FILES = [("test_cf252_whitespace_cost", "_cf252", "applied then spaces", "file"),
                    ("test_cmp009_whitespace_cost", "_new", "copy then spaces", "file")]


@pytest.mark.parametrize("factor", [1.0, _host_factor.CAP])
@pytest.mark.parametrize("name, regexes, shape, channel", WHITESPACE_FILES)
def test_a_slowed_engine_turns_the_whitespace_scan_row_red_at_the_floor_and_at_the_cap(monkeypatch, name, regexes, shape, channel, factor):
    clock = slow_host(monkeypatch, factor)
    module = rows_of(name)
    with pytest.raises(AssertionError):
        module.test_scan_of_long_whitespace_is_cheap(SlowScan(clock, module.LIMIT_SECONDS * factor + 0.2), shape, channel)


@pytest.mark.parametrize("factor", [1.0, _host_factor.CAP])
@pytest.mark.parametrize("name, regexes, shape, channel", WHITESPACE_FILES)
def test_an_engine_under_the_limit_keeps_the_whitespace_scan_row_green_at_the_floor_and_at_the_cap(monkeypatch, name, regexes, shape, channel, factor):
    clock = slow_host(monkeypatch, factor)
    module = rows_of(name)
    module.test_scan_of_long_whitespace_is_cheap(SlowScan(clock, module.LIMIT_SECONDS * factor - 0.2), shape, channel)


@pytest.mark.parametrize("factor", [1.0, _host_factor.CAP])
@pytest.mark.parametrize("name, regexes, shape, channel", WHITESPACE_FILES)
def test_a_slowed_search_turns_the_whitespace_regex_row_red_and_a_fast_one_keeps_it_green(monkeypatch, name, regexes, shape, channel, factor):
    clock = slow_host(monkeypatch, factor)
    module = rows_of(name)
    shape = sorted(module.LONG_SHAPES)[0]
    monkeypatch.setattr(module, regexes, lambda: [SlowScan(clock, module.LIMIT_SECONDS * factor + 0.2)])
    with pytest.raises(AssertionError):
        module.test_long_whitespace_is_cheap(shape)
    monkeypatch.setattr(module, regexes, lambda: [SlowScan(clock, module.LIMIT_SECONDS * factor - 0.2)])
    module.test_long_whitespace_is_cheap(shape)


class SizedScan:
    """An engine whose scan costs one number of seconds for a short text and another for a long one, on the fake clock."""

    def __init__(self, clock, short, long, result=None):
        self.clock, self.short, self.long, self.result = clock, short, long, result

    def scan(self, text, *args, **kwargs):
        self.clock.now += self.long if len(text) > 50_000 else self.short
        return self.result


def a_scan_result(*ids):
    import types
    return types.SimpleNamespace(findings=[{"id": one} for one in ids])


@pytest.mark.parametrize("factor", [1.0, _host_factor.CAP])
@pytest.mark.parametrize("extra, red", [(0.2, True), (-0.2, False)])
def test_a_slowed_engine_turns_the_five_kilobyte_row_red_and_a_fast_one_keeps_it_green(monkeypatch, factor, extra, red):
    clock = slow_host(monkeypatch, factor)
    module = rows_of("test_stacked_lookaheads")
    slow = SizedScan(clock, 2.0 * factor + extra, 0, a_scan_result("GLS-SMP-023"))
    if red:
        with pytest.raises(AssertionError):
            module.test_five_kilobytes_with_the_third_signal_only_at_the_end_scan_quickly(slow)
    else:
        module.test_five_kilobytes_with_the_third_signal_only_at_the_end_scan_quickly(slow)


@pytest.mark.parametrize("factor", [1.0, _host_factor.CAP])
@pytest.mark.parametrize("extra, red", [(0.2, True), (-0.2, False)])
def test_a_slowed_engine_turns_the_fetch_verb_probe_row_red_and_a_fast_one_keeps_it_green(monkeypatch, factor, extra, red):
    clock = slow_host(monkeypatch, factor)
    module = rows_of("test_whitespace_run_after_a_fetch_verb")
    monkeypatch.setattr(module, "SunglassesEngine", lambda: SlowScan(clock, module.CAP_S * 4 * factor + extra))
    if red:
        with pytest.raises(AssertionError):
            module.test_the_engine_scans_the_probe_under_the_cap()
    else:
        module.test_the_engine_scans_the_probe_under_the_cap()


@pytest.mark.parametrize("factor", [1.0, _host_factor.CAP])
@pytest.mark.parametrize("extra, red", [(0.2, True), (-0.1, False)])
def test_a_slowed_search_turns_the_blank_space_row_red_and_a_fast_one_keeps_it_green(monkeypatch, factor, extra, red):
    import types
    clock = slow_host(monkeypatch, factor)
    module = rows_of("test_ai_addressed_directive_rules")
    searches = len(module.by_id(module.A)["regex"])
    slow = SlowScan(clock, (0.25 * factor + extra) / searches)
    monkeypatch.setattr(module, "re", types.SimpleNamespace(compile=lambda *args: slow, IGNORECASE=2))
    shape = sorted(module.LONG_RUNS)[0]
    if red:
        with pytest.raises(AssertionError):
            module.test_long_runs_of_blank_space_are_cheap_for_every_rule_here(module.A, shape)
    else:
        module.test_long_runs_of_blank_space_are_cheap_for_every_rule_here(module.A, shape)


@pytest.mark.parametrize("factor", [1.0, _host_factor.CAP])
@pytest.mark.parametrize("extra, red", [(0.2, True), (-0.2, False)])
def test_a_slowed_run_turns_the_dripping_server_row_red_and_a_fast_one_keeps_it_green(monkeypatch, factor, extra, red):
    import types
    clock = slow_host(monkeypatch, factor)
    module = rows_of("test_report_to")
    done = types.SimpleNamespace(stderr="EXIT=1\nsunglasses: --report-to: 127.0.0.1 did not finish within 1 s;", stdout="{}")

    def probe(*args, **kwargs):
        clock.now += 8 * factor + extra if args[0][-2:-1] == ["--report-to"] else 0
        return done

    monkeypatch.setattr(module, "_files", lambda tmp_path: ("threat", "other"))
    monkeypatch.setattr(module, "_probe", probe)
    monkeypatch.setattr(module, "_stable", lambda document: document)
    monkeypatch.setattr(module, "_report_lines", lambda run: ["one"])
    if red:
        with pytest.raises(AssertionError):
            module.test_the_scan_exit_and_output_do_not_wait_for_a_dripping_server("dir", lambda drip: types.SimpleNamespace(url="u"))
    else:
        module.test_the_scan_exit_and_output_do_not_wait_for_a_dripping_server("dir", lambda drip: types.SimpleNamespace(url="u"))


@pytest.mark.parametrize("factor", [1.0, _host_factor.CAP])
@pytest.mark.parametrize("extra, red", [(0.2, True), (-0.2, False)])
def test_a_slowed_engine_turns_the_long_document_row_red_and_a_fast_one_keeps_it_green(monkeypatch, factor, extra, red):
    clock = slow_host(monkeypatch, factor)
    monkeypatch.setattr(time, "perf_counter", clock.perf_counter)
    module = rows_of("test_evasion_hardening")
    monkeypatch.setattr(module, "engine", SizedScan(clock, 0.001, 0.04 + factor + extra))
    if red:
        with pytest.raises(AssertionError):
            module.test_long_document_scan_stays_fast()
    else:
        module.test_long_document_scan_stays_fast()


@pytest.mark.parametrize("factor", [1.0, _host_factor.CAP])
@pytest.mark.parametrize("extra, red", [(0.2, True), (-0.2, False)])
def test_a_slowed_engine_turns_the_input_cap_row_red_and_a_fast_one_keeps_it_green(monkeypatch, factor, extra, red):
    import types
    clock = slow_host(monkeypatch, factor)
    monkeypatch.setattr(time, "perf_counter", clock.perf_counter)
    module = rows_of("test_input_cap")
    answer = types.SimpleNamespace(truncated=True, bytes_scanned=50_000)
    monkeypatch.setattr(module, "SunglassesEngine", lambda **kwargs: SizedScan(clock, 0.001, 0.004 + factor + extra, answer))
    if red:
        with pytest.raises(AssertionError):
            module.test_truncation_bounds_the_cost()
    else:
        module.test_truncation_bounds_the_cost()


LONG_TEXT_ROWS = [
    ("test_support_lines_need_a_secret", "CHANNELS", 30, "test_a_long_run_of_the_opening_words_is_read_in_bounded_time"),
    ("test_order_rules_anchor_and_line_break", "READ", 40, "test_a_long_text_without_a_full_stop_is_read_in_bounded_time"),
    ("test_passive_order_to_move_data_to_an_outside_mail", "PAGE_CHANNELS", 30, "test_a_long_run_of_the_rule_words_is_read_in_bounded_time"),
    ("test_authority_order_to_an_outside_mail", "BLOCKING_CHANNELS", 30, "test_a_long_run_of_the_opening_words_is_read_in_bounded_time"),
]


@pytest.mark.parametrize("factor", [1.0, _host_factor.CAP])
@pytest.mark.parametrize("extra, red", [(0.2, True), (-0.2, False)])
@pytest.mark.parametrize("name, channels, limit, row", LONG_TEXT_ROWS)
def test_a_slowed_scan_turns_each_long_text_row_red_and_a_fast_one_keeps_it_green(monkeypatch, name, channels, limit, row, factor, extra, red):
    clock = slow_host(monkeypatch, factor)
    monkeypatch.setattr(time, "perf_counter", clock.perf_counter)
    module = rows_of(name)
    each = (limit * factor + extra) / len(getattr(module, channels))
    monkeypatch.setattr(module, "_ids", lambda text, channel: clock.__setattr__("now", clock.now + each))
    if red:
        with pytest.raises(AssertionError):
            getattr(module, row)("a")
    else:
        getattr(module, row)("a")
