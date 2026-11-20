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
