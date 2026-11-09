"""The sentence that says what a run did names every outcome count and the total, or says nothing.

The page used to print only a passed count and a not run count over a partition that also held
failed, refused and errored counts. A reader saw numbers that looked like the whole result. These
rows use five DIFFERENT counts so a figure printed from the wrong field, a swapped pair or a
missing one cannot hide behind an equal neighbour.
"""
import pathlib
import re
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import render                                              # noqa: E402
import schema                                              # noqa: E402

PART = {"passed": 7, "failed": 11, "refused": 3, "errored": 2, "not_run": 51}
TOTAL = 74                                                 # 7 + 11 + 3 + 2 + 51
PATHS = {f"coverage.execution_partition.{k}": v for k, v in PART.items()}
PATHS["coverage.total"] = TOTAL
WITHHELD = "Execution counts did not reconcile to the delivered total; sentence withheld"


def _coverage(part=None, total=TOTAL):
    return {"state": "measured", "total": total, "plan_partition": {"drivable": 29},
            "execution_partition": dict(PART if part is None else part),
            "ceiling": {"state": "not_a_state"}}


def _page(coverage):
    return render._coverage_section({"coverage": coverage})


def _figures(page):
    return re.findall(r'data-bound="([^"]+)">([^<]*)<', page)


def test_the_fixture_counts_are_all_different_and_add_up():
    assert len(set(PART.values())) == 5 and sum(PART.values()) == TOTAL


def test_every_count_and_the_total_is_printed_from_its_own_field():
    page = _page(_coverage())
    shown = dict(_figures(page))
    for path, value in PATHS.items():
        assert shown.get(path) == str(value), path
    order = [page.index(f'data-bound="{p}"') for p in PATHS if p != "coverage.total"]
    assert order == sorted(order), "the five counts read passed, failed, refused, errored, not run"
    assert page.index('data-bound="coverage.execution_partition.not_run"') < page.rindex(
        'data-bound="coverage.total"')


def test_the_sentence_names_the_route_it_was_measured_on():
    assert "on a stand-in route and not on the product proxy" in _page(_coverage())


def test_the_old_two_count_sentence_is_gone():
    assert "Executed this run: " not in _page(_coverage())


@pytest.mark.parametrize("part,total", [
    (dict(PART, not_run=50), TOTAL),                       # one short
    (dict(PART, failed=12), TOTAL),                        # one over
    (PART, TOTAL + 1),                                     # denominator moved
    ({k: v for k, v in PART.items() if k != "errored"}, TOTAL),   # a count missing
    (dict(PART, refused="3"), TOTAL),                      # text, not a whole number
    (dict(PART, passed=True, failed=10), TOTAL),           # a bool is not a count
    ({}, TOTAL),
])
def test_counts_that_do_not_reconcile_withhold_the_sentence_and_print_no_figure(part, total):
    page = _page(_coverage(part, total))
    assert WITHHELD in page
    assert "data-bound=\"coverage.execution_partition" not in page
    assert "stand-in route" not in page


def test_the_withheld_text_is_exactly_the_ruled_words():
    assert render.EXECUTED_WITHHELD == WITHHELD


def test_the_schema_names_all_five_counts_so_the_page_may_read_them():
    declared = schema.REPORT_READS["coverage"]["execution_partition"][1]
    assert set(declared) == set(schema.PARTITION_KEYS)
    for key in ("failed", "refused", "errored"):
        assert ("execution_partition", key) in schema._READ_WHEN_NUMERIC
