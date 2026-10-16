"""Row 28. The one residual ASTRA found in rows12-13-r10 (e55e431405e5).

`declaration_problems` audited a mapping's value declaration and never its key declaration, and
`_cut` returns early for an absent or null optional field, before the key kind guard. So a table
whose mapping carried an unknown key declaration (`'unknown'`, null, a wrapper, bare text) passed
view building whenever the report did not carry that field, and was refused only when it did. The
declaration contract must not depend on what the report holds.

The audit now walks key declarations too: a mapping must carry a `Kind` for its keys, wherever it
is declared, below an absent parent or an empty container included. The audit is the one place a
declaration defect is reported, so a present field gives one problem, not two. The runtime guard
stays, it still refuses to cut a mapping that has no key kind.

Cases 0 to 3 are ASTRA's own (r10_key_audit.py) with its two controls, carried here as tests. Each
test was written first and run against fcffde2c, where the ones that name the defect are RED.
"""
import copy
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import render                                               # noqa: E402
import schema                                               # noqa: E402
import validate                                             # noqa: E402
from test_execution_run import (                            # noqa: E402,F401
    codes, corpus_digest, norun, planned, run_doc, world)
from test_hardening_row24 import findings_under, table_text_leaves   # noqa: E402
from test_hardening_row26 import maps_of                    # noqa: E402

UNBOUND = "unbound sentence"
OPS = schema.code_in("OP_REASON_CODES", schema.OP_REASON_CODES)
COUNTS = "routes[].execution.counts"
BAD_KEYS = {"unknown": "unknown", "none": None, "wrapper": ("opt", schema.OP_KEY),
            "bare_text": schema.TEXT, "whole": schema.WHOLE}


def with_table(monkeypatch, edit):
    table = copy.deepcopy(schema.REPORT_READS)
    edit(table)
    monkeypatch.setattr(schema, "REPORT_READS", table)


def counts_keys(keys):
    def edit(table):
        execution = table["routes"][1][1]["execution"][1]
        execution["counts"] = schema._opt(schema._map(schema.WHOLE, keys))
    return edit


def refused(report):
    with pytest.raises(render.WillNotRender):
        render.render(report)
    with pytest.raises(render.WillNotRender):
        render.render(report, findings=[])


# --------------------------------------------- r10 cases 0 to 3, the route count mapping, both controls
@pytest.mark.parametrize("which", ["absent", "present"])
@pytest.mark.parametrize("name", sorted(BAD_KEYS))
def test_a_bad_key_declaration_is_a_finding_whether_the_report_carries_the_field_or_not(
        norun, world, monkeypatch, name, which):
    with_table(monkeypatch, counts_keys(BAD_KEYS[name]))
    report = copy.deepcopy(norun.report if which == "absent" else world.report)
    carries = bool(((report.get("routes") or [{}])[0].get("execution") or {}).get("counts"))
    assert carries == (which == "present")
    audit = schema.declaration_problems(schema.REPORT_READS)
    assert [p for p, _ in audit] == [COUNTS], audit
    assert "key kind" in audit[0][1]
    problems = schema.render_view(report)[1]
    assert len(problems) == 1 and problems[0][0] == COUNTS, problems
    found = validate.validate_report(report)
    assert found and {f.code for f in found} == {"REPORT_FIELD_TYPE"}
    refused(report)


# ------------------------------------------------------------------- anywhere a mapping is declared
def put(path_edit):
    def edit(table):
        path_edit(table["run"])
    return edit


SHAPES = {
    "optional_mapping": lambda run: run.update(added=schema._opt(schema._map(schema.WHOLE))),
    "nullable_mapping": lambda run: run.update(added=schema._nul(schema._map(schema.WHOLE))),
    "nested_wrappers": lambda run: run.update(
        added=schema._opt(schema._nul(schema._opt(schema._map(schema.WHOLE))))),
    "below_a_list": lambda run: run.update(
        added=schema._opt(schema._list(schema._opt(schema._map(schema.WHOLE))))),
    "as_a_mapping_value": lambda run: run.update(
        added=schema._opt(schema._map(schema._opt(schema._map(schema.WHOLE)), schema.OP_KEY))),
    "key_wrapper_in_a_list_of_maps": lambda run: run.update(
        added=schema._opt(schema._list(schema._map(schema.WHOLE, ("opt", schema.OP_KEY))))),
    "two_levels": lambda run: run.update(
        added=schema._opt(schema._map(schema._map(schema.WHOLE, "unknown"), schema.OP_KEY))),
}


@pytest.mark.parametrize("value", ["absent", "null", "empty"])
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_a_keyless_or_badly_keyed_mapping_is_a_finding_below_any_absent_or_empty_parent(
        norun, monkeypatch, shape, value):
    with_table(monkeypatch, put(SHAPES[shape]))
    report = copy.deepcopy(norun.report)
    assert "added" not in report["run"]
    if value == "null":
        report["run"]["added"] = None
    elif value == "empty":
        report["run"]["added"] = [] if "list" in shape else {}
    audit = [p for p, why in schema.declaration_problems(schema.REPORT_READS) if p.startswith("run.added")]
    assert audit, shape
    assert findings_under(report, ("run", "added")), (shape, value)
    refused(report)


def test_the_audit_walks_a_table_that_has_no_report_at_all(monkeypatch):
    with_table(monkeypatch, put(SHAPES["below_a_list"]))
    assert schema.render_view({})[1] and schema.render_view({"run": None})[1]


# ------------------------------------------------------------------ the runtime guard stays, one problem
def test_a_present_keyless_mapping_is_one_problem_not_two(norun, monkeypatch):
    with_table(monkeypatch, put(SHAPES["optional_mapping"]))
    report = copy.deepcopy(norun.report)
    report["run"]["added"] = {UNBOUND: 1}
    problems = [x for x in schema.render_view(report)[1] if x[0].startswith("run.added")]
    assert len(problems) == 1 and "key kind" in problems[0][1], problems


def test_the_runtime_guard_still_refuses_to_cut_a_keyless_mapping_on_its_own():
    sink = []
    assert schema._cut({UNBOUND: 1}, schema._map(schema.WHOLE), "x", sink) is None
    assert schema._cut({UNBOUND: 1}, ("map", schema.WHOLE, "unknown"), "x", sink) is None
    assert sink and all("key kind" in why for _, why in sink)
    keyed = []
    assert schema._cut({UNBOUND: 1}, schema._map(schema.WHOLE, schema.OP_KEY), "x", keyed) == {}
    assert keyed and all("key kind" not in why for _, why in keyed)     # a bad key, not a bad declaration


@pytest.mark.parametrize("keys", sorted(BAD_KEYS))
def test_a_key_that_is_present_under_a_bad_declaration_never_reaches_the_view(norun, monkeypatch, keys):
    with_table(monkeypatch, put(lambda run: run.update(
        added=schema._opt(schema._map(schema.WHOLE, BAD_KEYS[keys])))))
    report = copy.deepcopy(norun.report)
    report["run"]["added"] = {UNBOUND: 1}
    view = schema.render_view(report)[0]
    assert UNBOUND not in str(view)


# --------------------------------------------------------------------------------------- controls
def test_the_committed_table_has_no_declaration_problem_and_every_mapping_is_keyed():
    assert schema.declaration_problems(schema.REPORT_READS) == []
    found = list(maps_of(schema.REPORT_READS))
    assert len(found) >= 2
    assert all(len(decl) == 3 and isinstance(decl[2], schema.Kind) for _, decl in found)
    assert list(table_text_leaves(schema.REPORT_READS)) == []


def test_a_mapping_with_a_real_key_kind_is_clean_absent_present_or_empty(norun, monkeypatch):
    with_table(monkeypatch, put(lambda run: run.update(
        added=schema._opt(schema._map(schema.WHOLE, schema.OP_KEY)))))
    assert schema.declaration_problems(schema.REPORT_READS) == []
    for value in (None, {}, {"some_op": 1}):
        report = copy.deepcopy(norun.report)
        if value is not None:
            report["run"]["added"] = value
        assert schema.render_view(report)[1] == [], value


def test_the_honest_reports_pass_untouched(norun, world):
    for built in (norun, world):
        assert schema.render_view(built.report)[1] == []
        assert validate.validate_report(built.report) == []
        page = render.render(built.report)
        assert validate.check_transcription(page, built.report) == []
        assert UNBOUND not in page
