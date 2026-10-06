"""Row 27. The one residual ASTRA found in rows12-13-r9 (2a97a604a6d5).

`_cut` unwrapped one optional or nullable layer. A second wrapper fell through to `_has_kind`,
whose last line read "anything else" as the opaque object declaration and accepted any dict, so a
mapping declared under two wrappers reached the typed view whole, keys and all, and neither the key
kind check nor the keyless mapping guard of row 26 ran. The same default accepted a declaration
the view did not recognise at all.

Two things are fixed. A wrapper is unwrapped to any depth, so the same checks run however a field
is wrapped. And a declaration the view does not recognise is a problem in the view, a schema defect
is a `REPORT_FIELD_TYPE` finding and a refusal and is never opaque. A thing is read as an opaque
object only when the table says OBJECT in so many words.

Cases 0 to 6 are ASTRA's own (r9_nested.py), carried here as tests. Each test was written first and
run against d114c573, where the ones that name the defect are RED.
"""
import copy
import pathlib
import sys
from html.parser import HTMLParser

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
from test_hardening_row26 import maps_of, rekey             # noqa: E402

UNBOUND = "unbound sentence"
CEILING = ("coverage", "ceiling", "unclassified")
OPS = schema.code_in("OP_REASON_CODES", schema.OP_REASON_CODES)


class Counter(HTMLParser):
    def __init__(self):
        super().__init__()
        self.count = 0

    def handle_data(self, data):
        self.count += data.count(UNBOUND)


def separate(page):
    counter = Counter()
    counter.feed(page)
    return counter.count


def with_table(monkeypatch, edit):
    table = copy.deepcopy(schema.REPORT_READS)
    edit(table)
    monkeypatch.setattr(schema, "REPORT_READS", table)


def set_ceiling(declaration):
    def edit(table):
        table["coverage"]["ceiling"][1]["unclassified"] = declaration
    return edit


def keyed():
    return schema._map(OPS, schema.OP_KEY)


def keyless():
    return schema._map(OPS)


# ASTRA's seven declarations around the ceiling mapping, indexed as in r9_nested.py. In r9 the
# first three wrap the committed (keyed) mapping, case 3 is the committed declaration, case 4 is
# one wrapper around a keyless mapping, cases 5 and 6 are two wrappers around a keyless mapping.
# Case 1 is `_nul` around the committed declaration as ASTRA wrote it, which is `_nul(_opt(map))`.
R9 = {
    0: lambda: schema._opt(schema._opt(keyed())),
    1: lambda: schema._nul(schema._opt(keyed())),
    2: lambda: schema._opt(schema._nul(schema._opt(keyed()))),
    3: lambda: schema._opt(keyed()),
    4: lambda: schema._opt(keyless()),
    5: lambda: schema._opt(schema._opt(keyless())),
    6: lambda: schema._opt(schema._nul(keyless())),
}
EXPECT_FINDING = range(7)


def r9_report(norun):
    return rekey(copy.deepcopy(norun.report))


@pytest.mark.parametrize("index", range(7))
def test_each_r9_case_is_a_finding_and_is_refused_and_the_key_never_reaches_the_view(
        norun, monkeypatch, index):
    with_table(monkeypatch, set_ceiling(R9[index]()))
    report = r9_report(norun)
    view, problems = schema.render_view(report)
    assert problems, index
    assert UNBOUND not in str(view), index
    found = validate.validate_report(report)
    assert found and {f.code for f in found} == {"REPORT_FIELD_TYPE"}, index
    with pytest.raises(render.WillNotRender):
        render.render(report)
    with pytest.raises(render.WillNotRender):
        render.render(report, findings=[])


@pytest.mark.parametrize("index", [0, 1, 2, 3])
def test_a_wrapped_keyed_mapping_still_reads_an_honest_report(norun, monkeypatch, index):
    with_table(monkeypatch, set_ceiling(R9[index]()))
    report = copy.deepcopy(norun.report)
    assert schema.render_view(report)[1] == []
    assert validate.validate_report(report) == []
    page = render.render(report)
    assert validate.check_transcription(page, report) == []
    assert separate(page) == 0


@pytest.mark.parametrize("index", [4, 5, 6])
def test_a_wrapped_keyless_mapping_is_a_finding_even_on_an_honest_report(norun, monkeypatch, index):
    with_table(monkeypatch, set_ceiling(R9[index]()))
    report = copy.deepcopy(norun.report)
    assert findings_under(report, CEILING)
    with pytest.raises(render.WillNotRender):
        render.render(report)


# ------------------------------------------------------------- any depth, and below a list or a map
@pytest.mark.parametrize("depth", [1, 2, 3, 5])
@pytest.mark.parametrize("wrap", ["opt", "nul"])
def test_a_mapping_under_any_number_of_wrappers_has_its_keys_checked(norun, monkeypatch, wrap, depth):
    declaration = keyed()
    for _ in range(depth):
        declaration = (wrap, declaration)
    with_table(monkeypatch, set_ceiling(declaration))
    report = r9_report(norun)
    assert UNBOUND not in str(schema.render_view(report)[0])
    assert findings_under(report, CEILING)


def test_a_mapping_under_wrappers_below_a_list_member_is_not_passed_through(norun, monkeypatch):
    with_table(monkeypatch, lambda t: t["run"].update(
        added=schema._opt(schema._list(schema._opt(schema._nul(keyless()))))))
    report = copy.deepcopy(norun.report)
    report["run"]["added"] = [{UNBOUND: "x"}]
    view, problems = schema.render_view(report)
    assert [p for p, _ in problems] == ["run.added[]"], problems       # the audit names the declaration (row 28)
    assert UNBOUND not in str(view)


def test_a_mapping_under_wrappers_as_a_mapping_value_is_not_passed_through(norun, monkeypatch):
    with_table(monkeypatch, lambda t: t["run"].update(
        added=schema._opt(schema._map(schema._opt(schema._opt(keyless())), schema.OP_KEY))))
    report = copy.deepcopy(norun.report)
    report["run"]["added"] = {"some_op": {UNBOUND: "x"}}
    view, problems = schema.render_view(report)
    assert [p for p, _ in problems] == ["run.added.*"] and "key kind" in problems[0][1], problems   # row 28
    assert UNBOUND not in str(view)


# ---------------------------------------------------- an unrecognised declaration is a schema defect
UNKNOWN = {
    "string": "somewhat",
    "none": None,
    "tuple_tag": ("wide", schema.WHOLE),
    "empty_tuple": (),
    "number": 7,
    "list_of_kinds": [schema.WHOLE],
    "short_wrapper": ("opt",),
}


@pytest.mark.parametrize("name", sorted(UNKNOWN))
def test_an_unrecognised_declaration_is_a_finding_and_is_refused(norun, monkeypatch, name):
    with_table(monkeypatch, lambda t: t["run"].update(added=UNKNOWN[name]))
    report = copy.deepcopy(norun.report)
    report["run"]["added"] = {UNBOUND: 1}
    view, problems = schema.render_view(report)
    assert any(p.startswith("run.added") and "does not recognise" in why for p, why in problems), problems
    assert "added" not in view["run"] and UNBOUND not in str(view)
    assert findings_under(report, ("run", "added"))
    with pytest.raises(render.WillNotRender):
        render.render(report)


@pytest.mark.parametrize("name", sorted(UNKNOWN))
def test_an_unrecognised_declaration_is_one_problem_not_a_second_reading_of_the_value(
        norun, monkeypatch, name):
    with_table(monkeypatch, lambda t: t["run"].update(added=UNKNOWN[name]))
    report = copy.deepcopy(norun.report)
    report["run"]["added"] = {UNBOUND: 1}
    problems = [(p, why) for p, why in schema.render_view(report)[1] if p.startswith("run.added")]
    assert len(problems) == 1 and "does not recognise" in problems[0][1], problems


@pytest.mark.parametrize("name", sorted(UNKNOWN))
def test_an_unrecognised_declaration_is_a_finding_whether_or_not_the_report_carries_the_field(
        norun, monkeypatch, name):
    with_table(monkeypatch, lambda t: t["run"].update(added=schema._opt(UNKNOWN[name])))
    report = copy.deepcopy(norun.report)
    assert "added" not in report["run"]
    assert findings_under(report, ("run", "added"))
    with pytest.raises(render.WillNotRender):
        render.render(report)


def test_an_unrecognised_declaration_under_wrappers_below_a_list_is_found(norun, monkeypatch):
    with_table(monkeypatch, lambda t: t["run"].update(
        added=schema._opt(schema._list(schema._opt(("wide", schema.WHOLE))))))
    assert findings_under(copy.deepcopy(norun.report), ("run", "added"))


def test_opaque_is_only_the_explicit_object_declaration(norun, monkeypatch):
    assert schema._has_kind({"k": 1}, schema.OBJECT) is True
    assert schema._has_kind(7, schema.OBJECT) is False
    for odd in ("somewhat", None, ("wide", schema.WHOLE), (), 7, [schema.WHOLE]):
        assert schema._has_kind({"k": 1}, odd) is False, odd
    with_table(monkeypatch, lambda t: t["run"].update(
        added=schema._opt(schema._nul(schema.OBJECT))))
    report = copy.deepcopy(norun.report)
    report["run"]["added"] = {UNBOUND: 1}
    assert schema.render_view(report)[1] == []             # a stated OBJECT is read for presence
    assert validate.validate_report(report) == []
    assert separate(render.render(report)) == 0            # and nothing of it is drawn


def test_the_committed_table_is_recognised_in_every_place():
    assert schema.declaration_problems(schema.REPORT_READS) == []
    assert list(table_text_leaves(schema.REPORT_READS)) == []
    assert all(len(decl) == 3 for _, decl in maps_of(schema.REPORT_READS))
    assert schema._has_kind({"x": 1}, schema._opt(schema.OBJECT)) is False   # a wrapper is never a leaf


# --------------------------------------------------------------------------------------- controls
def test_the_honest_reports_pass_and_the_page_holds_no_unbound_text(norun, world):
    for built in (norun, world):
        assert schema.render_view(built.report)[1] == []
        assert validate.validate_report(built.report) == []
        page = render.render(built.report)
        assert validate.check_transcription(page, built.report) == []
        assert separate(page) == 0


def test_the_committed_declaration_refuses_an_unbound_key(norun):
    report = r9_report(norun)
    assert findings_under(report, CEILING)
    with pytest.raises(render.WillNotRender):
        render.render(report)


def test_an_absent_optional_at_any_depth_is_not_a_finding(norun, monkeypatch):
    with_table(monkeypatch, lambda t: t["run"].update(
        added=schema._opt(schema._opt(schema._nul(schema.WHOLE)))))
    report = copy.deepcopy(norun.report)
    assert schema.render_view(report)[1] == []
    report["run"]["added"] = 3
    assert schema.render_view(report)[1] == []
    report["run"]["added"] = "three"
    assert schema.render_view(report)[1]
