"""Row 24. The three residuals ASTRA found in rows12-13-r7 (3b85090930fa), closed as one class.

r7 found text on the page that no check binds: a reason code that was a sentence (route rows,
unavailable coverage, the run summary), free prose under the ceiling, and a finish time that was
any string. Cases 4 and 5 (route name, run identity) were the same hole, uncounted.

The class is fixed, not the fields. Every text field the page reads declares exactly one kind in
`schema.REPORT_READS`: a code in a named table, an identifier with a pattern, a parsed timestamp, a
digest, or a value derived from the rest of the report. The typed view refuses a text field that
declares none and any value outside its kind. The ceiling prose is gone, a code stands in for it.

Cases 0 to 6 are ASTRA's own (r7_semantic.py), carried here as tests. Each test was written first
and run against a648c86f, where the ones that name the defect are RED.
"""
import copy
import pathlib
import sys
from html.parser import HTMLParser

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import produce                                              # noqa: E402,F401
import render                                               # noqa: E402
import schema                                               # noqa: E402
import validate                                             # noqa: E402
from test_execution_run import (                            # noqa: E402,F401
    codes, corpus_digest, norun, planned, run_doc, world)
from test_hardening_row17 import path_text, with_value      # noqa: E402

CLAIM = "The examiner confirmed every one of these variants against the product."


class Counter(HTMLParser):
    def __init__(self):
        super().__init__()
        self.count = 0

    def handle_data(self, data):
        self.count += data.count(CLAIM)


def separate(page):
    counter = Counter()
    counter.feed(page)
    return counter.count


def kinds_of(table, node, prefix=()):
    """(path, kind) for every declared leaf kind the report holds, down through lists and maps."""
    for key, kind in table.items():
        if not isinstance(node, dict) or key not in node or kind == schema.REFUSED_FIELD:
            continue
        yield from walk_kind(kind, node[key], prefix + (key,))


def walk_kind(kind, value, path):
    if isinstance(kind, tuple) and kind[0] in ("opt", "nul"):
        if value is None:
            return
        yield from walk_kind(kind[1], value, path)
    elif isinstance(kind, tuple) and kind[0] == "list":
        for index, item in enumerate(value or []):
            yield from walk_kind(kind[1], item, path + (index,))
    elif isinstance(kind, tuple) and kind[0] == "map":
        for key, item in (value or {}).items():
            yield from walk_kind(kind[1], item, path + (key,))
    elif isinstance(kind, dict):
        yield from kinds_of(kind, value, path)
    elif isinstance(kind, schema.Kind):
        yield path, kind


def leaves(report):
    return list(kinds_of(schema.REPORT_READS, report))


def where(path):
    return path_text(path) if path else ""


def findings_under(report, path):
    prefix = where(path)
    return [f for f in validate.validate_report(report)
            if f.code == "REPORT_FIELD_TYPE" and (
                f.path == prefix or f.path.startswith((prefix + ".", prefix + "[")))]


# ------------------------------------------------------------------ the table declares every text field
def table_text_leaves(kind, path=()):
    """Every leaf of the table that is bare text, with no kind. There must be none."""
    if kind == schema.TEXT:
        yield path
    elif isinstance(kind, tuple) and kind[0] in ("opt", "nul", "list"):
        yield from table_text_leaves(kind[1], path)
    elif isinstance(kind, tuple) and kind[0] == "map":
        yield from table_text_leaves(kind[1], path + ("*",))
    elif isinstance(kind, dict):
        for key, sub in kind.items():
            yield from table_text_leaves(sub, path + (key,))


def test_no_text_field_of_the_table_is_left_without_a_kind():
    assert list(table_text_leaves(schema.REPORT_READS)) == []


def test_every_declared_kind_is_one_of_the_five_and_names_itself():
    seen = set()
    for path, kind in leaves(_sample()):
        assert kind.how in {"code", "ident", "when", "digest", "derived"}, (path, kind.how)
        assert kind.name
        seen.add(kind.how)
    assert {"code", "ident", "when", "digest", "derived"} <= seen


def test_a_derived_field_names_the_check_that_derives_it():
    derived = [kind for _, kind in leaves(_sample()) if kind.how == "derived"]
    assert derived and all(kind.bound_by for kind in derived)


_SAMPLE = {}


def _sample():
    return _SAMPLE["world"]


@pytest.fixture(autouse=True)
def _remember(world):
    _SAMPLE["world"] = world.report


def test_the_typed_view_refuses_a_text_field_that_declares_no_kind(world, monkeypatch):
    table = copy.deepcopy(schema.REPORT_READS)
    table["run"]["bare"] = schema.TEXT
    monkeypatch.setattr(schema, "REPORT_READS", table)
    report = copy.deepcopy(world.report)
    report["run"]["bare"] = "anything"
    problems = schema.render_view(report)[1]
    assert any(p == "run.bare" and "no kind" in why for p, why in problems)


# ---------------------------------------------------------------------- r7 cases 0 to 6, as findings
def case_report(norun, index):
    r = copy.deepcopy(norun.report)
    if index == 0:
        node = r["coverage"]["ceiling"]["unclassified"]
        node[next(iter(node))] = CLAIM
    elif index == 1:
        r["routes"][0]["rows"]["reason_code"] = CLAIM
    elif index == 2:
        r["run"]["reason_code"] = CLAIM
    elif index == 3:
        r["coverage"]["state"] = "unavailable"
        r["coverage"]["reason_code"] = CLAIM
    elif index == 4:
        r["routes"][0]["name"] = CLAIM
    elif index == 5:
        r["run"]["id"] = CLAIM
    elif index == 6:
        r["run"]["finished_at"] = CLAIM
    return r


CASE_PATHS = {0: "coverage.ceiling.unclassified", 1: "routes[0].rows.reason_code",
              2: "run.reason_code", 3: "coverage.reason_code", 4: "routes[0].name",
              5: "run.id", 6: "run.finished_at"}


@pytest.mark.parametrize("index", range(7))
def test_each_r7_case_is_a_finding_at_its_field(norun, index):
    report = case_report(norun, index)
    found = validate.validate_report(report)
    hits = [f for f in found if f.code == "REPORT_FIELD_TYPE"
            and f.path.startswith(CASE_PATHS[index])]
    assert hits, (index, [(f.code, f.path) for f in found])


@pytest.mark.parametrize("index", range(7))
def test_each_r7_case_is_not_drawn_even_by_the_renderer_alone(norun, index):
    report = case_report(norun, index)
    with pytest.raises(render.WillNotRender):
        render.render(report, findings=[])
    with pytest.raises(render.WillNotRender):
        render.render(report)


def test_the_honest_control_has_no_finding_and_no_separate_assertion(norun, world):
    for built in (norun, world):
        assert validate.validate_report(built.report) == []
        page = render.render(built.report)
        assert validate.check_transcription(page, built.report) == []
        assert separate(page) == 0


# ------------------------------------------------------------- every kind, every field, a hostile value
def test_every_declared_field_refuses_a_sentence_in_its_place(world, norun):
    swept = 0
    for built in (world, norun):
        for path, kind in leaves(built.report):
            mutated = with_value(built.report, path, CLAIM)
            if kind.how == "derived":
                assert validate.validate_report(mutated), (where(path), kind.name)
                continue
            assert findings_under(mutated, path), (where(path), kind.name)
            with pytest.raises(render.WillNotRender):
                render.render(mutated, findings=[])
            swept += 1
    assert swept >= 40


def test_every_declared_field_refuses_the_wrong_member_of_its_own_family(world):
    """Not only a sentence: a code that is a real code of another table is still outside its kind."""
    swept = 0
    for path, kind in leaves(world.report):
        if kind.how != "code":
            continue
        other = "not_a_member_of_any_table"
        mutated = with_value(world.report, path, other)
        assert findings_under(mutated, path), (where(path), kind.name)
        swept += 1
    assert swept >= 10


def test_a_reason_code_is_checked_against_the_one_reason_table(world):
    for path, kind in leaves(world.report):
        if kind.name == "REASON_CODES":
            assert kind.fits("EVIDENCE_UNBOUND")
            assert not kind.fits("evidence_unbound") and not kind.fits("EVIDENCE_UNBOUND ")


def test_an_identifier_takes_no_space_newline_or_markup():
    kind = schema.ROUTE_NAME
    assert kind.fits("proxy_strict")
    for bad in ("two words", "proxy_strict\n", "<b>x</b>", "", "x" * 200, CLAIM):
        assert not kind.fits(bad), bad


def test_a_timestamp_is_parsed_not_matched():
    assert schema.WHEN.fits("2026-10-06T00:39:23-07:00")
    assert schema.WHEN.fits("2026-10-06T07:39:23.298949+00:00")
    for bad in ("", "yesterday", CLAIM, "2026-10-06T00:39:23 and a sentence", "2026-13-40T00:00:00"):
        assert not schema.WHEN.fits(bad), bad


def test_a_digest_is_hex_of_the_right_length():
    assert schema.DIGEST64.fits("a" * 64) and schema.GIT_HEAD.fits("b" * 40)
    for bad in ("a" * 63, "A" * 64, "g" * 64, "a" * 64 + "\n", CLAIM):
        assert not schema.DIGEST64.fits(bad), bad
    assert not schema.GIT_HEAD.fits("c" * 41)


def test_a_map_key_has_a_kind_too(world):
    report = copy.deepcopy(world.report)
    node = report["coverage"]["ceiling"]["unclassified"]
    node[CLAIM] = node.pop(next(iter(node)))
    assert findings_under(report, ("coverage", "ceiling", "unclassified"))
    with pytest.raises(render.WillNotRender):
        render.render(report, findings=[])
    report = copy.deepcopy(world.report)
    counts = report["routes"][0]["execution"]["counts"]
    counts[CLAIM] = 1
    assert findings_under(report, ("routes", 0, "execution", "counts"))


# ------------------------------------------------------------------------ the ceiling prose is gone
def test_the_producer_writes_a_code_under_every_unclassified_op(norun):
    listed = norun.report["coverage"]["ceiling"]["unclassified"]
    assert listed and set(listed.values()) <= set(schema.OP_REASON_CODES)
    assert all(schema.REASON_CODES[code] for code in listed.values())


def test_the_page_shows_the_fixed_text_for_the_ceiling_code_and_no_report_prose(norun):
    page = render.render(norun.report)
    for op, code in norun.report["coverage"]["ceiling"]["unclassified"].items():
        assert render._text(schema.REASON_CODES[code]) in page
        assert f"<code>{render._text(op)}</code>" in page


def test_ceiling_prose_in_place_of_a_code_is_refused(norun):
    report = copy.deepcopy(norun.report)
    node = report["coverage"]["ceiling"]["unclassified"]
    node[next(iter(node))] = "fault dispatch machinery exists at proxy/fault_dispatch.py"
    assert findings_under(report, ("coverage", "ceiling", "unclassified"))


def test_every_unclassified_op_key_the_map_can_produce_has_the_identifier_form():
    import classify
    capmap = classify.load_map()
    ops = set(capmap["classified"]) | set(capmap["unclassified"])
    assert ops and all(schema.OP_KEY.fits(op) for op in ops), sorted(
        op for op in ops if not schema.OP_KEY.fits(op))


# -------------------------------------------------------------------------------- derived fields
def test_the_two_derived_fields_still_have_their_own_finding(world):
    report = copy.deepcopy(world.report)
    report["routes"][0]["execution"]["fit_scope"] = CLAIM
    assert "STANDIN_SCOPE_MISSING" in codes(validate.validate_report(report))
    report = copy.deepcopy(world.report)
    report["ledger"]["lines"][0]["text"] = CLAIM
    assert validate.validate_report(report)


# --------------------------------------------------------------------------------- the one parse rule
def test_validate_and_schema_share_the_one_timestamp_parse():
    for value in ("2026-10-06T00:39:23-07:00", "2026-10-06T00:39:23", "x", ""):
        assert (validate._when(value) is None) == (schema.parse_when(value) is None)
    assert schema.parse_when("2026-10-06T00:39:23").tzinfo is not None


# ----------------------------------------------------------------------------- what the row keeps, held
def test_the_encoders_and_equality_are_still_what_they_were(world):
    assert render._text("<&\"'>") == "&lt;&amp;&quot;&#x27;&gt;"
    page = render.render(world.report)
    assert validate.check_transcription(page, world.report) == []
    assert validate.check_transcription(page + " ", world.report)


def test_detail_is_still_refused(norun):
    report = copy.deepcopy(norun.report)
    report["harness"]["detail"] = CLAIM
    assert findings_under(report, ("harness", "detail"))
