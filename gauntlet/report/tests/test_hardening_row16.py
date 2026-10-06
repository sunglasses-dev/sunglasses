"""Row 16. The residuals ASTRA found in rows12-13-r3.

R6 The page is checked against the renderer's own markup, not against a reading of CSS. Bound
   elements, their ancestors and their descendants carry only attributes the renderer writes, and
   every style element is the renderer's stylesheet byte for byte.
R7 One table says what a driver record is. The driver writes through it, the producer and the
   validator read it, and 200 plus type swaps of a good record are findings with no exception.
V16 A report that says complete with nothing executed fails validation, whatever the ceiling.

Each test was written first and run against the row 15 head, where it is RED.
"""
import copy
import html as html_lib
import ast
import pathlib
import re
import sys
from html.parser import HTMLParser

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import classify                                             # noqa: E402
import drive                                                # noqa: E402
import produce                                              # noqa: E402
import render                                               # noqa: E402
import schema                                               # noqa: E402
import validate                                             # noqa: E402
from test_execution_run import (                            # noqa: E402,F401
    _build, codes, corpus_digest, norun, planned, run_doc, world)
from test_hardening_row14 import page, passed_span         # noqa: E402,F401
from test_hardening_row15 import (                          # noqa: E402,F401
    build_closed, closed_map, closed_norun, executed_total)


# ---------------------------------------------------------------------------------------- R6
def attr_findings(found):
    return [f for f in found if f.code == "BINDING_ATTRIBUTE_FORBIDDEN"]


def test_r6_the_css_reader_is_gone():
    assert not hasattr(validate, "HIDING_STYLE")


def test_r6_the_allowlist_is_named_in_schema_and_the_renderer_stays_inside_it(
        world, norun, closed_norun, page):
    allow = schema.RENDER_ATTRIBUTES
    assert {"data-bound", "id", "class"} <= set(allow)
    assert not {"style", "hidden", "aria-hidden"} & set(allow)

    class Seen(HTMLParser):
        def __init__(self):
            super().__init__(convert_charrefs=True)
            self.attrs = []

        def handle_starttag(self, tag, attrs):
            self.attrs += [(tag, k, v) for k, v in attrs]

    for report in (world.report, norun.report, closed_norun[0]):
        seen = Seen()
        seen.feed(render.render(report))
        for tag, key, value in seen.attrs:
            if tag in ("meta", "html"):
                continue
            assert key in allow, (tag, key)
            if allow[key] is not None:
                tokens = (value or "").split() if key == "class" else [value]
                assert set(tokens) <= set(allow[key]), (tag, key, value)


def test_r6_the_page_carries_the_renderers_stylesheet_byte_for_byte(page):
    sheets = re.findall(r"<style>(.*?)</style>", page, re.S)
    assert sheets == [schema.RENDER_STYLESHEET]


def test_r6_ordinary_pages_pass(world, norun, closed_norun, page):
    assert validate.check_transcription(page, world.report) == []
    assert validate.check_transcription(render.render(norun.report), norun.report) == []
    assert validate.check_transcription(render.render(closed_norun[0]), closed_norun[0]) == []


@pytest.mark.parametrize("edit", [
    lambda s: s + " ",
    lambda s: s + "\n.fig{display:none}",
    lambda s: s.replace("color:#fff", "color:#fff;", 1),
    lambda s: s.replace("#0a0a0a", "#0a0a0b", 1),
    lambda s: "",
    lambda s: s.replace("}", "}/* x */", 1),
])
def test_r6_a_style_element_that_is_not_the_renderers_is_refused(world, page, edit):
    changed = page.replace(schema.RENDER_STYLESHEET, edit(schema.RENDER_STYLESHEET), 1)
    assert changed != page
    assert "STYLESHEET_NOT_RENDERERS" in codes(validate.check_transcription(changed, world.report))


@pytest.mark.parametrize("extra", [
    "<style>.fig{display:none}</style>",
    "<style></style>",
    '<link rel="stylesheet" href="https://example.invalid/x.css">',
    '<link rel="stylesheet" href="x.css">',
])
def test_r6_a_second_style_element_or_a_linked_sheet_is_refused(world, page, extra):
    for place in ("<main>", "</main>"):
        changed = page.replace(place, extra + place, 1)
        assert "STYLESHEET_NOT_RENDERERS" in codes(
            validate.check_transcription(changed, world.report)), (place, extra)


ATTRIBUTES = [
    'style="display:none"', 'style="color:red"', 'style=""', "hidden", 'hidden="until-found"',
    'aria-hidden="true"', 'aria-hidden="false"', 'class="made-up"', 'class="fig extra"',
    'class=""', 'onclick="x()"', 'title="t"', 'data-x="1"', 'dir="rtl"', 'role="presentation"',
    'tabindex="0"', 'id="not-an-id"', 'inert', 'slot="a"', 'popover']


def with_attribute(page, report, where, attribute):
    """The page with `attribute` added to the bound element, to an ancestor, or to a descendant.
    It goes LAST in the opening tag, so a repeated name (id, class) is the one a parser keeps."""
    span = re.search(r'<span class="(?:fig|bound-text)" data-bound="[^"]+">[^<]*</span>', page).group(0)
    if where == "bound":
        return page.replace(span, span.replace('">', f'" {attribute}>', 1), 1)
    if where == "descendant":
        inner = re.sub(r">([^<]*)</span>$", rf"><b {attribute}>\1</b></span>", span)
        return page.replace(span, inner, 1)
    assert page.index('<div id="freshness">') < page.index(span)       # the first figure is in it
    return page.replace('<div id="freshness">', f'<div id="freshness" {attribute}>', 1)


@pytest.mark.parametrize("where", ["bound", "ancestor", "descendant"])
@pytest.mark.parametrize("attribute", ATTRIBUTES)
def test_r6_an_attribute_outside_the_renderers_list_is_a_finding(world, page, where, attribute):
    changed = with_attribute(page, world.report, where, attribute)
    assert changed != page
    found = attr_findings(validate.check_transcription(changed, world.report))
    assert found, (where, attribute)
    assert all(f.path.startswith("html.") for f in found)


def test_r6_an_unknown_attribute_on_an_unrelated_element_is_not_this_checks_business(world, page):
    changed = page.replace("<title>", '<title data-x="1">', 1)
    assert not attr_findings(validate.check_transcription(changed, world.report))


def test_r6_a_hidden_child_of_a_bound_element_is_refused_by_attribute_not_by_css(world, page):
    span, value = passed_span(page, world)
    for hider in ('<span style="display:none">{}</span>', '<span style="opacity:0">{}</span>',
                  '<span style="font-size:0">{}</span>', '<i hidden>{}</i>'):
        concealed = span.replace(f">{value}</span>", ">" + hider.format(value) + "</span>")
        found = validate.check_transcription(page.replace(span, concealed), world.report)
        assert attr_findings(found), hider


# ---------------------------------------------------------------------------------------- R7
def full_record():
    """A record with EVERY field the driver writes, each of the right type and none null."""
    digest = "c" * 64
    return {
        "record_schema": 1, "variant_id": "a.b", "scenario_id": "a", "variant": "b",
        "route": "proxy_strict", "implementation_kind": "harness_stand_in", "mode": "head_of_line",
        "control_route": "no_mediation", "started_at": "2026-10-05T00:00:00+00:00",
        "finished_at": "2026-10-05T00:00:01+00:00", "harness_head": "a" * 40,
        "delivered_digest": "b" * 64, "outcome": "passed", "reason_code": "EXEC_CONTRADICTED",
        "cause": "x",
        "control": {"route": "no_mediation", "stimulus_delivered": True, "refusal": "x",
                    "payload_sent_by_client": True, "payload_visible_at_client": True,
                    "declared_frames_reached_client": True, "terminal_arrived": True,
                    "client_bound_wire_stable_sha256": digest, "execution_stable_sha256": digest},
        "expectation": {"source_sha256": digest, "policy_decision": "block",
                        "assert_original_payload_absent": True, "bytes_outcome": "withheld",
                        "unreadable": False},
        "assertions": {"held": ["x"], "not_held": ["y"], "no_subject": ["z"],
                       "expect_payload_absent": True, "payload_at_destination": False,
                       "stimulus_origin": "client", "expect_original": False,
                       "declared_frames_delivered_unchanged": False},
        "graded_on": ["x"], "steps": ["send"], "primary_id": 3, "terminal_expected": True,
        "terminal_arrived": True, "upstream_as_declared": True, "mediator_disposition": "blocked",
        "client_bound_wire_stable_sha256": digest, "into_mediator_wire_stable_sha256": digest,
        "execution_stable_sha256": digest, "receipts_stable_sha256": digest,
        "volatile": {"bytes_to_client": 10, "bytes_into_mediator": 12, "execution_sha256": digest,
                     "receipts_sha256": digest},
        "stable_record_digest": digest,
    }


WRONG = {
    str: [1, True, [1], {"k": 1}, 1.5],
    bool: ["x", 1, [1], {"k": 1}, 1.5],
    int: ["x", True, [1], {"k": 1}, 1.5],
    list: ["x", 1, {"k": 1}, [1], [None]],
    dict: ["x", 1, [1], True],
}
SCALAR_WRONG = [True, [1], {"k": 1}, 1.5]               # primary_id may be text or a whole number


def swaps():
    """(path, wrong value) for every field of the full record, nested ones included."""
    out, record = [], full_record()
    for key, value in record.items():
        pool = SCALAR_WRONG if key == "primary_id" else WRONG[type(value)]
        out += [((key,), bad) for bad in pool]
        if isinstance(value, dict):
            for sub, inner in value.items():
                out += [((key, sub), bad) for bad in WRONG[type(inner)]]
    return out


SWAPS = swaps()
SWAP_IDS = [".".join(path) + "=" + repr(bad) for path, bad in SWAPS]


def mutated(path, bad):
    record = full_record()
    node = record
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = bad
    return record


def test_r7_there_are_at_least_200_type_swaps():
    assert len(SWAPS) >= 200


def test_r7_the_full_record_is_every_field_of_the_table_and_passes_it():
    record = full_record()
    assert schema.record_shape_problem(record) is None
    assert set(record) == set(schema.RECORD_FIELDS)
    for key, sub in ((k, v) for k, v in schema.RECORD_FIELDS.items() if isinstance(v, dict)):
        assert set(record[key]) == set(sub), key


@pytest.mark.parametrize("path,bad", SWAPS, ids=SWAP_IDS)
def test_r7_every_type_swap_is_a_finding_and_never_an_exception(world, path, bad):
    report = copy.deepcopy(world.report)
    record = mutated(path, bad)
    record["variant_id"] = report["execution_run"]["records"][0]["variant_id"] \
        if path != ("variant_id",) else record["variant_id"]
    report["execution_run"]["records"][0] = record
    found = validate.validate_report(report)                 # must not raise
    assert "VALIDATOR_CRASHED" not in codes(found)
    assert any(f.code == "EXEC_RECORD_SCHEMA" and f.path.startswith("execution_run.records[0]")
               for f in found), (path, bad)
    with pytest.raises(render.WillNotRender):
        render.render(report)


@pytest.mark.parametrize("path,bad", SWAPS[::4], ids=SWAP_IDS[::4])
def test_r7_the_producer_refuses_the_same_swaps_with_a_report_that_validates(
        tmp_path_factory, run_doc, path, bad):
    doc = copy.deepcopy(run_doc)
    keep = doc["records"][0]["variant_id"]
    doc["records"][0] = mutated(path, bad)
    if path != ("variant_id",):
        doc["records"][0]["variant_id"] = keep
    report, code = _build(tmp_path_factory, doc)
    assert (code, report["run"]["reason_code"]) == (3, "RUN_REFUSED")
    assert "execution_run" not in report
    assert validate.validate_report(report) == []
    assert validate.check_transcription(render.render(report), report) == []


@pytest.mark.parametrize("where", ["record", "control", "expectation", "assertions", "volatile"])
def test_r7_a_field_the_table_does_not_name_is_a_finding(where):
    record = full_record()
    (record if where == "record" else record[where])["invented_field"] = "x"
    assert schema.record_shape_problem(record)


def test_r7_null_is_allowed_for_a_named_field_and_never_for_the_two_that_identify_it():
    record = full_record()
    for key in schema.RECORD_FIELDS:
        if key not in ("variant_id", "outcome"):
            trial = dict(record)
            trial[key] = None
            assert schema.record_shape_problem(trial) is None, key
    for key in ("variant_id", "outcome"):
        assert schema.record_shape_problem(dict(record, **{key: None}))


def test_r7_the_driver_the_producer_and_the_validator_read_one_table(
        monkeypatch, world, tmp_path_factory, run_doc):
    """Change the one table and all three change with it."""
    table = dict(schema.RECORD_FIELDS, cause=schema.FLAG)
    monkeypatch.setattr(schema, "RECORD_FIELDS", table)
    record = full_record()                                   # `cause` is text in this record
    assert schema.record_shape_problem(record)
    assert produce.malformed_record([record])
    report = copy.deepcopy(world.report)
    report["execution_run"]["records"][0] = dict(record, variant_id=report["execution_run"][
        "records"][0]["variant_id"])
    assert any(f.code == "EXEC_RECORD_SCHEMA" for f in validate.validate_report(report))
    rebuilt = drive._finish(dict(record))
    assert rebuilt["outcome"] == "errored" and rebuilt["reason_code"] == "RUN_FAILED"


def test_r7_a_record_the_driver_cannot_write_to_its_own_table_becomes_an_errored_one():
    for bad in (dict(full_record(), control=[1]), dict(full_record(), steps="x"),
                dict(full_record(), invented="x")):
        out = drive._finish(bad)
        assert schema.record_shape_problem(out) is None
        assert (out["outcome"], out["reason_code"]) == ("errored", "RUN_FAILED")
        assert "shape" in out["cause"]


def test_r7_a_good_record_goes_through_the_driver_finish_unchanged_but_for_its_digest():
    good = full_record()
    out = drive._finish(dict(good))
    assert out["outcome"] == "passed" and out["stable_record_digest"]
    assert schema.record_shape_problem(out) is None


def _driver_keys():
    """Every string key the driver writes into a record, found in its source."""
    tree = ast.parse((HERE.parent / "drive.py").read_text())
    keys = set()
    for func in tree.body:
        if isinstance(func, ast.FunctionDef) and func.name in ("drive_one", "classify_run", "_finish"):
            for node in ast.walk(func):
                if isinstance(node, ast.Dict):
                    keys |= {k.value for k in node.keys
                             if isinstance(k, ast.Constant) and isinstance(k.value, str)}
                if isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Constant) and \
                        isinstance(node.slice.value, str):
                    keys.add(node.slice.value)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
                        node.func.attr == "update":
                    keys |= {k.arg for k in node.keywords if k.arg}
    return keys


def test_r7_every_key_the_driver_source_writes_is_in_the_one_table():
    table = set(schema.RECORD_FIELDS)
    for sub in schema.RECORD_FIELDS.values():
        if isinstance(sub, dict):
            table |= set(sub)
    # keys of other things the same functions touch, named so a new one is a decision
    other = {"op", "held", "id", "name", "expected", "directory", "scenarios", "variants",
             "requests", "bytes_delivered", "policy", "decision", "outcome_of"}
    missing = _driver_keys() - table - other
    assert not missing, sorted(missing)


def test_r7_validation_survives_malformed_anything_and_says_so(world):
    """No exception from a wrong type at any depth of the first two levels. A section the validator
    cannot read is itself a finding, so a malformed report is never empty-handed."""
    report = world.report
    cases = []
    for key, value in report.items():
        cases += [(key,), ]
        if isinstance(value, dict):
            cases += [(key, inner) for inner in value]
    count = 0
    for path in cases:
        for bad in (1, "x", [1], {"k": [1]}, True, None):
            mutant = copy.deepcopy(report)
            node = mutant
            for part in path[:-1]:
                node = node[part]
            node[path[-1]] = bad
            found = validate.validate_report(mutant)         # must not raise
            assert isinstance(found, list)
            count += 1
    assert count >= 200
    for bad in (1, "x", {"k": 1}, [1], [None], [[1]]):
        mutant = copy.deepcopy(report)
        mutant["execution_run"]["records"] = bad
        assert validate.validate_report(mutant)


def test_r7_a_section_that_crashes_is_a_finding_not_an_exception(world, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(validate, "_validate_ledger", boom)
    found = validate.validate_report(world.report)
    assert "VALIDATOR_CRASHED" in codes(found)


# --------------------------------------------------------------------------------------- V16
@pytest.mark.parametrize("state", ["true", "false", "not_applicable", "not_computed"])
def test_v16_complete_with_nothing_executed_is_a_finding_whatever_the_ceiling(closed_norun, state):
    report = copy.deepcopy(closed_norun[0])
    report["coverage"]["ceiling"]["state"] = state
    report["run"].update(outcome="complete", exit_code=0, reason_code=None)
    assert "EXEC_NONE_NOT_REFUSED" in codes(validate.validate_report(report))


def test_v16_complete_with_a_missing_partition_is_a_finding(closed_norun):
    report = copy.deepcopy(closed_norun[0])
    del report["coverage"]["execution_partition"]
    report["run"].update(outcome="complete", exit_code=0, reason_code=None)
    assert "EXEC_NONE_NOT_REFUSED" in codes(validate.validate_report(report))


def test_v16_a_run_that_executed_something_is_not_that_finding(tmp_path_factory, run_doc):
    report, code = build_closed(tmp_path_factory, run_doc)
    assert (code, report["run"]["outcome"]) == (0, "complete") and executed_total(report) > 0
    assert "EXEC_NONE_NOT_REFUSED" not in codes(validate.validate_report(report))


def test_v16_the_refusal_with_nothing_executed_is_not_that_finding(closed_norun):
    assert "EXEC_NONE_NOT_REFUSED" not in codes(validate.validate_report(closed_norun[0]))


def test_v16_the_producer_refuses_nothing_executed_when_the_ceiling_is_not_applicable(
        tmp_path_factory, monkeypatch):
    real = produce.plan_corpus()
    monkeypatch.setattr(produce, "plan_corpus", lambda *a, **k: {
        "drivable": real["drivable"], "blocked": {}, "invalid": {}})
    patch = pytest.MonkeyPatch()
    patch.setattr(classify, "load_map", lambda path=None: closed_map())
    try:
        report, code = _build(tmp_path_factory)
    finally:
        patch.undo()
    assert report["coverage"]["ceiling"]["state"] == "not_applicable"
    assert (code, report["run"]["reason_code"]) == (3, "EXEC_NONE")
    assert validate.validate_report(report) == []
