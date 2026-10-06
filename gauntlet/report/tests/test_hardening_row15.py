"""Row 15. The two residuals ASTRA found in row 14 (rows12-13-r2, 9fa8cfb6629c).

R6 A bound element's text is its OWN visible text. A hidden, aria hidden, script, style or
   template descendant inside a bound element used to count toward it, so the correct number or
   the required scope sentence could sit concealed inside a visible parent and pass. The scope
   disclosure must be shown, or transcription fails.
R7 Every nested field of a record is shape checked on import, and the validator returns findings
   for a bad one instead of raising. A bad nested field gives a refusal report that itself
   passes validation, renders and transcribes.

Each test was written first and run against ecf28cd3, where it is RED.
"""
import copy
import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import produce                                              # noqa: E402
import render                                               # noqa: E402
import schema                                               # noqa: E402
import validate                                             # noqa: E402
from test_execution_run import (                            # noqa: E402,F401
    _build, codes, corpus_digest, norun, planned, run_doc, world)
from test_hardening_row14 import page, passed_span          # noqa: E402,F401

SENTENCE_SPAN = ('<span class="bound-text" data-bound="routes[0].execution.fit_scope">'
                 + schema.STANDIN_SCOPE_SENTENCE.replace("'", "&#x27;") + "</span>")

HIDERS = {
    "hidden attribute": '<span hidden>{}</span>',
    "display none": '<span style="display:none">{}</span>',
    "visibility hidden": '<span style="visibility:hidden">{}</span>',
    "opacity zero": '<span style="opacity:0">{}</span>',
    "aria hidden": '<span aria-hidden="true">{}</span>',
    "script": "<script>{}</script>",
    "style": "<style>{}</style>",
    "template": "<template>{}</template>",
}


# ---------------------------------------------------------------------------------------- R6
@pytest.mark.parametrize("hider", sorted(HIDERS))
def test_r6_a_count_moved_into_a_hidden_child_of_its_bound_element_is_refused(
        world, page, hider):
    span, value = passed_span(page, world)
    concealed = span.replace(f">{value}</span>", ">" + HIDERS[hider].format(value) + "</span>")
    assert concealed != span
    found = validate.check_transcription(page.replace(span, concealed), world.report)
    assert "TRANSCRIPTION_MISMATCH" in codes(found)


@pytest.mark.parametrize("hider", sorted(HIDERS))
def test_r6_the_scope_sentence_inside_a_hidden_child_is_refused(world, page, hider):
    assert SENTENCE_SPAN in page
    sentence = schema.STANDIN_SCOPE_SENTENCE.replace("'", "&#x27;")
    concealed = SENTENCE_SPAN.replace(f">{sentence}</span>",
                                      ">" + HIDERS[hider].format(sentence) + "</span>")
    found = validate.check_transcription(page.replace(SENTENCE_SPAN, concealed), world.report)
    assert [f.code for f in found if f.path == "routes[0].execution.fit_scope"] == [
        "TRANSCRIPTION_MISMATCH"]


def test_r6_the_scope_sentence_under_a_hidden_ancestor_is_refused(world, page):
    for opener in ('<div hidden>', '<div aria-hidden="true">', '<div style="display:none">'):
        wrapped = page.replace(SENTENCE_SPAN, f"{opener}{SENTENCE_SPAN}</div>")
        found = validate.check_transcription(wrapped, world.report)
        assert "BINDING_NOT_VISIBLE" in codes(found), opener
        assert "BINDING_MISSING" in codes(found), opener


def test_r6_visible_nested_text_still_counts_and_hidden_nested_text_does_not(world):
    shown = '<span data-bound="a">3<b>4</b></span>'
    assert validate.check_transcription(shown, {"a": 34}) == []
    mixed = '<span data-bound="a">3<span hidden>9</span></span>'
    assert validate.check_transcription(mixed, {"a": 3}) == []
    assert "TRANSCRIPTION_MISMATCH" in codes(validate.check_transcription(mixed, {"a": 39}))


@pytest.mark.parametrize("rule", [".bound-text{display:none}", ".fig { visibility:hidden }",
                                  "main{opacity:0}", ".bound-text{font-size:0}"])
def test_r6_a_style_sheet_that_hides_content_is_refused(world, page, rule):
    tampered = page.replace("</style>", f"{rule}</style>", 1)
    assert tampered != page
    found = validate.check_transcription(tampered, world.report)
    assert "BINDING_NOT_VISIBLE" in codes(found)


def test_r6_the_ordinary_page_has_no_hiding_rule_and_still_passes(world, page):
    assert validate.check_transcription(page, world.report) == []


# ---------------------------------------------------------------------------------------- R7
HOSTILE = [[1], "x", 7, {"k": [1]}]
NESTED = [("control", None), ("assertions", None), ("expectation", None), ("graded_on", None),
          ("assertions", "held"), ("assertions", "not_held"), ("assertions", "no_subject"),
          ("assertions", "payload_at_destination"), ("assertions", "expect_payload_absent"),
          ("assertions", "expect_original"),
          ("assertions", "declared_frames_delivered_unchanged"),
          ("control", "stimulus_delivered"), ("control", "route"),
          ("expectation", "assert_original_payload_absent"), ("expectation", "bytes_outcome"),
          ("reason_code", None), ("harness_head", None), ("delivered_digest", None),
          ("started_at", None), ("finished_at", None), ("route", None),
          ("implementation_kind", None), ("mode", None), ("record_schema", None),
          ("variant_id", None)]


def poison(record, field, sub, value):
    if sub is None:
        record[field] = value
    else:
        if not isinstance(record.get(field), dict):
            record[field] = {}
        record[field][sub] = value


STRINGS = {"reason_code", "harness_head", "delivered_digest", "started_at", "finished_at", "route",
           "implementation_kind", "mode", "variant_id"}
SUB_STRINGS = {("control", "route"), ("expectation", "bytes_outcome")}


def hostile_for(field, sub):
    """Values of the WRONG type for this field. A value of the right type is shape correct, and
    whether it is a believable value is the validator's question, not the import's."""
    if (field, sub) in (("graded_on", None), ("assertions", "held"), ("assertions", "not_held"),
                        ("assertions", "no_subject")):
        return ["x", 7, {"k": [1]}, [1]]              # [1] is a list of the wrong item type
    if field in ("control", "assertions", "expectation") and sub is None:
        return ["x", 7, [1]]
    if field in STRINGS or (field, sub) in SUB_STRINGS:
        return [[1], 7, {"k": [1]}]
    if field == "record_schema":
        return ["x", [1], {"k": [1]}]
    return ["x", 7, [1], {"k": [1]}]                  # a boolean field


CASES = [(f, s, v) for f, s in NESTED for v in hostile_for(f, s)]
IDS = [f"{f}.{s}={v!r}" if s else f"{f}={v!r}" for f, s, v in CASES]


@pytest.mark.parametrize("field,sub,value", CASES, ids=IDS)
def test_r7_a_bad_nested_field_is_a_refusal_report_that_validates_and_renders(
        tmp_path_factory, run_doc, field, sub, value):
    doc = copy.deepcopy(run_doc)
    poison(doc["records"][0], field, sub, value)
    report, code = _build(tmp_path_factory, doc)
    assert code == 3
    assert report["run"]["outcome"] == "refused" and report["run"]["reason_code"] == "RUN_REFUSED"
    assert report["coverage"]["execution_state"] == "unavailable"
    assert "execution_run" not in report
    assert validate.validate_report(report) == []
    page = render.render(report)                          # a refusal page that can be drawn
    assert validate.check_transcription(page, report) == []


@pytest.mark.parametrize("field,sub,value", CASES, ids=IDS)
def test_r7_direct_validation_returns_findings_and_never_raises(world, field, sub, value):
    report = copy.deepcopy(world.report)
    poison(report["execution_run"]["records"][0], field, sub, value)
    found = validate.validate_report(report)              # must not raise
    assert isinstance(found, list)
    assert "EXEC_RECORD_SCHEMA" in {f.code for f in found
                                    if f.path.startswith("execution_run.records[0]")}
    with pytest.raises(render.WillNotRender):
        render.render(report)


def test_r7_a_well_formed_record_passes_the_shape_check(run_doc):
    assert all(schema.record_shape_problem(r) is None for r in run_doc["records"])
    assert produce.malformed_record(run_doc["records"]) is None


def test_r7_the_real_driver_record_shape_passes_the_shape_check():
    """The shape check reads the fields the driver really writes, not only the synthetic ones."""
    record = {
        "record_schema": 1, "variant_id": "a.b", "route": "proxy_strict",
        "implementation_kind": "harness_stand_in", "mode": "head_of_line", "harness_head": "a" * 40,
        "delivered_digest": "b" * 64, "outcome": "passed", "reason_code": None,
        "control": {"route": "no_mediation", "stimulus_delivered": True, "terminal_arrived": True,
                    "payload_visible_at_client": True},
        "expectation": {"assert_original_payload_absent": True, "bytes_outcome": "withheld",
                        "policy_decision": "block", "source_sha256": "c" * 64},
        "graded_on": ["x"], "steps": [], "volatile": {}, "primary_id": 3,
        "assertions": {"held": ["x"], "not_held": [], "no_subject": [], "payload_at_destination": False,
                       "expect_payload_absent": True, "expect_original": False,
                       "declared_frames_delivered_unchanged": None, "stimulus_origin": "client"},
        "started_at": "2026-10-05T00:00:00+00:00", "finished_at": "2026-10-05T00:00:01+00:00",
    }
    assert schema.record_shape_problem(record) is None


def test_r7_header_fields_of_the_wrong_type_never_make_validation_raise(world):
    keys = list(world.report["execution_run"]["header"])
    for key in keys:
        for value in ([1], "x", 7, {"k": [1]}, None, True):
            report = copy.deepcopy(world.report)
            report["execution_run"]["header"][key] = value
            found = validate.validate_report(report)       # must not raise
            assert isinstance(found, list), (key, value)


# ------------------------------------------------------------------------------------------ V15
# A closed capability map computes a ceiling. A computed ceiling over a run that executed nothing
# is a page with a number and nothing behind it, so the producer refuses with EXEC_NONE.
import classify                                             # noqa: E402

REAL_LOAD_MAP = classify.load_map


def closed_map():
    """The reviewed map with its open questions answered, so the ceiling is computable."""
    capmap = REAL_LOAD_MAP()
    for op in capmap["unclassified"]:
        capmap["classified"][op] = {"bucket": classify.ROUTE, "basis": "inspected_source",
                                    "evidence": "test fixture, a closed map"}
    capmap["unclassified"] = {}
    return capmap


def build_closed(tmp_path_factory, doc=None):
    patch = pytest.MonkeyPatch()
    patch.setattr(classify, "load_map", lambda path=None: closed_map())
    try:
        return _build(tmp_path_factory, doc)
    finally:
        patch.undo()


def executed_total(report):
    part = report["coverage"]["execution_partition"]
    return sum(part[k] for k in ("passed", "failed", "refused", "errored"))


@pytest.fixture(scope="module")
def closed_norun(tmp_path_factory):
    return build_closed(tmp_path_factory)


def test_v15_a_closed_map_and_nothing_executed_is_refusal_rc_3_exec_none(closed_norun):
    report, code = closed_norun
    assert report["coverage"]["ceiling"]["state"] in ("true", "false")      # it IS computed
    assert executed_total(report) == 0
    assert code == 3
    assert report["run"]["outcome"] == "refused" and report["run"]["exit_code"] == 3
    assert report["run"]["reason_code"] == "EXEC_NONE"


def test_v15_the_refusal_report_itself_validates_renders_and_transcribes(closed_norun):
    report, _ = closed_norun
    assert validate.validate_report(report) == []
    assert validate.check_transcription(render.render(report), report) == []


def test_v15_exec_none_is_a_named_reason_code():
    assert "EXEC_NONE" in schema.REASON_CODES and schema.REASON_CODES["EXEC_NONE"]


def test_v15_a_closed_map_with_executed_records_is_not_refused(tmp_path_factory, run_doc):
    report, code = build_closed(tmp_path_factory, run_doc)
    assert executed_total(report) > 0 and report["coverage"]["ceiling"]["state"] in ("true", "false")
    assert (code, report["run"]["outcome"]) == (0, "complete")
    assert validate.validate_report(report) == []


def test_v15_an_open_map_keeps_its_own_refusal_code(norun):
    assert norun.report["coverage"]["ceiling"]["state"] == "not_computed"
    assert (norun.code, norun.report["run"]["reason_code"]) == (3, "RUN_REFUSED")


def test_v15_an_unreadable_run_keeps_its_own_refusal_code(tmp_path_factory):
    patch = pytest.MonkeyPatch()
    patch.setattr(classify, "load_map", lambda path=None: closed_map())
    try:
        report, code = _build(tmp_path_factory, raw="{not json")
    finally:
        patch.undo()
    assert (code, report["run"]["reason_code"]) == (3, "RUN_REFUSED")


def test_v15_a_run_with_no_records_is_exec_none_too(tmp_path_factory, run_doc):
    doc = copy.deepcopy(run_doc)
    doc["records"] = []
    doc["header"]["counts"] = {"passed": 0, "failed": 0, "refused": 0, "errored": 0}
    doc["header"]["records_digest"] = schema.records_digest([])
    report, code = build_closed(tmp_path_factory, doc)
    assert executed_total(report) == 0
    assert (code, report["run"]["reason_code"]) == (3, "EXEC_NONE")
    assert validate.validate_report(report) == []
