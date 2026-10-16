"""Row 23. The one residual ASTRA found in rows12-13-r6 (de8d8a02418e).

A panel (harness, ledger, a route's rows) could carry a free form `detail` string. The renderer
picked it ahead of the fixed text for the reason code and printed it as a sentence, and nothing
bound it to anything, so a crafted report put any sentence on the page and both validation and
the byte equality check accepted it, because the page was the renderer's own output.

Same class as the encoders row: a string the validator cannot bind is an off switch for the
truth. So it is deleted, not bound. The panels carry a state and a reason code, the page shows
only the fixed text keyed by the code, and a report that still carries a `detail` field on a panel
is a finding (an unknown field, refused).

Case 0 to 2 are ASTRA's own (r6_independent.py), carried here as tests. Each test was written
first and run against f65a4381, where the ones that name the defect are RED.
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

CLAIM = "The examiner confirmed every one of these variants against the product."
PATHS = [("harness",), ("ledger",), ("routes", 0, "rows"), ("coverage",)]
PATH_IDS = [".".join(str(k) for k in p) for p in PATHS]
PANEL_PATHS = PATHS[:3]                    # the three the page prints a note for


class Counter(HTMLParser):
    def __init__(self, sentence):
        super().__init__()
        self.sentence, self.count = sentence, 0

    def handle_data(self, data):
        if data == self.sentence:
            self.count += 1


def separate(page, sentence=CLAIM):
    counter = Counter(sentence)
    counter.feed(page)
    return counter.count


def node_at(report, path):
    node = report
    for key in path:
        node = node[key]
    return node


def with_detail(base, path, value=CLAIM):
    report = copy.deepcopy(base)
    node_at(report, path)["detail"] = value
    return report


def panels(report):
    """Every dict in the report that is a panel, found by walking, not by naming the paths."""
    found = []

    def walk(node, where):
        if isinstance(node, dict):
            if "state" in node and "reason_code" in node:
                found.append((where, node))
            for key, value in node.items():
                walk(value, where + (key,))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                walk(value, where + (index,))
    walk(report, ())
    return found


# ------------------------------------------------------------------------ the three paths, case 0 to 2
@pytest.mark.parametrize("path", PATHS, ids=PATH_IDS)
def test_a_report_still_carrying_detail_is_a_finding_at_that_field(norun, path):
    report = with_detail(norun.report, path)
    found = validate.validate_report(report)                # must not raise
    where = ".".join(str(k) if not isinstance(k, int) else f"[{k}]" for k in path)
    where = where.replace(".[", "[") + ".detail"
    hits = [f for f in found if f.path == where]
    assert hits, (where, [(f.code, f.path) for f in found])
    assert {f.code for f in hits} == {"REPORT_FIELD_TYPE"}
    assert "unknown field" in hits[0].detail


@pytest.mark.parametrize("path", PATHS, ids=PATH_IDS)
def test_a_report_carrying_detail_is_refused_not_rendered(norun, path):
    report = with_detail(norun.report, path)
    with pytest.raises(render.WillNotRender):
        render.render(report)


@pytest.mark.parametrize("value", [CLAIM, "", None, 7, [CLAIM], {"k": CLAIM}, True],
                         ids=["text", "empty", "null", "number", "list", "object", "bool"])
@pytest.mark.parametrize("path", PATHS, ids=PATH_IDS)
def test_any_value_under_detail_is_the_same_finding_and_never_raises(norun, path, value):
    report = with_detail(norun.report, path, value)
    found = validate.validate_report(report)
    assert any(f.code == "REPORT_FIELD_TYPE" and f.path.endswith(".detail") for f in found)


@pytest.mark.parametrize("path", PATHS, ids=PATH_IDS)
def test_the_schema_view_drops_detail_and_names_it_a_problem(norun, path):
    view, problems = schema.render_view(with_detail(norun.report, path))
    assert "detail" not in node_at(view, path)
    assert any(p.endswith(".detail") and "unknown field" in why for p, why in problems)


def test_the_panel_shapes_hold_no_detail_field():
    def reads(shape):
        if isinstance(shape, dict):
            return {k: v for k, v in shape.items()}
        return {}
    for table in (schema.REPORT_READS["harness"], schema.REPORT_READS["ledger"],
                  schema.REPORT_READS["coverage"], schema._PANEL):
        entry = reads(table).get("detail")
        assert entry is None or entry == schema.REFUSED_FIELD, entry


# ------------------------------------------------------------------ the renderer alone, past the validator
@pytest.mark.parametrize("path", PATHS, ids=PATH_IDS)
def test_render_alone_refuses_a_report_that_carries_detail(norun, path):
    report = with_detail(norun.report, path)
    with pytest.raises(render.WillNotRender, match="detail"):
        render.render(report, findings=[])                  # the renderer alone, no validator


@pytest.mark.parametrize("path", PANEL_PATHS, ids=PATH_IDS[:3])
def test_the_page_shows_the_fixed_text_for_the_reason_code(norun, path):
    page = render.render(norun.report, findings=[])
    code = node_at(norun.report, path)["reason_code"]
    fixed = schema.REASON_CODES[code]
    assert fixed and render._text(fixed) in page
    assert separate(page) == 0


def test_the_note_is_the_fixed_text_keyed_by_code_and_nothing_else():
    panel = {"state": "unavailable", "reason_code": "EVIDENCE_UNBOUND", "detail": "X-DETAIL"}
    note = render._state_note(panel)
    assert "X-DETAIL" not in note
    assert render._text(schema.REASON_CODES["EVIDENCE_UNBOUND"]) in note
    unknown = render._state_note({"state": "unavailable", "reason_code": "NO_SUCH", "detail": "X"})
    assert "X</p>" not in unknown and 'class="detail"' not in unknown


# ---------------------------------------------------------------------------------- the honest control
def test_the_honest_report_passes_with_no_detail_anywhere(norun, world):
    for built in (norun, world):
        assert validate.validate_report(built.report) == []
        for where, panel in panels(built.report):
            assert "detail" not in panel, where
        page = render.render(built.report)
        assert validate.check_transcription(page, built.report) == []
        assert separate(page) == 0


def test_the_producer_writes_no_detail_into_any_panel(norun):
    assert panels(norun.report)
    assert all("detail" not in panel for _, panel in panels(norun.report))


def test_every_reason_code_a_producer_writes_has_a_fixed_text(norun, world):
    for built in (norun, world):
        for where, panel in panels(built.report):
            code = panel.get("reason_code")
            if code and panel.get("state") in ("unavailable", "historical", "not_run"):
                assert schema.REASON_CODES.get(code), (where, code)


# ----------------------------------------------------------------------- what the row keeps, held
def test_the_encoders_are_still_the_one_door_for_text():
    assert render._text("<&\"'>") == "&lt;&amp;&quot;&#x27;&gt;"
    assert render._attr("<&\"'>") == render._text("<&\"'>")
    assert "<" not in render._data({"k": "<>&"})


def test_equality_is_still_the_whole_transcription_check(world):
    page = render.render(world.report)
    assert validate.check_transcription(page, world.report) == []
    assert validate.check_transcription(page + " ", world.report)


def test_the_typed_view_still_refuses_a_wrong_typed_field(norun):
    report = copy.deepcopy(norun.report)
    report["harness"]["state"] = ["x"]
    assert any(f.code == "REPORT_FIELD_TYPE" for f in validate.validate_report(report))
