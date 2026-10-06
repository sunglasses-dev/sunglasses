"""The page carries the execution block, the scope sentence and both ledger lines as data.

Row 13 of the executed partition. Row 12 made these fields validated data. This file proves the
renderer puts them on the page without retyping them:

  VERBATIM. The text on the page equals the validated field byte for byte, after the one
  unescape a browser performs. The sentence that says what the examiner's finding covers is
  compared against `schema.STANDIN_SCOPE_SENTENCE`, not against the report, so a renderer and a
  report that drifted together still fail here.

  NOTHING TYPED. Take the bound spans out of the new blocks and no digit is left. A number the
  renderer wrote beside the data would survive that and fail this.

  A TYPED LINE FAILS. A ledger line, or the sentence, edited by hand in the artifact does not
  render, and one edited in the page after rendering fails the transcription check.

The fixtures come from `test_execution_run.py`, built through `produce.build()` with a run
document of synthetic records. No number from them is quoted here.
"""
import copy
import html as html_lib
import pathlib
import re
import sys

import pytest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

import render                                               # noqa: E402
import schema                                               # noqa: E402
import validate                                             # noqa: E402
from test_execution_run import (                            # noqa: E402,F401
    LEDGER, _build, codes, corpus_digest, line_of, norun, planned, retext, run_doc, world)

SPAN = re.compile(r'<span class="bound-text" data-bound="([^"]+)">([^<]*)</span>')
ANY_SPAN = re.compile(r'<span class="(?:fig|bound-text)" data-bound="[^"]+">[^<]*</span>')
CUM, NIGHT = "cumulative_gate2", "no_live_calls_standin_run"


def texts(html):
    """data-bound path to the text a browser would show for it."""
    return {path: html_lib.unescape(text) for path, text in SPAN.findall(html)}


def block_of(html, opening, closing):
    start = html.index(opening)
    return html[start:html.index(closing, start)]


@pytest.fixture(scope="module")
def page(world):
    return render.render(world.report)


def test_the_scope_sentence_is_on_the_page_byte_for_byte(world, page):
    shown = texts(page)["routes[0].execution.fit_scope"]
    assert shown == schema.STANDIN_SCOPE_SENTENCE
    assert shown == world.report["routes"][0]["execution"]["fit_scope"]
    assert shown.encode() == schema.STANDIN_SCOPE_SENTENCE.encode()


def test_the_apostrophe_is_escaped_in_the_markup_and_still_transcribes(world, page):
    assert "examiner&#x27;s FIT finding" in page
    assert validate.check_transcription(page, world.report) == []


def test_both_ledger_lines_are_on_the_page_byte_for_byte(world, page):
    shown, lines = texts(page), world.report["ledger"]["lines"]
    assert len(lines) == 2
    for index, line in enumerate(lines):
        assert line["text"] == schema.ledger_line_text(line)
        assert shown[f"ledger.lines[{index}].text"] == line["text"]
    assert shown["ledger.lines[0].text"] == "cumulative Gate 2, 36 of 60 charged driver invocations"
    assert shown["ledger.lines[1].text"] == "this nightly, 0 live calls"


def test_the_two_lines_stay_in_order_and_inside_the_method_section(page):
    method = block_of(page, '<section id="method">', "</section>")
    assert method.index("cumulative Gate 2") < method.index("this nightly")
    assert "ledger.lines[0].text" in method and "ledger.lines[1].text" in method


def test_the_execution_block_sits_in_the_route_and_equals_the_data(world, page):
    route = block_of(page, '<section id="routes">', "</section>")
    assert '<div class="execution">' in route
    block = world.report["routes"][0]["execution"]
    for key, value in block["counts"].items():
        assert f'data-bound="routes[0].execution.counts.{key}">{value}<' in route
    shown = texts(route)
    assert shown["routes[0].execution.state"] == block["state"]
    assert f'data-bound="routes[0].execution.harness_head">{block["harness_head"]}<' in route
    assert f'data-bound="routes[0].execution.records_digest">{block["records_digest"]}<' in route


def test_the_block_says_it_is_not_the_product_next_to_the_data(page):
    route = block_of(page, '<div class="execution">', "</div>")
    assert "never read as the product" in route
    assert route.index("never read as the product") < route.index("fit_scope")


def test_the_new_blocks_hold_no_typed_digit(page):
    """Remove every bound span and no digit remains in the execution block or the ledger lines."""
    for opening, closing in (('<div class="execution">', "</div>"),
                             ('<ul class="ledger-lines">', "</ul>")):
        bare = ANY_SPAN.sub("", block_of(page, opening, closing))
        assert not re.search(r"\d", re.sub(r"<[^>]+>", "", bare)), bare


def test_every_bound_figure_on_the_page_still_transcribes(world, page):
    assert validate.check_transcription(page, world.report) == []


def test_a_typed_ledger_line_does_not_render(world):
    for scope, typed in ((CUM, "cumulative Gate 2, 3 of 60 charged driver invocations"),
                         (NIGHT, "this nightly, no live calls")):
        report = copy.deepcopy(world.report)
        line_of(report, scope)["text"] = typed
        assert "LEDGER_LINE_TYPED" in codes(validate.validate_report(report))
        with pytest.raises(render.WillNotRender):
            render.render(report)


def test_a_reworded_scope_sentence_does_not_render(world):
    report = copy.deepcopy(world.report)
    block = report["routes"][0]["execution"]
    block["fit_scope"] = block["fit_scope"].replace("has not been examined",
                                                    "has been examined")
    assert "STANDIN_SCOPE_MISSING" in codes(validate.validate_report(report))
    with pytest.raises(render.WillNotRender):
        render.render(report)


def test_a_dropped_scope_sentence_does_not_render(world):
    report = copy.deepcopy(world.report)
    del report["routes"][0]["execution"]["fit_scope"]
    with pytest.raises(render.WillNotRender):
        render.render(report)


def test_a_line_typed_into_the_page_after_rendering_fails_transcription(world, page):
    typed = page.replace("this nightly, 0 live calls", "this nightly, 1 live calls")
    assert typed != page
    assert "TRANSCRIPTION_MISMATCH" in codes(validate.check_transcription(typed, world.report))


def test_a_sentence_edited_in_the_page_after_rendering_fails_transcription(world, page):
    typed = page.replace("has not been examined", "has been examined")
    assert typed != page
    found = validate.check_transcription(typed, world.report)
    assert [f.path for f in found] == ["routes[0].execution.fit_scope"]


def test_transcription_compares_what_a_browser_shows_not_the_markup():
    html = '<span data-bound="a">x &amp; y</span>'
    assert validate.check_transcription(html, {"a": "x & y"}) == []
    assert "TRANSCRIPTION_MISMATCH" in codes(
        validate.check_transcription('<span data-bound="a">x &amp; z</span>', {"a": "x & y"}))


def test_an_unavailable_line_says_so_and_prints_no_count(tmp_path_factory, run_doc):
    world = _build(tmp_path_factory, run_doc, ledger=None)[0]
    assert validate.validate_report(world) == []
    page = render.render(world)
    lines = block_of(page, '<ul class="ledger-lines">', "</ul>")
    first, second = lines.split("</li>")[:2]
    assert "cumulative_gate2" in first and "unavailable" in first and "EVIDENCE_UNBOUND" in first
    prose = re.sub(r"<[^>]+>", "", re.sub(r"<code>[^<]*</code>", "", first))
    assert "bound-text" not in first and not re.search(r"\d", prose), prose
    assert texts(lines)["ledger.lines[1].text"] == "this nightly, 0 live calls"
    assert validate.check_transcription(page, world) == []


def test_a_report_with_no_run_renders_without_the_new_blocks(norun):
    page = render.render(norun.report)
    assert "What ran on this route" not in page
    assert 'class="ledger-lines"' not in page and "bound-text" not in page.split("</style>")[1]
    assert validate.check_transcription(page, norun.report) == []
