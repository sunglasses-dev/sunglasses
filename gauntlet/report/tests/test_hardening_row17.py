"""Row 17. The residuals ASTRA found in rows12-13-r4.

R6 The published page is `render.render(report)` byte for byte, one comparison. There is no HTML
   parser, no list of tags and no list of attributes left to be a denylist with a hole in it.
   Render is deterministic, and every one of ASTRA's seven r4 cases is a finding.
R7 Render reads the report only through the table in `schema.REPORT_READS`, and the validator types
   every field that table names, identities included. A validated report always renders, and a
   report that does not validate is refused by `WillNotRender` and by nothing else.
C6 The fixture around the ceiling flip carries executed rows (test_acceptance_controls).

Each test was written first and run against the row 16 head, where it is RED.
"""
import ast
import copy
import html as html_lib
import json
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
    _build, codes, corpus_digest, norun, planned, run_doc, world)
from test_hardening_row15 import build_closed, closed_norun  # noqa: E402,F401

SCOPE_PATH = "routes[0].execution.fit_scope"
SPAN = re.compile(r'<span class="[a-z-]+" data-bound="([^"]+)">([^<]*)</span>')


@pytest.fixture(scope="module")
def page(world):
    return render.render(world.report)


def bound_span(page, path):
    for found in SPAN.finditer(page):
        if found.group(1) == path:
            return found.group(0), found.group(2)
    raise AssertionError(f"no bound span for {path}")


# ---------------------------------------------------------------------------------------- R6
def source_of(module):
    return pathlib.Path(module.__file__).read_text()


def test_r6_the_parser_the_denylist_and_the_allowlist_are_gone():
    tree = ast.parse(source_of(validate))
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import)
                for alias in node.names}
    imported |= {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert "html.parser" not in imported and "HTMLParser" not in source_of(validate)
    for name in ("NON_VISIBLE_TAGS", "VOID_TAGS", "_Bindings", "_attribute_problem",
                 "_required_bindings", "HIDING_STYLE"):
        assert not hasattr(validate, name), name
    for name in ("RENDER_ATTRIBUTES", "RENDER_IDS", "RENDER_CLASSES", "RENDER_STYLESHEET"):
        assert not hasattr(schema, name), name


def test_r6_the_check_is_one_comparison_with_the_render(world, page):
    assert validate.check_transcription(page, world.report) == []
    found = validate.check_transcription(page + " ", world.report)
    assert [f.code for f in found] == ["PAGE_NOT_THE_RENDER"]
    assert found[0].path == "html"


def test_r6_render_is_deterministic(world, page):
    assert render.render(world.report) == page
    assert render.render(copy.deepcopy(world.report)) == page
    assert render.render(json.loads(json.dumps(world.report))) == page


def test_r6_render_does_not_depend_on_the_order_keys_were_written_in(world, page):
    def reversed_keys(node):
        if isinstance(node, dict):
            return {key: reversed_keys(node[key]) for key in reversed(list(node))}
        if isinstance(node, list):
            return [reversed_keys(item) for item in node]
        return node
    assert render.render(reversed_keys(world.report)) == page


def test_r6_render_holds_no_clock_no_environment_and_no_randomness():
    tree = ast.parse(source_of(render))
    names = {alias.name.split(".")[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
             for alias in node.names}
    names |= {(node.module or "").split(".")[0] for node in ast.walk(tree)
              if isinstance(node, ast.ImportFrom)}
    assert not names & {"time", "datetime", "os", "random", "uuid", "secrets", "socket",
                        "platform", "locale"}, names
    used = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
    assert not used & {"environ", "getenv", "now", "utcnow", "today", "time", "random",
                       "uuid4", "monotonic"}, used


def test_r6_the_unchanged_page_passes_for_every_kind_of_report(world, norun, closed_norun, page):
    for report in (world.report, norun.report, closed_norun[0]):
        assert validate.check_transcription(render.render(report), report) == []


def hidden(span_and_text):
    span, text = span_and_text
    return span, text


ASTRA_CASES = {
    # the seven r4 cases, built from the page as ASTRA built them
    "closed_dialog": lambda p, s, t: p.replace(s, "<dialog>" + s + "</dialog>"),
    "closed_details": lambda p, s, t: p.replace(s, "<details><summary></summary>" + s
                                                + "</details>"),
    "svg_defs": lambda p, s, t: p.replace(s, "<svg><defs>" + s + "</defs></svg>"),
    "sibling_overlay": lambda p, s, t: p.replace(
        "</main>", '<div style="position:fixed;inset:0;background:white;z-index:2147483647">'
                   "</div></main>"),
    "duplicate_renderer_sheet": lambda p, s, t: p.replace(
        "<main>", "<style>" + render.STYLESHEET + "</style><main>"),
    "script_hiding": lambda p, s, t: p.replace(
        "</main>", '<script>document.querySelectorAll("[data-bound]").forEach('
                   "e=>e.hidden=true)</script></main>"),
    "scope_dialog_descendant": lambda p, s, t: p.replace(
        s, s.replace(">" + t + "<", "><dialog>" + t + "</dialog><")),
}
EARLIER_CASES = {
    # every concealment from rows 14 to 16, now one comparison and no reading of markup
    "hidden_attribute": lambda p, s, t: p.replace(s, s.replace("<span ", "<span hidden ", 1)),
    "aria_hidden": lambda p, s, t: p.replace(s, s.replace("<span ", '<span aria-hidden="true" ', 1)),
    "style_attribute": lambda p, s, t: p.replace(
        s, s.replace("<span ", '<span style="display:none" ', 1)),
    "unknown_attribute": lambda p, s, t: p.replace(s, s.replace("<span ", "<span inert ", 1)),
    "class_outside_the_list": lambda p, s, t: p.replace(
        s, s.replace('class="bound-text"', 'class="bound-text sr-only"', 1)),
    "second_sheet_that_hides": lambda p, s, t: p.replace(
        "<main>", "<style>[data-bound]{display:none}</style><main>"),
    "linked_sheet": lambda p, s, t: p.replace(
        "<main>", '<link rel="stylesheet" href="x.css"><main>'),
    "sheet_changed_one_byte": lambda p, s, t: p.replace("color:#fff;", "color:#000;", 1),
    "sentence_reworded": lambda p, s, t: p.replace(
        "has not been examined", "has been examined"),
    "sentence_dropped": lambda p, s, t: p.replace(s, ""),
    "binding_dropped": lambda p, s, t: p.replace(s, "<span>" + t + "</span>"),
    "binding_in_script": lambda p, s, t: p.replace(s, "<script>" + t + "</script>"),
    "binding_in_template": lambda p, s, t: p.replace(s, "<template>" + t + "</template>"),
    "binding_in_noscript": lambda p, s, t: p.replace(s, "<noscript>" + t + "</noscript>"),
    "text_moved_into_a_hidden_child": lambda p, s, t: p.replace(
        s, s.replace(">" + t + "<", '><b hidden>' + t + "</b><")),
    "figure_retyped": lambda p, s, t: p.replace('data-bound="run.attempt">',
                                                'data-bound="run.attempt">9'),
    "comment_added": lambda p, s, t: p.replace("<main>", "<!-- ok --><main>"),
    "trailing_whitespace": lambda p, s, t: p + "\n",
    "leading_bom": lambda p, s, t: "﻿" + p,
    "script_removed": lambda p, s, t: p[:p.index("<script>")],
    "script_extended": lambda p, s, t: p.replace("check();\n", "check(); void 0;\n", 1),
    "title_changed": lambda p, s, t: p.replace("<title>Nightly gauntlet</title>",
                                               "<title>Fine</title>"),
    "meta_added": lambda p, s, t: p.replace("<title>", '<meta name="robots" content="x"><title>'),
    "tag_case": lambda p, s, t: p.replace("<main>", "<MAIN>").replace("</main>", "</MAIN>"),
    "section_swapped": lambda p, s, t: p.replace('<section id="run">', '<section id="runs">'),
    "text_in_the_page_unbound": lambda p, s, t: p.replace(
        "</main>", "<p>All variants passed.</p></main>"),
}
CASES = {**ASTRA_CASES, **EARLIER_CASES}


@pytest.mark.parametrize("label", sorted(CASES))
def test_r6_every_altered_page_is_a_finding(world, page, label):
    span, text = bound_span(page, SCOPE_PATH)
    altered = CASES[label](page, span, text)
    assert altered != page, "the edit did not apply; the case is vacuous"
    found = validate.check_transcription(altered, world.report)
    assert [f.code for f in found] == ["PAGE_NOT_THE_RENDER"], label


def test_r6_there_are_seven_astra_cases_and_they_are_all_here():
    assert sorted(ASTRA_CASES) == sorted([
        "closed_dialog", "closed_details", "svg_defs", "sibling_overlay",
        "duplicate_renderer_sheet", "script_hiding", "scope_dialog_descendant"])


def test_r6_a_page_for_a_report_that_cannot_be_rendered_is_refused_whole(world, page):
    broken = copy.deepcopy(world.report)
    broken["identities"] = 7
    found = validate.check_transcription(page, broken)
    assert [f.code for f in found] == ["PAGE_REPORT_NOT_RENDERABLE"]


def test_r6_a_page_that_is_not_text_is_a_finding(world):
    for bad in (None, b"<html>", 7, ["x"]):
        assert [f.code for f in validate.check_transcription(bad, world.report)] == [
            "PAGE_NOT_THE_RENDER"]


def test_r6_the_finding_names_where_the_page_first_differs(world, page):
    altered = page.replace("What our own adversarial harness proved last night", "All good")
    found = validate.check_transcription(altered, world.report)
    assert "line 12" in found[0].detail or re.search(r"line \d+", found[0].detail)
    assert "All good" in found[0].detail


# ---------------------------------------------------------------------------------------- R7
def test_r7_the_table_names_what_render_reads_and_the_page_comes_from_its_view(world, page,
                                                                               monkeypatch):
    view, problems = schema.render_view(world.report)
    assert problems == []
    marked = copy.deepcopy(view)
    marked["run"]["id"] = "FROM-THE-VIEW"
    monkeypatch.setattr(schema, "render_view", lambda report: (marked, []))
    shown = render.render(world.report, findings=[])
    assert "FROM-THE-VIEW" in shown and "FROM-THE-VIEW" not in page


def test_r7_a_field_the_table_does_not_name_never_reaches_the_page(world, page):
    """A field the table does not name is added to every object the table describes."""
    padded = copy.deepcopy(world.report)
    added = 0
    for path, kind in [((), schema.REPORT_READS)] + list(table_paths(schema.REPORT_READS, padded)):
        inner = kind[1] if isinstance(kind, tuple) and kind[0] in ("opt", "nul") else kind
        if isinstance(inner, tuple) and inner[0] == "list":
            inner = inner[1]
        if not isinstance(inner, dict):
            continue
        node = padded
        for part in path:
            node = node[part]
        for target in (node if isinstance(node, list) else [node]):
            target["zz_extra"] = "<script>alert(1)</script>"
            added += 1
    assert added >= 8
    shown = render.render(padded, findings=[])
    assert shown == page and "alert(1)" not in shown


def fits(value, kind):
    """Is `value` what the table says `kind` is. The spec restated, not the code under test."""
    if isinstance(kind, tuple):
        wrap, inner = kind
        if wrap in ("opt", "nul") and value is None:
            return True
        if wrap in ("opt", "nul"):
            return fits(value, inner)
        if wrap == "list":
            return isinstance(value, list) and all(fits(item, inner) for item in value)
        return isinstance(value, dict) and all(
            isinstance(key, str) and fits(item, inner) for key, item in value.items())
    if isinstance(kind, dict):
        return isinstance(value, dict)
    if kind == schema.TEXT:
        return isinstance(value, str)
    if kind == schema.WHOLE:
        return isinstance(value, int) and not isinstance(value, bool)
    if kind == schema.NUMBER:
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, dict)


def wrong_for(kind):
    """Values that are not what `kind` is, for a field that is present."""
    return [bad for bad in (True, False, 1, 2.5, "x", [], [1], {}, {"k": [1]}, {"k": "x"})
            if not fits(bad, kind)]


def table_paths(table, node, prefix=()):
    """(path tuple, kind) for every field of the table that the report holds."""
    for key, kind in table.items():
        if not isinstance(node, dict) or key not in node:
            continue
        yield prefix + (key,), kind
        inner = kind[1] if isinstance(kind, tuple) and kind[0] in ("opt", "nul") else kind
        if isinstance(inner, dict):
            yield from table_paths(inner, node[key], prefix + (key,))
        elif isinstance(inner, tuple) and inner[0] == "list" and isinstance(node[key], list) \
                and node[key] and isinstance(inner[1], dict):
            yield from table_paths(inner[1], node[key][0], prefix + (key, 0))


def with_value(report, path, bad):
    mutated = copy.deepcopy(report)
    node = mutated
    for part in path[:-1]:
        node = node[part]
    node[path[-1]] = bad
    return mutated


def path_text(path):
    out = ""
    for part in path:
        out += f"[{part}]" if isinstance(part, int) else (f".{part}" if out else part)
    return out


def test_r7_every_field_the_table_names_is_typed_by_the_validator(world, norun, closed_norun):
    checked = 0
    for report in (world.report, norun.report, closed_norun[0]):
        for path, kind in table_paths(schema.REPORT_READS, report):
            for bad in wrong_for(kind):
                found = validate.validate_report(with_value(report, path, bad))
                where = path_text(path)
                assert any(f.code == "REPORT_FIELD_TYPE" and (
                    f.path == where or f.path.startswith((where + ".", where + "[")))
                    for f in found), (where, bad)
                checked += 1
    assert checked >= 400


def test_r7_the_seven_identities_cases_and_the_absent_and_empty_ones(norun):
    base = norun.report
    for bad in (None, 7, 1.5, "x", True, [], [1]):
        mutated = copy.deepcopy(base)
        mutated["identities"] = bad
        found = validate.validate_report(mutated)
        assert any(f.code == "REPORT_FIELD_TYPE" and f.path.startswith("identities")
                   for f in found), bad
        with pytest.raises(render.WillNotRender):
            render.render(mutated)
    absent = copy.deepcopy(base)
    del absent["identities"]
    empty = copy.deepcopy(base)
    empty["identities"] = {}
    for mutated in (absent, empty):
        assert "REPORT_FIELD_TYPE" in codes(validate.validate_report(mutated))
        with pytest.raises(render.WillNotRender):
            render.render(mutated)


BAD_VALUES = [None, False, 1, 1.5, "x", [], [1], {}, {"k": [1]}]


def report_paths(node, prefix=()):
    """The mutation set ASTRA used: every key to depth three, and the first item of each list."""
    if isinstance(node, dict):
        for key, value in node.items():
            yield prefix + (key,)
            if len(prefix) < 3:
                yield from report_paths(value, prefix + (key,))
    elif isinstance(node, list) and node and len(prefix) < 3:
        yield prefix + (0,)
        yield from report_paths(node[0], prefix + (0,))


def report_mutations(report):
    for path in report_paths(report):
        node = report
        for part in path:
            node = node[part]
        for bad in BAD_VALUES:
            if type(node) is type(bad):
                continue
            yield path, bad


def test_r7_the_report_mutation_set_gives_no_exception_in_validate_or_render(world, norun):
    cases = failed = refused = accepted = 0
    for report in (world.report, norun.report):
        for path, bad in report_mutations(report):
            mutated = with_value(report, path, bad)
            cases += 1
            found = validate.validate_report(mutated)               # never raises
            assert isinstance(found, list)
            if found:
                with pytest.raises(render.WillNotRender):           # and nothing else
                    render.render(mutated)
                refused += 1
            else:
                assert isinstance(render.render(mutated), str), (path, bad)
                accepted += 1
    # 1681 on the row 17 head. Row 23 removed the detail keys the honest reports used to carry,
    # so the same walk is 40 cases shorter.
    assert cases >= 1641, cases
    assert refused > accepted > 0


def test_r7_a_validated_report_always_renders_and_the_render_is_the_page(world, norun):
    for report in (world.report, norun.report):
        assert validate.validate_report(report) == []
        page = render.render(report)
        assert validate.check_transcription(page, report) == []


def test_r7_render_never_raises_anything_but_will_not_render(world, monkeypatch):
    def broken(view):
        raise ZeroDivisionError("a bug in the page builder")
    monkeypatch.setattr(render, "_page", broken)
    with pytest.raises(render.WillNotRender):
        render.render(world.report)


def test_r7_render_of_something_that_is_not_a_report_is_refused_not_raised():
    for bad in (None, 7, "x", [], [{}], {}):
        with pytest.raises(render.WillNotRender):
            render.render(bad)


def test_r7_a_measured_coverage_panel_must_hold_what_the_page_shows(world):
    for chain in (("plan_partition",), ("total",), ("execution_partition",), ("ceiling",)):
        if world.report["coverage"].get("state") not in schema.NUMERIC_STATES:
            pytest.skip("the fixture panel is not measured")
        mutated = copy.deepcopy(world.report)
        del mutated["coverage"][chain[0]]
        assert validate.validate_report(mutated)
        with pytest.raises(render.WillNotRender):
            render.render(mutated)
