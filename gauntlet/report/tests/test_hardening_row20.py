"""Row 20. The one residual ASTRA found in rows12-13-r5 (a9d6f887825a).

A refusal report's freshness value was checked non empty only, and the page embedded it as JSON
inside the script element with no encoding for that place. A crafted value closed the script
element and wrote a separate sentence the report never made, and both validation and the byte
equality check accepted the page because it was the renderer's own output.

The class is fixed, not the field. Every report value reaches the page through one encoder for the
place it lands (`render._text`, `render._attr`, `render._data`), a test reads the renderer's syntax
tree to hold that, and a sweep puts a hostile string into every string the report holds. The
freshness value is also held to the same parse rule an executed report is held to.

Case 0 and its honest positive control are ASTRA's own (extra_checks.py case 0 and
extra_negative_control.py), carried here as tests. Each test was written first and run against
ee8fb98a, where the ones that name the defect are RED.
"""
import ast
import copy
import json
import pathlib
import re
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

UNREADABLE = "FRESHNESS_MEASURED_AT_UNREADABLE"

REAL_VIEW = schema.render_view


@pytest.fixture(autouse=True)
def _encoders_alone(monkeypatch):
    """Row 24 made the typed view refuse a text field that is not its declared kind, so a hostile
    string in such a field no longer reaches the renderer at all. This file tests the encoders as
    their own layer, so it hands the renderer the raw report and skips the typed view as it skips
    the validator. The validator still runs wherever a test calls render.render without
    `findings=[]`, so every refusal asserted here is still the validator's."""
    monkeypatch.setattr(schema, "render_view", lambda report: (copy.deepcopy(report), []))

CLAIM = schema.STANDIN_SCOPE_SENTENCE
HOSTILE = '"><script>X</script><b id="y" onclick="z">&lt;\'</b><!--  '
SCRIPT_BODY = re.compile(r"<script>(.*?)</script>", re.S)
EMBEDDED = re.compile(r"var d = (\{.*?\});\n", re.S)


class Shape(HTMLParser):
    """What a markup parser sees, reduced to tag names, attribute names, the element a piece of
    text sits in, and how many script elements the page has."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.tags, self.attrs, self.stack, self.texts = set(), set(), [], []
        self.scripts = 0

    def handle_starttag(self, tag, attrs):
        self.tags.add(tag)
        self.attrs.update(name for name, _ in attrs)
        self.scripts += tag == "script"
        self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag in self.stack:
            del self.stack[len(self.stack) - 1 - self.stack[::-1].index(tag):]

    def handle_data(self, data):
        self.texts.append((data, self.stack[-1] if self.stack else None))


def shape(page):
    parsed = Shape()
    parsed.feed(page)
    return parsed


def case_zero(report):
    """ASTRA's case 0. The value closes the element the text sits in, then states the examiner's
    sentence inside a fresh element of the same kind, so it reads as a separate assertion."""
    probe = copy.deepcopy(report)
    probe["freshness"]["measured_at"] = "R20_MARKER"
    parent = max(((len(t), el) for t, el in shape(render.render(probe, findings=[])).texts
                  if "R20_MARKER" in t), default=(0, "script"))[1]
    value = f"</{parent}><{parent}>{CLAIM}</{parent}>"
    out = copy.deepcopy(report)
    out["freshness"]["measured_at"] = value
    return out


def separate_claims(page):
    return sum(1 for text, _ in shape(page).texts if text == CLAIM)


def embedded_value(page):
    """What the page's script reads, decoded the way the script engine would decode it."""
    return json.loads(EMBEDDED.search(page).group(1))


# ---------------------------------------------------------------- case 0 and its positive control
def test_case0_the_refusal_report_with_a_crafted_freshness_value_is_a_finding(norun):
    report = case_zero(norun.report)
    found = validate.validate_report(report)
    assert UNREADABLE in {f.code for f in found if f.path == "freshness.measured_at"}
    with pytest.raises(render.WillNotRender):
        render.render(report)


def test_case0_even_past_the_validator_the_page_has_no_separate_assertion(norun):
    """The encoder is its own layer. This is the renderer alone, with the validator skipped."""
    report = case_zero(norun.report)
    page = render.render(report, findings=[])
    assert separate_claims(page) == 0
    assert shape(page).scripts == 1 and page.count("</script>") == 1
    assert embedded_value(page)["measured_at"] == report["freshness"]["measured_at"]


def test_case0_positive_control_the_instrument_sees_the_defect_when_the_encoder_is_taken_out(
        norun, monkeypatch):
    """Without this the test above could pass because the parser sees nothing at all. The same
    report is rendered with the encoder swapped for the bare json.dumps the page used before, and
    the separate assertion appears."""
    report = case_zero(norun.report)
    monkeypatch.setattr(render, "_data", lambda value: json.dumps(value, sort_keys=True))
    assert separate_claims(render.render(report, findings=[])) == 1


def test_case0_honest_control_an_honest_report_renders_validates_and_embeds_its_value(
        norun, world):
    for report in (norun.report, world.report):
        assert validate.validate_report(report) == []
        page = render.render(report)
        assert validate.check_transcription(page, report) == []
        assert embedded_value(page)["measured_at"] == report["freshness"]["measured_at"]
        assert separate_claims(page) == (1 if "execution_run" in report else 0)


# ------------------------------------------------------------------- the freshness parse rule
def at_measured_at(report, value):
    """A string that is not a date is named for what it is. An empty or wrong typed value is
    already a finding of its own (no measurement time, or a field of the wrong type)."""
    found = {f.code for f in validate.validate_report(report) if f.path == "freshness.measured_at"}
    return UNREADABLE in found if value and isinstance(value, str) else bool(found)


NOT_DATES = ["R5B", "<b>", "2026-13-45", "yesterday", "2026-10-05 25:00", 5, 1.5, True, [], {},
             ["2026-10-05T00:00:00+00:00"]]


@pytest.mark.parametrize("value", NOT_DATES, ids=[repr(v) for v in NOT_DATES])
def test_a_measurement_time_that_is_not_a_date_is_a_finding_on_a_refusal_report(norun, value):
    report = copy.deepcopy(norun.report)
    report["freshness"]["measured_at"] = value
    assert at_measured_at(report, value)
    with pytest.raises(render.WillNotRender):
        render.render(report)


@pytest.mark.parametrize("value", NOT_DATES, ids=[repr(v) for v in NOT_DATES])
def test_a_measurement_time_that_is_not_a_date_is_a_finding_on_an_executed_report_too(world, value):
    report = copy.deepcopy(world.report)
    report["freshness"]["measured_at"] = value
    assert at_measured_at(report, value)


def test_an_empty_measurement_time_keeps_its_own_code(norun):
    report = copy.deepcopy(norun.report)
    report["freshness"]["measured_at"] = ""
    found = validate.validate_report(report)
    assert "FRESHNESS_NO_MEASURED_AT" in codes(found) and UNREADABLE not in codes(found)


@pytest.mark.parametrize("value", ["2026-10-05T00:00:00+00:00", "2026-10-05T00:00:00",
                                   "2026-10-05T07:15:00-07:00", "2026-10-05"])
def test_a_date_the_executed_report_parser_reads_passes_on_a_refusal_report(norun, value):
    report = copy.deepcopy(norun.report)
    report["freshness"]["measured_at"] = value
    assert UNREADABLE not in codes(validate.validate_report(report))
    assert validate._when(value) is not None


def test_the_one_parse_rule_is_the_one_the_executed_check_uses():
    """Both checks call `_when`, so they cannot disagree about what a date is."""
    tree = ast.parse(pathlib.Path(validate.__file__).read_text())
    callers = {fn.name for fn in ast.walk(tree) if isinstance(fn, ast.FunctionDef)
               for node in ast.walk(fn) if isinstance(node, ast.Call)
               and isinstance(node.func, ast.Name) and node.func.id == "_when"}
    assert {"_validate_report", "_validate_execution"} <= callers


# ------------------------------------------------------------------ the encoders themselves
def test_the_data_encoder_leaves_no_markup_character_and_decodes_to_the_same_value():
    value = {"a": HOSTILE, "b": ["<", ">", "&", "</script>", "<!--", "]]>"], "c": 1.5, "d": None}
    text = render._data(value)
    assert not set("<>&") & set(text)
    assert json.loads(text) == value


def test_the_text_and_attribute_encoders_leave_no_markup_character_or_quote():
    for encode in (render._text, render._attr):
        out = encode(HOSTILE)
        assert not set('<>"\'') & set(out.replace("&lt;", "").replace("&gt;", "")
                                      .replace("&quot;", "").replace("&#x27;", "")
                                      .replace("&amp;", ""))


def test_there_is_exactly_one_encoder_per_place_and_no_old_one_left():
    names = {n for n in dir(render) if n in ("_esc", "_text", "_attr", "_data")}
    assert names == {"_text", "_attr", "_data"}


# ------------------------------------------------------ the audit of every insertion in render.py
ENCODERS = {"_text", "_attr", "_data"}
BUILDERS = {"_figure", "_bound_text", "_bound_or_not", "_state_note", "_coverage_section",
            "_routes_section", "_execution_block", "_ledger_lines"}
RENDER_TREE = ast.parse(pathlib.Path(render.__file__).read_text())


ASSIGNED = {}
for _node in ast.walk(RENDER_TREE):
    if isinstance(_node, ast.Assign) and all(isinstance(t, ast.Name) for t in _node.targets):
        for _target in _node.targets:
            ASSIGNED.setdefault(_target.id, []).append(_node.value)


def is_markup(node):
    return isinstance(node, ast.Constant) and isinstance(node.value, str) and "<" in node.value


def allowed(node):
    """A piece of a page is a literal, an encoder's output, a builder's output (which is built
    from encoders by this same rule) or a name that only ever holds one of those. Nothing else."""
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.Name):
        # a name is as safe as everything assigned to it
        values = ASSIGNED.get(node.id)
        return bool(values) and all(allowed(v) for v in values)
    if isinstance(node, ast.IfExp):
        return allowed(node.body) and allowed(node.orelse)
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Name):
            return func.id in ENCODERS | BUILDERS
        if (isinstance(func, ast.Attribute) and func.attr == "join"
                and isinstance(func.value, ast.Constant)):
            return True                                     # "".join(parts), parts audited below
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return allowed(node.left) and allowed(node.right)
    if isinstance(node, ast.JoinedStr):
        return all(allowed(v.value) for v in node.values if isinstance(v, ast.FormattedValue))
    return False


def html_fragments():
    """Every expression in render.py that is markup or is put into markup."""
    for node in ast.walk(RENDER_TREE):
        if isinstance(node, ast.JoinedStr) and any(
                is_markup(part) for part in node.values):
            yield node
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add) and any(
                is_markup(side) for side in (node.left, node.right)):
            yield node
        elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
              and node.func.attr == "append" and node.args):
            yield node.args[0]
        elif isinstance(node, ast.List):
            yield from node.elts


def test_the_audit_walks_something():
    assert sum(1 for _ in html_fragments()) > 40


def test_every_value_put_into_markup_goes_through_the_encoder_for_its_place():
    bad = [ast.unparse(node)[:90] for node in html_fragments()
           if not allowed(node) and not isinstance(node, ast.List)]
    assert bad == []


def test_a_raw_value_in_a_markup_string_would_be_caught_by_the_audit():
    """The audit is not blind. Each of these is what the old page did or what a new line might do."""
    for source in ('f"<p>{value}</p>"', '"<p>" + value + "</p>"', 'f"<b>{html_mod.escape(v)}</b>"',
                   'f"<script>var d = {json.dumps(v)};</script>"', 'f"<i>{str(v)}</i>"'):
        node = ast.parse(source, mode="eval").body
        assert not allowed(node), source
    ASSIGNED["raw_name"] = [ast.parse("json.dumps(v)", mode="eval").body]
    ASSIGNED["safe_name"] = [ast.parse("_data(v)", mode="eval").body]
    assert not allowed(ast.parse('f"<p>{raw_name}</p>"', mode="eval").body)
    assert allowed(ast.parse('f"<p>{safe_name}</p>"', mode="eval").body)
    for source in ('f"<p>{_text(value)}</p>"', '"<p>" + _attr(v) + "</p>"',
                   'f"<script>var d = {_data(v)};</script>"'):
        assert allowed(ast.parse(source, mode="eval").body), source


def test_the_page_function_inserts_json_only_through_the_data_encoder():
    page_fn = next(n for n in RENDER_TREE.body
                   if isinstance(n, ast.FunctionDef) and n.name == "_page")
    dumps = [n for n in ast.walk(page_fn) if isinstance(n, ast.Attribute) and n.attr == "dumps"]
    assert dumps == []
    assert any(isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id == "_data"
               for n in ast.walk(page_fn))


# ----------------------------------------------- the sweep, a hostile string in every string leaf
def string_leaves(value, path=()):
    if isinstance(value, str):
        yield path
    elif isinstance(value, dict):
        for key in value:
            yield from string_leaves(value[key], path + (key,))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from string_leaves(item, path + (index,))


def put(report, path, value):
    out = copy.deepcopy(report)
    node = out
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return out


def leaf_cases(report):
    # The embedded run document is not read by the page at all (the table says OBJECT), so a
    # string inside it cannot land anywhere.
    return [p for p in string_leaves(report) if p[0] != "execution_run"]


@pytest.mark.parametrize("which", ["norun", "world"])
def test_a_hostile_string_in_any_string_the_report_holds_cannot_change_the_markup(
        request, which):
    report = request.getfixturevalue(which).report
    base = shape(render.render(report))
    leaves = leaf_cases(report)
    assert len(leaves) > 20
    for path in leaves:
        page = render.render(put(report, path, HOSTILE), findings=[])
        parsed = shape(page)
        where = ".".join(map(str, path))
        assert HOSTILE not in page, where
        assert parsed.scripts == 1 and page.count("</script>") == 1, where
        assert parsed.tags <= base.tags, (where, parsed.tags - base.tags)
        assert parsed.attrs <= base.attrs, (where, parsed.attrs - base.attrs)
        assert separate_claims(page) <= separate_claims(render.render(report)), where
        embedded_value(page)                                # the script data still parses


def test_the_sweep_would_catch_the_old_page(norun, monkeypatch):
    """The sweep above is red against the page that json.dumps'd with no encoding."""
    monkeypatch.setattr(render, "_data", lambda value: json.dumps(value, sort_keys=True))
    path = ("freshness", "measured_at")
    page = render.render(put(norun.report, path, HOSTILE), findings=[])
    assert not (shape(page).scripts == 1 and page.count("</script>") == 1)


# --------------------------------------------------------------- R6 equality and the R7 view
def test_exact_transcription_is_still_one_comparison(norun):
    page = render.render(norun.report)
    assert validate.check_transcription(page, norun.report) == []
    assert validate.check_transcription(page + " ", norun.report)
    assert render.render(norun.report) == render.render(copy.deepcopy(norun.report))


def test_the_render_view_table_is_untouched_by_the_encoders(norun):
    view, problems = REAL_VIEW(norun.report)
    assert problems == [] and set(view) <= set(schema.REPORT_READS)
