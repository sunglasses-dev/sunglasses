"""Row 26. The one residual ASTRA found in rows12-13-r8 (8a2fc0339996).

A mapping in the table could be declared without a kind for its keys. `_cut` checked a key only
when the declaration carried one, so the keys of such a mapping were free text that reached the
typed view unchecked. The two mappings the table declares today both carry a key kind, so no
report could show it yet, but a mapping added later, or a key kind dropped from the ceiling, passed
validation with zero findings and the key reached the page.

Same class as row 24, one level down. A key is text, so it declares a kind like any other text.
A mapping whose declaration carries no key kind is a problem in the typed view, so a
`REPORT_FIELD_TYPE` finding and a refusal, whatever the report holds under it.

Cases 1 and 2 are ASTRA's own (r8_extra.py), carried here as tests. Each test was written first
and run against c0699eda, where the ones that name the defect are RED.
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

UNBOUND = "unbound sentence"
CEILING = ("coverage", "ceiling", "unclassified")


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


def maps_of(kind, path=()):
    """(path, declaration) for every mapping the table declares."""
    if isinstance(kind, tuple) and kind[0] in ("opt", "nul", "list"):
        yield from maps_of(kind[1], path)
    elif isinstance(kind, tuple) and kind[0] == "map":
        yield path, kind
        yield from maps_of(kind[1], path + ("*",))
    elif isinstance(kind, dict):
        for key, sub in kind.items():
            yield from maps_of(sub, path + (key,))


def with_table(monkeypatch, edit):
    table = copy.deepcopy(schema.REPORT_READS)
    edit(table)
    monkeypatch.setattr(schema, "REPORT_READS", table)


def ceiling_node(report):
    node = report
    for key in CEILING:
        node = node[key]
    return node


def rekey(report, new_key=UNBOUND):
    node = ceiling_node(report)
    node[new_key] = node.pop(next(iter(node)))
    return report


# ------------------------------------------------------- the table: every mapping names its key kind
def test_every_mapping_in_the_table_declares_a_key_kind():
    found = list(maps_of(schema.REPORT_READS))
    assert len(found) >= 2, found
    for path, decl in found:
        assert len(decl) == 3 and isinstance(decl[2], schema.Kind), (path, decl)


def test_the_text_leaf_walk_reads_keys_as_well_as_values():
    keyless = {"a": schema._opt(schema._map(schema.WHOLE))}
    assert list(table_text_leaves(keyless)) == [("a", "<keys>")]
    text_keyed = {"a": schema._map(schema.WHOLE, schema.TEXT)}
    assert list(table_text_leaves(text_keyed)) == [("a", "<keys>")]
    kinded = {"a": schema._map(schema.WHOLE, schema.OP_KEY)}
    assert list(table_text_leaves(kinded)) == []
    assert list(table_text_leaves(schema.REPORT_READS)) == []


# ------------------------------------------------------------------- r8 case 1, a new keyless mapping
def test_a_new_mapping_with_no_key_kind_is_a_finding_and_is_refused(norun, monkeypatch):
    with_table(monkeypatch, lambda t: t["run"].update(added_map=schema._map(schema.WHOLE)))
    report = copy.deepcopy(norun.report)
    report["run"]["added_map"] = {UNBOUND: 1}
    view, problems = schema.render_view(report)
    assert any(p == "run.added_map" and "key kind" in why for p, why in problems), problems
    assert "added_map" not in view["run"]
    found = findings_under(report, ("run", "added_map"))
    assert found and {f.code for f in found} == {"REPORT_FIELD_TYPE"}
    with pytest.raises(render.WillNotRender):
        render.render(report)
    with pytest.raises(render.WillNotRender):
        render.render(report, findings=[])


def test_the_defect_is_the_declaration_so_an_empty_mapping_is_the_same_finding(norun, monkeypatch):
    with_table(monkeypatch, lambda t: t["run"].update(added_map=schema._map(schema.WHOLE)))
    report = copy.deepcopy(norun.report)
    report["run"]["added_map"] = {}
    assert findings_under(report, ("run", "added_map"))


# ----------------------------------------------------- r8 case 2, the ceiling with its key kind dropped
def drop_ceiling_key_kind(table):
    ceiling = table["coverage"]["ceiling"][1]
    mapping = ceiling["unclassified"][1]
    ceiling["unclassified"] = schema._opt(schema._map(mapping[1]))


def test_the_ceiling_without_its_key_kind_is_a_finding_and_is_refused(norun, monkeypatch):
    with_table(monkeypatch, drop_ceiling_key_kind)
    report = rekey(copy.deepcopy(norun.report))
    view, problems = schema.render_view(report)
    assert any(p == "coverage.ceiling.unclassified" and "key kind" in why
               for p, why in problems), problems
    assert UNBOUND not in str(view)
    found = findings_under(report, CEILING[:1] + CEILING[1:])
    assert found and {f.code for f in found} == {"REPORT_FIELD_TYPE"}
    with pytest.raises(render.WillNotRender):
        render.render(report)
    with pytest.raises(render.WillNotRender):
        render.render(report, findings=[])


def test_the_ceiling_without_its_key_kind_is_a_finding_on_an_honest_report_too(norun, monkeypatch):
    with_table(monkeypatch, drop_ceiling_key_kind)
    assert findings_under(copy.deepcopy(norun.report), CEILING)
    with pytest.raises(render.WillNotRender):
        render.render(norun.report)


@pytest.mark.parametrize("keys", [schema.WHOLE, schema.TEXT, "text", None],
                         ids=["whole", "bare_text", "string", "none"])
def test_a_key_declaration_that_is_not_a_kind_is_the_same_finding(norun, monkeypatch, keys):
    def edit(table):
        mapping = table["coverage"]["ceiling"][1]["unclassified"][1]
        table["coverage"]["ceiling"][1]["unclassified"] = schema._opt(("map", mapping[1], keys))
    with_table(monkeypatch, edit)
    problems = schema.render_view(copy.deepcopy(norun.report))[1]
    assert any(p == "coverage.ceiling.unclassified" and "key kind" in why for p, why in problems)


# ------------------------------------------------------------------------------ the controls
def test_the_committed_declaration_refuses_an_unbound_key(norun):
    report = rekey(copy.deepcopy(norun.report))
    assert findings_under(report, CEILING)
    with pytest.raises(render.WillNotRender):
        render.render(report)


def test_the_honest_reports_pass_and_the_page_holds_no_unbound_text(norun, world):
    for built in (norun, world):
        assert schema.render_view(built.report)[1] == []
        assert validate.validate_report(built.report) == []
        page = render.render(built.report)
        assert validate.check_transcription(page, built.report) == []
        assert separate(page) == 0


def test_the_committed_key_kinds_still_fit_what_the_producer_writes(norun, world):
    for built in (norun, world):
        for key in (ceiling_node(built.report) or {}):
            assert schema.OP_KEY.fits(key), key
        counts = ((built.report.get("routes") or [{}])[0].get("execution") or {}).get("counts") or {}
        for key in counts:
            assert key in schema.EXEC_STATES, key
