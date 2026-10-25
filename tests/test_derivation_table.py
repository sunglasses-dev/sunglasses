"""The shipped derivation table is a speed-up that must never change how a rule is built.

`sunglasses/_derivation_table.py` holds two answers the engine would otherwise derive from
the text of each shipped rule regex on every start: how a caret-led predicate splits into
guards and a core, and, for a rule that asks for anchored mode, whether its regex contains a
lookaround and the longest match it can make. A wrong entry does not slow the scanner down,
it builds a rule with the wrong guards or the wrong window. So these tests ask:

  * is the shipped module exactly what the generator writes now (a stale table fails HERE,
    on every Python version CI runs),
  * is every entry what a live derivation says, and does the table hold every source that
    has an answer,
  * does an engine built from the table hold the same rules as one built without it,
  * is a source that does not ship with the package never read from the table,
  * does a change to the module after the engine read it change nothing.

Regenerate with `python3 scripts/gen_derivation_table.py`.
"""
import importlib.util
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from sunglasses import _derivation_table as shipped_module   # noqa: E402
from sunglasses import _prefilter                             # noqa: E402
from sunglasses import engine as engine_module                # noqa: E402
from sunglasses.engine import SunglassesEngine                # noqa: E402


def _load_generator():
    spec = importlib.util.spec_from_file_location(
        "gen_derivation_table", ROOT / "scripts" / "gen_derivation_table.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


GEN = _load_generator()
EMPTY = (types.MappingProxyType({}), types.MappingProxyType({}))


def _held():
    return engine_module._derivation_table()


def _rules(engine):
    """Every compiled rule an engine holds, as plain data: mode, source, guards or twin."""
    out = {}
    for pattern, compiled in engine._regex_patterns:
        rows = []
        for mode, rx, extra in compiled:
            if mode == "guarded":
                extra = tuple(g.pattern for g in extra)
            elif mode == "leadin":
                extra = extra.pattern
            rows.append((mode, rx.pattern, extra))
        out[pattern["id"]] = rows
    return out


@pytest.fixture(scope="module")
def sources():
    found = sorted(engine_module._shipped_regex_sources())
    assert len(found) > 1000, "no shipped regex sources; every check below would pass on nothing"
    return found


@pytest.fixture(scope="module")
def anchored(sources):
    found = GEN.anchored_sources()
    assert found, "no shipped rule asks for anchored mode; the anchor checks would pass on nothing"
    return found


def test_the_shipped_module_is_what_the_generator_writes_now():
    current = pathlib.Path(shipped_module.__file__).read_text(encoding="utf-8")
    assert current == GEN.build(), "run: python3 scripts/gen_derivation_table.py"


def test_the_staleness_check_fails_when_one_entry_is_changed(monkeypatch, tmp_path, capsys):
    current = pathlib.Path(shipped_module.__file__).read_text(encoding="utf-8")
    key = next(iter(shipped_module.SPLIT))
    stale = tmp_path / "_derivation_table.py"
    monkeypatch.setattr(GEN, "TABLE_PATH", stale)
    stale.write_text(current, encoding="utf-8")
    monkeypatch.setattr(GEN, "ROOT", tmp_path)
    assert GEN.main(["--check"]) == 0
    stale.write_text(current.replace("%r: (" % key, "%r: (9" % key, 1), encoding="utf-8")
    assert GEN.main(["--check"]) == 1
    assert "STALE" in capsys.readouterr().out


def test_every_split_the_table_holds_is_what_a_live_derivation_says(sources):
    for source in sources:
        live = SunglassesEngine._split_caret_predicate(source)
        assert engine_module._shipped_split(source) == live, source


def test_the_table_holds_every_shipped_source_that_splits_and_no_other(sources):
    splitting = {_prefilter.table_key(s) for s in sources
                 if SunglassesEngine._split_caret_predicate(s) is not None}
    assert splitting, "no shipped source splits"
    assert set(_held()[0]) == splitting


def test_every_anchor_fact_the_table_holds_is_what_a_live_derivation_says(anchored):
    for source in anchored:
        assert engine_module._shipped_anchor(source) == (
            _prefilter.has_lookaround(source), _prefilter.max_match_length(source)), source


def test_the_table_holds_every_shipped_source_that_asks_for_anchored_mode_and_no_other(anchored):
    assert set(_held()[1]) == {_prefilter.table_key(s) for s in anchored}


def test_an_engine_built_from_the_table_holds_the_rules_an_engine_built_without_it_holds(monkeypatch):
    with_table = SunglassesEngine()
    monkeypatch.setattr(engine_module, "_DERIVATION_TABLE", EMPTY)
    without = SunglassesEngine()
    assert _rules(with_table) == _rules(without)
    assert with_table._anchor_spec == without._anchor_spec
    assert with_table._anchor_refusals == without._anchor_refusals
    assert any(mode == "guarded" for rows in _rules(with_table).values() for mode, _, _ in rows)
    assert with_table._anchor_spec, "no anchored rule was built; the comparison above holds nothing about anchors"


GUARDED = r"(?i)^(?!.*never obey)(?=.*alpha)(?=.*omega).*"
CUSTOM_ANCHORED = r"(?i)\bcustom marker\b.{0,10}\bobject\b"


def _custom_pattern(regex, **extra):
    return {"id": "CUSTOM-1", "name": "custom", "category": "test", "severity": "high",
            "keywords": [], "regex": [regex], "channel": ["message"], **extra}


def test_a_custom_rule_is_never_read_from_the_table(monkeypatch):
    seen = []
    real = engine_module._derivation_table

    def spy():
        seen.append(1)
        return real()

    monkeypatch.setattr(engine_module, "_derivation_table", spy)
    assert engine_module._shipped_split(GUARDED) is None
    assert engine_module._shipped_anchor(CUSTOM_ANCHORED) is None
    assert not seen


def test_a_custom_rule_is_split_and_windowed_as_before():
    engine = SunglassesEngine(patterns=[
        _custom_pattern(GUARDED),
        {**_custom_pattern(CUSTOM_ANCHORED), "id": "CUSTOM-2", "anchor_terms": ["custom marker"]},
    ], mechanisms=False, validators=False)
    rules = _rules(engine)
    assert [m for m, _, _ in rules["CUSTOM-1"]] == ["guarded"]
    assert [m for m, _, _ in rules["CUSTOM-2"]] == ["anchored"]


def test_a_change_to_the_module_after_the_engine_read_it_changes_nothing(monkeypatch, sources, anchored):
    split_before = {s: engine_module._shipped_split(s) for s in sources}
    anchor_before = {s: engine_module._shipped_anchor(s) for s in anchored}
    key = next(iter(shipped_module.SPLIT))
    anchor_key = next(iter(shipped_module.ANCHOR))
    assert shipped_module.ANCHOR[anchor_key] != (True, 1)
    monkeypatch.setitem(shipped_module.SPLIT, key, (0, (), 0))
    monkeypatch.setitem(shipped_module.ANCHOR, anchor_key, (True, 1))
    assert {s: engine_module._shipped_split(s) for s in sources} == split_before
    assert {s: engine_module._shipped_anchor(s) for s in anchored} == anchor_before


def test_the_mappings_the_engine_holds_reject_assignment():
    for held in _held():
        with pytest.raises(TypeError):
            held["x"] = None


def test_a_module_that_cannot_be_imported_leaves_every_answer_to_a_live_derivation(monkeypatch):
    monkeypatch.setattr(engine_module, "_DERIVATION_TABLE", None)
    monkeypatch.setitem(sys.modules, "sunglasses._derivation_table", None)
    monkeypatch.delattr(sys.modules["sunglasses"], "_derivation_table")
    try:
        assert engine_module._derivation_table() == ({}, {})
        assert engine_module._shipped_split(next(
            s for s in engine_module._shipped_regex_sources()
            if SunglassesEngine._split_caret_predicate(s) is not None)) is None
    finally:
        monkeypatch.setattr(engine_module, "_DERIVATION_TABLE", None)


def _anchored_rule(engine):
    """(rule id, entry index, source) of one shipped rule built in anchored mode."""
    for pattern, compiled in engine._regex_patterns:
        for index, (mode, rx, _extra) in enumerate(compiled):
            if mode == "anchored":
                return pattern["id"], index, rx.pattern
    raise AssertionError("no shipped rule is built in anchored mode")


def test_the_engine_acts_on_the_anchor_facts_the_table_holds(monkeypatch):
    rule, index, source = _anchored_rule(SunglassesEngine())
    key = _prefilter.table_key(source)
    anchor = dict(_held()[1])

    anchor[key] = (True, None)
    monkeypatch.setattr(engine_module, "_DERIVATION_TABLE", (_held()[0], types.MappingProxyType(dict(anchor))))
    refused = SunglassesEngine()
    assert "lookahead or lookbehind" in refused._anchor_refusals[(rule, index)]

    anchor[key] = (False, 7)
    monkeypatch.setattr(engine_module, "_DERIVATION_TABLE", (_held()[0], types.MappingProxyType(dict(anchor))))
    bounded = SunglassesEngine()
    assert (rule, index) not in bounded._anchor_refusals
    assert bounded._anchor_spec[(rule, index)][1] == 7
