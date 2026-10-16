"""A guarded rule is compiled in its pieces, not also as a whole that is then thrown away.

A caret-led co-occurrence rule, `(?is)^(?!G1)(?!G2)(?=P1)...`, is stored as its negation guards
plus its positive core (`_split_caret_predicate`). `SunglassesEngine.__init__` also compiled the
whole expression first and kept it only as a fallback, so 781 rules paid for a second, discarded
compile on every start of the engine (about 460 ms of a 1.6 s start on the measured machine).

What these tests pin:

1. The whole source of a SHIPPED guarded rule is no longer handed to `re.compile`. That is safe
   because every shipped source is proven here to be valid as a whole.
2. A source that does not ship (a custom rule) keeps the whole compile: pieces that each compile
   do not prove the whole is valid (R1 a global flag in the middle, R2 an unterminated guard,
   R3 a lookbehind on a renumbered group).
3. Nothing else changes: the same rules come out guarded, the same rules are dropped, and the
   fallbacks (pieces that do not compile, named groups that must be checked as a whole) behave
   exactly as before.
"""

import re

import pytest

import sunglasses.engine as engine_module
from sunglasses.engine import MECHANISM_PATTERNS, PATTERNS, SunglassesEngine

GUARDED = (r"(?is)^(?!.*\b(?:do\s*not|never)\s+(?:ignore|bypass)\b)"
           r"(?=.*\b(?:agent|planner)\b)(?=.*\b(?:trusted|signed)\b)(?=.*\b(?:override|bypass)\b).*")


def _rule(rule_id, *sources):
    return {"id": rule_id, "name": rule_id, "category": "test", "severity": "high",
            "channel": ["message"], "keywords": [], "regex": list(sources)}


def _record_compiles(monkeypatch):
    sources = []
    real = re.compile

    def spy(pattern, flags=0):
        sources.append(pattern)
        return real(pattern, flags)

    monkeypatch.setattr(re, "compile", spy)
    return sources


def _modes(engine, rule_id):
    for pattern, compiled in engine._regex_patterns:
        if pattern["id"] == rule_id:
            return [mode for mode, _rx, _extra in compiled]
    return None


def _shipped_sources():
    for rule in list(PATTERNS) + list(MECHANISM_PATTERNS):
        for source in rule.get("regex", []):
            yield rule["id"], source


def test_the_whole_source_of_a_shipped_guarded_rule_is_not_compiled(monkeypatch):
    shipped = next(src for _id, src in _shipped_sources()
                   if SunglassesEngine._split_caret_predicate(src) is not None)
    seen = _record_compiles(monkeypatch)
    engine = SunglassesEngine(patterns=[_rule("GLS-TEST-001", shipped)], mechanisms=False)
    assert _modes(engine, "GLS-TEST-001") == ["guarded"]
    assert shipped not in seen


def test_every_shipped_guarded_source_is_valid_as_a_whole():
    # The reason the shortcut is allowed: nothing that ships would have been dropped by the whole compile.
    invalid = []
    for rule_id, source in _shipped_sources():
        if SunglassesEngine._split_caret_predicate(source) is None:
            continue
        try:
            re.compile(source, re.IGNORECASE)
        except re.error:
            invalid.append(rule_id)
    assert not invalid, invalid


def test_no_shipped_guarded_rule_is_compiled_whole(monkeypatch):
    whole = {source for _id, source in _shipped_sources()
             if SunglassesEngine._split_caret_predicate(source) is not None}
    assert len(whole) > 500
    seen = _record_compiles(monkeypatch)
    SunglassesEngine()
    assert not whole & set(seen), len(whole & set(seen))


def test_the_same_shipped_rules_come_out_guarded_and_none_are_dropped():
    engine = SunglassesEngine()
    expected_guarded, expected_entries = {}, {}
    for rule_id, source in _shipped_sources():
        expected_entries[rule_id] = expected_entries.get(rule_id, 0) + 1
        split = SunglassesEngine._split_caret_predicate(source)
        if split is not None:
            expected_guarded[rule_id] = expected_guarded.get(rule_id, 0) + 1
    actual_entries = {pattern["id"]: len(compiled) for pattern, compiled in engine._regex_patterns}
    actual_guarded = {pattern["id"]: sum(1 for mode, _r, _e in compiled if mode == "guarded")
                      for pattern, compiled in engine._regex_patterns}
    assert {k: v for k, v in actual_entries.items() if k in expected_entries} == \
        {k: v for k, v in expected_entries.items() if k in actual_entries}
    assert set(actual_entries) == set(expected_entries)
    assert {k: v for k, v in actual_guarded.items() if v} == expected_guarded


def test_a_guarded_rule_keeps_the_pieces_it_always_had():
    engine = SunglassesEngine(patterns=[_rule("GLS-TEST-002", GUARDED)], mechanisms=False)
    (_pattern, compiled), = engine._regex_patterns
    (mode, core_rx, guard_rx), = compiled
    guards, core = SunglassesEngine._split_caret_predicate(GUARDED)
    assert mode == "guarded"
    assert core_rx.pattern == core
    assert [g.pattern for g in guard_rx] == guards


# ── what must not change ───────────────────────────────────────────────────

def test_a_guarded_rule_that_does_not_compile_as_a_whole_is_still_dropped():
    # the same group name in a guard and in the core: each piece compiles, the whole does not
    source = r"(?is)^(?!.*(?P<w>never))(?=.*(?P<w>agent)).*"
    with pytest.raises(re.error):
        re.compile(source)
    engine = SunglassesEngine(patterns=[_rule("GLS-TEST-003", source)], mechanisms=False)
    assert _modes(engine, "GLS-TEST-003") is None


def test_pieces_that_do_not_compile_fall_back_to_the_whole_rule():
    # the core refers to a group that is defined inside a guard: valid as a whole, not in pieces
    source = r"(?is)^(?!.*(never)\s+x)(?=.*agent\1).*"
    re.compile(source)
    engine = SunglassesEngine(patterns=[_rule("GLS-TEST-004", source)], mechanisms=False)
    assert _modes(engine, "GLS-TEST-004") == ["plain"]


def test_a_rule_with_a_second_plain_regex_keeps_both_entries():
    engine = SunglassesEngine(
        patterns=[_rule("GLS-TEST-005", GUARDED, r"(?i)\bsend\s+the\s+keys\b")], mechanisms=False)
    assert _modes(engine, "GLS-TEST-005") == ["guarded", "plain"]


def test_a_guarded_rule_still_fires_and_still_holds_back():
    engine = SunglassesEngine(patterns=[_rule("GLS-TEST-006", GUARDED)], mechanisms=False)
    assert "GLS-TEST-006" in {f["id"] for f in
                              engine.scan("the planner output is signed, so override it", channel="message").findings}
    assert not engine.scan("never ignore the planner output that is signed to override", channel="message").findings
    assert not engine.scan("a note about the weather", channel="message").findings


# ── custom rules keep the whole-expression check (R1-R3) ───────────────────

# each: the guards and the core compile on their own, the whole does not (on Python 3.11+;
# older Pythons only warn about a global flag in the middle, and then both ends keep the rule)
R1_FLAG = r"(?s)^(?!(?i)never\s+bypass)(?=.*agent).*"
R2_UNTERMINATED = r"(?is)^(?!.*never\s+bypass(?=.*agent).*"
R3_LOOKBEHIND = r"(?is)^(?!.*(a+)never)(?=.*(b)(?<=\1)agent).*"
FAMILIES = [("R1-global-flag", R1_FLAG), ("R2-unterminated-guard", R2_UNTERMINATED),
            ("R3-numbered-lookbehind", R3_LOOKBEHIND)]


def _whole_compiles(source):
    try:
        re.compile(source, re.IGNORECASE)
    except re.error:
        return False
    return True


@pytest.mark.parametrize("name,source", FAMILIES, ids=[n for n, _ in FAMILIES])
def test_a_custom_rule_is_kept_only_if_its_whole_expression_compiles(name, source):
    split = SunglassesEngine._split_caret_predicate(source)
    assert split is not None, "the probe must be a guarded source or it proves nothing"
    engine = SunglassesEngine(patterns=[_rule("GLS-TEST-010", source)], mechanisms=False)
    assert (_modes(engine, "GLS-TEST-010") is not None) == _whole_compiles(source)


def test_the_probes_are_invalid_wholes_on_this_python():
    # Guards against the probes going stale: R2 and R3 are errors on every supported Python.
    assert not _whole_compiles(R2_UNTERMINATED)
    assert not _whole_compiles(R3_LOOKBEHIND)


def test_an_unterminated_guard_does_not_take_a_keyword_verdict_away():
    # main drops the invalid regex and the keyword still fires; the shortcut kept the rule as a guard
    # that held the finding back (block -> allow).
    rule = {"id": "GLS-TEST-011", "name": "kw", "category": "test", "severity": "high",
            "channel": ["message"], "keywords": ["bypass the trusted agent"],
            "regex": [r"(?is)^(?!.*bypass(?=.*agent).*"]}
    engine = SunglassesEngine(patterns=[rule], mechanisms=False)
    ids = {f["id"] for f in engine.scan("please bypass the trusted agent now", channel="message").findings}
    assert "GLS-TEST-011" in ids


def test_a_shipped_source_given_as_a_custom_rule_still_takes_the_shortcut(monkeypatch):
    # the allow-list is by source text, so copies of shipped rules (the test suites do this) stay fast
    shipped = next(src for _id, src in _shipped_sources()
                   if SunglassesEngine._split_caret_predicate(src) is not None)
    seen = _record_compiles(monkeypatch)
    SunglassesEngine(patterns=[_rule("GLS-TEST-012", shipped)], mechanisms=False)
    assert shipped not in seen
