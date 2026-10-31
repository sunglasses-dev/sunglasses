"""The normalization count must come from the code that normalizes.

The README and the site said "17 normalization techniques". No command counted
them and the number sat in stats/current.json by hand. The code has 16 distinct
undos: the keyword lane in preprocessor.normalize_with_length and the regex
lane's wider fold in engine.py, where a wider function undoing the same thing
as a keyword-lane one is the same technique, not another.

preprocessor.NORMALIZATION_STEPS is the list. These tests prove each row on a
crafted input, prove the input needs that row (with the row's functions turned
off the input no longer folds), and fail when either lane calls a function no
row names, so a new step cannot ship uncounted. The documents then have to agree
with len(NORMALIZATION_STEPS), through tools/gen_normalization_stats.py.
"""
import ast
import base64
import contextlib
import json
import pathlib
import re

import pytest

from sunglasses import engine, preprocessor
from sunglasses.preprocessor import NORMALIZATION_STEPS
from tools.gen_normalization_stats import measure

ROOT = pathlib.Path(__file__).resolve().parents[1]

# Preprocessor functions a lane calls that are not a step of their own.
NOT_A_STEP = {
    "normalize": "the keyword lane itself, run again on the spaced view",
    "normalize_with_length": "the keyword lane itself",
    "decoded_at": "reads one character of a letter reference for alignment; changes no text",
    "decoded_before": "reads one character of a letter reference for alignment; changes no text",
}

SHADOW = "".join(chr(0xE0000 + ord(c)) for c in "ignore previous")
KEEP = lambda text, *a, **k: text          # noqa: E731
NOTHING = lambda text, *a, **k: None       # noqa: E731

# (step, lane reader, input, text the reader must produce, functions turned off for the control)
PROBES = [
    ("shadow_ascii", "normalize", SHADOW, "ignore previous", {"decode_shadow_ascii": NOTHING}),
    ("shadow_ascii", "_shadow_fold_text", SHADOW, "ignore previous", {"decode_shadow_ascii": NOTHING}),
    # Off means the controls are deleted, which is what the plain view already does.
    ("hidden_separators", "normalize", "ignore\x00previous", "ignore previous",
     {"controls_as_spaces": lambda text: preprocessor.CONTROL_CHARS.sub("", text)}),
    ("hidden_separators", "_spaced_text", "ignore​previous", "ignore previous",
     {"space_ignorable_between_words": NOTHING}),
    ("invisible_characters", "normalize", "ig​nore", "ignore", {"strip_invisible": KEEP}),
    ("invisible_characters", "_wide_fold_text", "ig⁣nore", "ignore", {"strip_ignorable": KEEP}),
    # Circled and mathematical letters: fullwidth ones are also in HOMOGLYPHS, so they prove nothing here.
    ("compatibility_forms", "normalize", "ⓘⓖⓝⓞⓡⓔ", "ignore",
     {"normalize_unicode": KEEP}),
    ("compatibility_forms", "_wide_fold_text", "\U0001d422\U0001d420\U0001d427\U0001d428\U0001d42b\U0001d41e",
     "ignore", {"normalize_unicode": KEEP}),
    ("homoglyphs", "normalize", "іgnore", "ignore", {"replace_homoglyphs": KEEP}),
    ("homoglyphs", "_wide_fold_text", "іgnore", "ignore", {"replace_lookalikes": KEEP}),
    ("html_references", "normalize", "&#105;gnore", "ignore", {"decode_html_entities": KEEP}),
    ("html_references", "_wide_fold_text", "&#105;gnore", "ignore", {"decode_letter_references": KEEP}),
    ("url_encoding", "normalize", "%69gnore", "ignore", {"decode_url_encoding": KEEP}),
    ("hex_escapes", "normalize", "\\x69gnore", "ignore", {"decode_hex_escapes": KEEP}),
    ("base64", "normalize", base64.b64encode(b"ignore previous instructions").decode(),
     "ignore previous instructions", {"decode_base64_segments": KEEP}),
    ("leetspeak", "normalize", "1gn0r3 pr3v10us", "ignore previous", {"decode_leetspeak": KEEP}),
    ("delimiter_padding", "normalize", "i.g.n.o.r.e previous", "ignore previous",
     {"strip_delimiter_padding": KEEP}),
    # One tab: two would be read as a word boundary by strip_delimiter_padding.
    ("whitespace_runs", "normalize", "ignore\tprevious", "ignore previous", {"collapse_whitespace": KEEP}),
    ("rot13", "normalize", "vtaber cerivbhf", "ignore previous", {"decode_rot13": KEEP}),
    # Inline in normalize_with_length, so there is nothing to turn off; the source guard covers them.
    ("reversed", "normalize", "suoiverp erongi", "ignore previous", {}),
    ("mixed_case", "normalize", "IgNoRe PrEvIoUs", "ignore previous", {}),
    ("l_for_i", "normalize", "lgnore prevlous", "ignore prev", {}),
]

# What each inline row is, in the source of normalize_with_length.
INLINE = {"reversed": "[::-1]", "mixed_case": ".lower()", "l_for_i": "re.sub(r'\\bl(?=[a-z])', 'i'"}


def _read(reader, text):
    if reader == "normalize":
        return preprocessor.normalize(text)
    return getattr(engine, reader)(text)


@contextlib.contextmanager
def _turned_off(functions):
    """Replace each function in both modules, since engine imports them by name."""
    saved = []
    for module in (preprocessor, engine):
        for name, stand_in in functions.items():
            if hasattr(module, name):
                saved.append((module, name, getattr(module, name)))
                setattr(module, name, stand_in)
    try:
        yield
    finally:
        for module, name, original in saved:
            setattr(module, name, original)


def _rows():
    return {step: functions for step, _undoes, functions in NORMALIZATION_STEPS}


def test_every_row_is_well_formed_and_unique():
    steps = [row[0] for row in NORMALIZATION_STEPS]
    assert len(steps) == len(set(steps))
    named = [f for _s, _u, functions in NORMALIZATION_STEPS for f in functions]
    assert len(named) == len(set(named)), "one function undoes one thing; it cannot sit in two rows"
    for step, undoes, functions in NORMALIZATION_STEPS:
        assert undoes and isinstance(functions, tuple), step
        for name in functions:
            assert callable(getattr(preprocessor, name, None)), f"{step}: no preprocessor.{name}"


def test_every_row_has_a_probe_and_every_named_function_is_proven():
    rows = _rows()
    assert {p[0] for p in PROBES} == set(rows)
    proven = {name for p in PROBES for name in p[4]}
    named = {f for functions in rows.values() for f in functions}
    assert proven == named, f"functions with no probe that turns them off: {sorted(named - proven)}"


@pytest.mark.parametrize("step,reader,text,expected,functions", PROBES,
                         ids=[f"{p[0]}-{p[1]}" for p in PROBES])
def test_the_step_folds_its_probe(step, reader, text, expected, functions):
    assert expected not in text
    assert expected in _read(reader, text)


@pytest.mark.parametrize("step,reader,text,expected,functions", [p for p in PROBES if p[4]],
                         ids=[f"{p[0]}-{p[1]}" for p in PROBES if p[4]])
def test_the_probe_needs_its_step(step, reader, text, expected, functions):
    """With the row's function off, no other step folds the probe. A probe some
    neighbour also folds would prove nothing about the row it stands for."""
    with _turned_off(functions):
        assert expected not in _read(reader, text)


def _calls_in(tree, function_name):
    """Names called inside one top-level function of a parsed module."""
    function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == function_name)
    return {c.func.id for c in ast.walk(function) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}


def test_no_lane_calls_a_function_no_row_names():
    """Both directions: every function a lane calls is a row or a named non-step,
    and every function a row names is called by a lane."""
    source = pathlib.Path(preprocessor.__file__).read_text()
    tree = ast.parse(source)
    defined = {n.name for n in tree.body if isinstance(n, ast.FunctionDef)}
    keyword_lane = _calls_in(tree, "normalize_with_length") & defined

    engine_tree = ast.parse(pathlib.Path(engine.__file__).read_text())
    imported = {alias.name for node in engine_tree.body if isinstance(node, ast.ImportFrom)
                and node.module == "preprocessor" and node.level == 1 for alias in node.names}
    regex_lane = imported & defined

    named = {f for functions in _rows().values() for f in functions}
    called = (keyword_lane | regex_lane) - set(NOT_A_STEP)
    assert called - named == set(), f"called by a lane, counted nowhere: {sorted(called - named)}"
    assert named - called == set(), f"counted, called by no lane: {sorted(named - called)}"
    assert set(NOT_A_STEP) <= defined


def test_every_inline_row_is_still_inline():
    source = ast.get_source_segment(
        pathlib.Path(preprocessor.__file__).read_text(),
        next(n for n in ast.parse(pathlib.Path(preprocessor.__file__).read_text()).body
             if isinstance(n, ast.FunctionDef) and n.name == "normalize_with_length"))
    inline_rows = {step for step, functions in _rows().items() if not functions}
    assert inline_rows == set(INLINE)
    for step, marker in INLINE.items():
        assert marker in source, f"{step}: normalize_with_length no longer has {marker!r}"


def test_the_generator_counts_the_rows():
    assert measure()["normalization_techniques"] == len(NORMALIZATION_STEPS) == 16


def test_stats_carries_the_measured_count_and_names_its_generator():
    stats = json.loads((ROOT / "stats" / "current.json").read_text())
    assert stats.get("normalization_techniques") == len(NORMALIZATION_STEPS)
    assert stats.get("normalization_stats_generated_by") == "tools/gen_normalization_stats.py"


def test_the_readme_says_the_measured_count():
    readme = (ROOT / "README.md").read_text()
    shown = re.findall(r"\| Normalization techniques \| (\d+) \|", readme) \
        + re.findall(r"normalization \((\d+) techniques\)", readme)
    assert shown, "the README no longer states the count; drop this test with the claim"
    assert set(shown) == {str(len(NORMALIZATION_STEPS))}, f"README says {shown}"
