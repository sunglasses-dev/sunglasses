"""The normalization count must come from the code that normalizes.

The README and the site said "17 normalization techniques". No command counted
them and the number sat in stats/current.json by hand. The code has 16 distinct
undos: the keyword lane in preprocessor.normalize_with_length and the regex
lane's wider fold in engine.py, where a wider function undoing the same thing
as a keyword-lane one is the same technique, not another.

preprocessor.NORMALIZATION_STEPS is the list. These tests prove each row on a
crafted input and prove the input needs that row: with the row's functions
turned off, or for an inline row with that line of normalize_with_length
removed, the input no longer folds. A function that undoes two things sits in
two rows and has a probe in each.

What makes a new step fail here, and what does not:
- call guard: a function normalize_with_length calls by bare name (builtins
  aside), and a preprocessor helper engine.py calls by bare name after a
  `from .preprocessor import` or `from sunglasses.preprocessor import` at any
  level, aliases resolved, must be a row's function or a listed non-step.
  Scopes are not tracked: a name imported as different helpers in different
  places counts as a call to every one of them, so a shared name can also make
  a row's function look called when only another helper is;
- fingerprint: FINGERPRINT pins the text of every top-level function in
  preprocessor.py with its decorators, preprocessor.py's import statements, and
  the engine's view builders (VIEW_BUILDERS). Any change to that text fails the
  fingerprint test until the value is updated. It is a review trigger: it says
  the text changed, not that the list was read again;
- neither covers: preprocessor.py's tables and other module-level assignments
  (HOMOGLYPHS, LEET, the compiled patterns), since a new entry widens a row and
  is not a new step; engine code outside VIEW_BUILDERS (scan() builds the same
  views inline) except through the call guard; a helper reached through a module
  attribute (`preprocessor.x(...)`), getattr, or a name bound some other way.
The documents then have to agree with len(NORMALIZATION_STEPS), through
tools/gen_normalization_stats.py.
"""
import ast
import base64
import builtins
import contextlib
import hashlib
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
    ("hidden_separators", "_spaced_text", "ignore\u200bprevious", "ignore previous",
     {"space_ignorable_between_words": NOTHING}),
    # A blank-drawn filler between two Braille cells is the gap between two words.
    ("hidden_separators", "_wide_fold_text", "\u2801\u3164\u2803", "\u2801 \u2803",
     {"strip_ignorable": KEEP}),
    # The Braille blank is drawn as a space and is not whitespace to a regex.
    ("hidden_separators", "_wide_fold_text", "ignore\u2800previous", "ignore previous",
     {"replace_lookalikes": KEEP}),
    ("invisible_characters", "normalize", "ig​nore", "ignore", {"strip_invisible": KEEP}),
    ("invisible_characters", "_wide_fold_text", "ig⁣nore", "ignore", {"strip_ignorable": KEEP}),
    # Circled and mathematical letters: fullwidth ones are also in HOMOGLYPHS, so they prove nothing here.
    ("compatibility_forms", "normalize", "ⓘⓖⓝⓞⓡⓔ", "ignore",
     {"normalize_unicode": KEEP}),
    ("compatibility_forms", "_wide_fold_text", "\U0001d422\U0001d420\U0001d427\U0001d428\U0001d42b\U0001d41e",
     "ignore", {"normalize_unicode": KEEP}),
    ("homoglyphs", "normalize", "іgnore", "ignore", {"replace_homoglyphs": KEEP}),
    ("homoglyphs", "_wide_fold_text", "іgnore", "ignore", {"replace_lookalikes": KEEP}),
    ("homoglyphs", "_wide_fold_text", "rm \u2212rf", "rm -rf", {"replace_lookalikes": KEEP}),
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
    # Both functions fold a run of line breaks, so the control turns off both.
    ("whitespace_runs", "normalize", "ignore\n\nprevious", "ignore previous",
     {"collapse_whitespace": KEEP, "strip_delimiter_padding": KEEP}),
    ("delimiter_padding", "normalize", "i_g_n_o_r_e previous", "ignore previous",
     {"strip_delimiter_padding": KEEP}),
    ("rot13", "normalize", "vtaber cerivbhf", "ignore previous", {"decode_rot13": KEEP}),
    # Inline in normalize_with_length: the control removes the line instead (INLINE).
    ("reversed", "normalize", "suoiverp erongi", "ignore previous", {}),
    ("mixed_case", "normalize", "IgNoRe PrEvIoUs", "ignore previous", {}),
    ("l_for_i", "normalize", "lgnore prevlous", "ignore prev", {}),
]

# What each inline row is in the source of normalize_with_length, and what the
# control puts in its place to turn the row off.
INLINE = {
    "reversed": ("text[::-1]", "text"),
    "mixed_case": ("text = text.lower()", "text = text"),
    "l_for_i": ("re.sub(r'\\bl(?=[a-z])', 'i', text)", "text"),
}

# The engine functions that build the regex lane's views from preprocessor helpers.
VIEW_BUILDERS = ("_fold_text", "_shadow_fold_text", "_compact_text", "_wide_fold_text",
                 "_wide_compact_text", "_spaced_text", "_fold_spaced_text", "_compact_spaced_text")

# sha256 of the pinned sources (_pinned_source). When it changes: read
# NORMALIZATION_STEPS against the change, add or fix a row and its probe if the
# change undoes something new, then put the new value here.
FINGERPRINT = "c1d2a863172055526a442481918b6165fc5b29ad8dd0e9670bad9e22042915dd"


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
    for step, undoes, functions in NORMALIZATION_STEPS:
        assert len(functions) == len(set(functions)), step
        assert undoes and isinstance(functions, tuple), step
        for name in functions:
            assert callable(getattr(preprocessor, name, None)), f"{step}: no preprocessor.{name}"


def test_every_row_has_a_probe_and_each_of_its_functions_is_proven_in_it():
    """Per row: a function that sits in two rows needs a probe in each."""
    rows = _rows()
    assert {p[0] for p in PROBES} == set(rows)
    for step, functions in rows.items():
        proven = {name for p in PROBES if p[0] == step for name in p[4]}
        assert proven == set(functions), f"{step}: no probe turns off {sorted(set(functions) - proven)}"


@pytest.mark.parametrize("step,reader,text,expected,functions", PROBES,
                         ids=[f"{p[0]}-{p[1]}" for p in PROBES])
def test_the_step_folds_its_probe(step, reader, text, expected, functions):
    assert expected not in text
    assert expected in _read(reader, text)


@pytest.mark.parametrize("step,reader,text,expected,functions", [p for p in PROBES if p[4]],
                         ids=[f"{p[0]}-{p[1]}-{i}" for i, p in enumerate(PROBES) if p[4]])
def test_the_probe_needs_its_step(step, reader, text, expected, functions):
    """With the row's function off, no other step folds the probe. A probe some
    neighbour also folds would prove nothing about the row it stands for."""
    with _turned_off(functions):
        assert expected not in _read(reader, text)


def _without_line(marker, replacement):
    """normalize_with_length compiled again with one inline step replaced."""
    source = ast.get_source_segment(PREPROCESSOR_SOURCE, _top_level(PREPROCESSOR_TREE, "normalize_with_length"))
    assert marker in source, f"normalize_with_length no longer has {marker!r}"
    namespace = dict(vars(preprocessor))
    exec(compile(source.replace(marker, replacement), preprocessor.__file__, "exec"), namespace)
    return namespace["normalize_with_length"]


@pytest.mark.parametrize("step,reader,text,expected,functions", [p for p in PROBES if not p[4]],
                         ids=[p[0] for p in PROBES if not p[4]])
def test_the_probe_needs_its_inline_step(step, reader, text, expected, functions):
    assert reader == "normalize"
    assert expected not in _without_line(*INLINE[step])(text)[0]


PREPROCESSOR_SOURCE = pathlib.Path(preprocessor.__file__).read_text()
PREPROCESSOR_TREE = ast.parse(PREPROCESSOR_SOURCE)
ENGINE_SOURCE = pathlib.Path(engine.__file__).read_text()
ENGINE_TREE = ast.parse(ENGINE_SOURCE)


def _top_level(tree, name):
    return next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name)


def _bare_calls(node):
    """Names called by bare name anywhere inside node."""
    return {c.func.id for c in ast.walk(node) if isinstance(c, ast.Call) and isinstance(c.func, ast.Name)}


def test_no_lane_calls_a_function_no_row_names():
    """Both directions: every function a lane calls by bare name is a row's or a
    named non-step, and every function a row names is called by a lane. Python
    builtins aside, the keyword lane may call nothing else by bare name, imported
    or not; the regex lane is every preprocessor helper engine.py imports and
    calls (an import nobody calls is not a lane)."""
    defined = {n.name for n in PREPROCESSOR_TREE.body if isinstance(n, ast.FunctionDef)}
    keyword_lane = _bare_calls(_top_level(PREPROCESSOR_TREE, "normalize_with_length")) - set(dir(builtins))

    # Scopes are not tracked, so a name imported as different helpers in
    # different places stands for all of them.
    local_names = {}
    for node in ast.walk(ENGINE_TREE):
        if isinstance(node, ast.ImportFrom) and (node.module, node.level) in (
                ("preprocessor", 1), ("sunglasses.preprocessor", 0)):
            for alias in node.names:
                local_names.setdefault(alias.asname or alias.name, set()).add(alias.name)
    regex_lane = {f for n in _bare_calls(ENGINE_TREE) for f in local_names.get(n, ())}

    named = {f for functions in _rows().values() for f in functions}
    called = (keyword_lane | regex_lane) - set(NOT_A_STEP)
    assert called - named == set(), f"called by a lane, counted nowhere: {sorted(called - named)}"
    assert named - called == set(), f"counted, called by no lane: {sorted(named - called)}"
    assert set(NOT_A_STEP) <= defined


def _text_with_decorators(source, node):
    lines = source.splitlines()
    first = min([node.lineno] + [d.lineno for d in getattr(node, "decorator_list", [])])
    return "\n".join(lines[first - 1:node.end_lineno])


def _pinned_source():
    parts = [_text_with_decorators(PREPROCESSOR_SOURCE, n) for n in PREPROCESSOR_TREE.body
             if isinstance(n, (ast.FunctionDef, ast.Import, ast.ImportFrom))]
    parts += [_text_with_decorators(ENGINE_SOURCE, _top_level(ENGINE_TREE, name)) for name in VIEW_BUILDERS]
    return "\n\x00\n".join(parts)


def test_the_normalization_code_is_the_code_this_list_was_read_against():
    """Fails on any change to the pinned text (see the module docstring for what
    that is and is not). Read NORMALIZATION_STEPS against the change, then
    update FINGERPRINT."""
    assert hashlib.sha256(_pinned_source().encode()).hexdigest() == FINGERPRINT, (
        "the normalization code changed: check NORMALIZATION_STEPS still lists what it undoes, "
        "then set FINGERPRINT to the new sha256")


def test_every_inline_row_is_still_inline():
    source = ast.get_source_segment(PREPROCESSOR_SOURCE, _top_level(PREPROCESSOR_TREE, "normalize_with_length"))
    inline_rows = {step for step, functions in _rows().items() if not functions}
    assert inline_rows == set(INLINE)
    for step, (marker, _replacement) in INLINE.items():
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
