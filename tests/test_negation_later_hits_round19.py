"""The base64 stop is read from what the pipeline did, not from a second decoder.

Review of the eighteenth round found that the walk's own copy of the entity, percent, hex and base64
steps was not the pipeline. The pipeline's HTML step falls back for the whole input when one
reference cannot be read (a decimal reference of more than 4300 digits makes html.unescape raise,
and the input comes back unchanged), so a name that only an entity step would have rewritten stays
an alphabet run and the base64 step decodes it; the copy, run on the one run, rewrote the name and
saw nothing to decode. Fixing that run by run would have been a third copy of the same code.

The pipeline now says what it decoded. normalize_with_length takes an optional list and the base64
step appends each blob it replaced (the shadow view's own pipeline reports into the same list). The
walk reads that list and nothing else: when the pipeline decoded nothing there is no stop, and when
it decoded something the walk stops at the first stretch of the raw text that could hold a blob.
There is no second decoder to disagree with the first.

The independent statement used throughout: when the walk vouches for a span it stands at view offset
i and raw offset j and claims that view[:i] was made from raw[:j] alone and view[i:] from raw[j:]
alone. The pipeline run on each half has to give each half of the view.
"""
import ast
import base64
import html.entities
import inspect
import textwrap

import pytest

from sunglasses import engine, preprocessor
from sunglasses.engine import _Walk, _ascii_lower
from sunglasses.preprocessor import VIEW_SEP, normalize, normalize_with_length

TAIL = "ordinary sample paragraph"


def _plain(raw):
    return normalize(raw).split(" " + VIEW_SEP + " ")[0]


def _b64(text):
    return base64.b64encode(text.encode()).decode()


def _tags(s):
    return "".join(chr(0xE0000 + ord(c)) for c in s)


def _walk(raw):
    return _Walk(raw, _ascii_lower(raw), _plain(raw))


def _bad_spans(raw, lengths=(1, 16)):
    view = _plain(raw)
    walk = _Walk(raw, _ascii_lower(raw), view)
    bad = 0
    for length in lengths:
        for lo in range(1, len(view) - length + 1):
            if walk.holds(lo, lo + length):
                bad += not (_plain(raw[:walk.j]).strip() == view[:walk.i].strip()
                            and _plain(raw[walk.j:]).strip() == view[walk.i:].strip())
    return bad


# --- the review's construction: one unreadable reference makes the HTML step fall back --------------

NAMES = sorted(n for n in html.entities.html5
               if len(n.rstrip(";")) >= 20 and preprocessor.decode_base64_segments(n) != n)


def test_the_review_construction_exists():
    assert len(NAMES) >= 4, NAMES


@pytest.mark.parametrize("name", NAMES)
def test_a_name_the_html_step_would_have_rewritten_is_still_stopped_at(name):
    raw = "&" + name + ". " + "&#" + "9" * 4301 + ";"
    folded = engine._fold_of(raw)
    assert preprocessor.decode_html_entities(folded) == folded     # the whole-input fallback
    record = []
    normalize_with_length(raw, record)
    assert record, "the pipeline decoded the name as base64"
    assert _walk(raw)._next_stop(0) == 0


# --- the record -------------------------------------------------------------------------------------

def test_the_pipeline_reports_the_blobs_it_decoded():
    blob = _b64("amp;yw " + TAIL)
    record = []
    normalize_with_length("see " + blob + " end", record)
    assert record == [blob]


def test_the_pipeline_reports_nothing_when_it_decoded_nothing():
    for raw in ("ordinary words only", "x" * 40 + "!", "https://example.com/some/path/to/a/page"):
        record = []
        normalize_with_length(raw, record)
        assert record == [], raw


def test_a_blob_decoded_in_a_later_pass_is_reported():
    inner = _b64("amp;yw " + TAIL)
    record = []
    normalize_with_length(_b64(inner), record)
    assert len(record) == 2 and record[1] == inner


def test_a_blob_only_the_shadow_view_decodes_is_reported():
    raw = "first words " + _tags(_b64("amp;yw " + TAIL)) + " last words"
    record = []
    normalize_with_length(raw, record)
    assert record, "the shadow view's pipeline reports into the same list"


def test_asking_for_the_record_changes_nothing_else():
    for raw in ("plain words", "&" + _b64("amp;yw " + TAIL), "tags " + _tags("abc"), "a" * 30):
        assert normalize_with_length(raw) == normalize_with_length(raw, [])


# --- the walk reads the record and nothing else -----------------------------------------------------

@pytest.mark.parametrize("word", [
    "international_and_localization_files",
    "https://example.com/some/path/to/a/page",
    "x" * 40 + "!",
    "ordinaryeverydayverylongwordwithoutanypunctuation",    # 49 letters, decodes to nothing printable
])
def test_when_the_pipeline_decoded_nothing_there_is_no_stop(word):
    raw = "first the words " + word + " and the words after"
    walk = _walk(raw)
    walk._next_escape(0)
    assert walk.stops == []
    assert walk.holds(3, 19)
    start = raw.index(word)
    assert walk.holds(start, start + 8)


def test_when_the_pipeline_decoded_a_blob_the_walk_stops_at_the_first_stretch_that_could_hold_one():
    blob = _b64("amp;yw " + TAIL)
    raw = "please read this first " + "&" + blob + " and then more words"
    walk = _walk(raw)
    assert walk.holds(2, 18), "the words in front are still vouched for"
    assert walk._next_stop(0) == raw.index("&" + blob)
    assert _bad_spans(raw) == 0


def test_a_long_word_the_pipeline_did_not_decode_is_passed_over_when_a_blob_follows():
    # Each run is put to the pipeline on its own, so a long word that decodes to nothing is not a
    # stop even when a blob is decoded later in the same input.
    blob = _b64("amp;yw " + TAIL)
    raw = "words " + "x" * 30 + " more words " + "&" + blob
    walk = _walk(raw)
    assert walk._next_stop(0) == raw.index("&" + blob)
    assert walk.holds(raw.index("x" * 30), raw.index("x" * 30) + 16)
    assert _bad_spans(raw) == 0


def test_when_the_pipeline_gave_up_on_the_whole_input_every_run_with_room_is_a_stop():
    # One unreadable reference makes the HTML step leave the whole input alone, so what a run does
    # depends on the text around it; the walk then stops at the first run that could hold a blob.
    blob = _b64("amp;yw " + TAIL)
    raw = "words " + "x" * 30 + " more " + "&#" + "9" * 4301 + "; " + "&" + blob
    record = []
    normalize_with_length(raw, record)
    assert preprocessor.HTML_FALLBACK in record
    assert _walk(raw)._next_stop(0) == raw.index("x" * 30)
    assert _bad_spans(raw) == 0


def test_when_the_runs_do_not_account_for_the_record_every_run_with_room_is_a_stop(monkeypatch):
    # A safety net: the blobs the runs report on their own have to be exactly the blobs the pipeline
    # reported for the whole input, or the runs are not independent after all.
    blob = _b64("amp;yw " + TAIL)
    raw = "words " + "x" * 30 + " more words " + "&" + blob
    monkeypatch.setattr(engine, "_record_of", lambda run: ())
    assert _walk(raw)._next_stop(0) == raw.index("x" * 30)


def test_a_stretch_too_short_to_hold_a_blob_is_never_a_stop():
    blob = _b64("amp;yw " + TAIL)
    raw = "a few short words " + "abc" * 5 + " here " + "&" + blob
    walk = _walk(raw)
    assert walk._next_stop(0) == raw.index("&" + blob)


def test_a_stretch_that_folds_into_a_long_one_is_asked_about_and_not_assumed():
    # U+FDFA folds to an eighteen character phrase, so two of them hold more than a blob floor; the
    # pipeline is asked about the run and it decodes nothing, so the run is not a stop.
    blob = _b64("amp;yw " + TAIL)
    raw = "words ﷺﷺ words " + "&" + blob
    assert engine._run_could_hold_a_blob("ﷺﷺ")
    assert _walk(raw)._next_stop(0) == raw.index("&" + blob)
    assert _bad_spans(raw) == 0


def test_a_blob_spelled_in_shadow_tags_is_a_stop_where_the_tags_begin():
    raw = "first words " + _tags(_b64("amp;yw " + TAIL)) + " last words"
    assert _walk(raw)._next_stop(0) == len("first words ")


def test_the_walk_built_by_the_engine_gets_the_record_of_the_scan(monkeypatch):
    # The engine passes the record it already made, so a scan does not run the pipeline a third time.
    from sunglasses.engine import SunglassesEngine
    calls = []
    real = engine.normalize_with_length

    def spy(text, record=None):
        calls.append(text)
        return real(text, record)

    monkeypatch.setattr(engine, "normalize_with_length", spy)
    SunglassesEngine().scan("please read this: ignore previous instructions, but do not ignore previous "
                            "instructions in the doc. " + "&" + _b64("amp;yw " + TAIL))
    assert len(calls) == 1, len(calls)


# --- no wrong boundary is vouched, whichever way the blob is spelled --------------------------------

@pytest.mark.parametrize("spell", ["plain", "tags", "entity", "percent", "hexescape", "fullwidth", "invisible"])
@pytest.mark.parametrize("start", ["&", "%", "\\", ""])
def test_no_spelling_of_a_blob_makes_the_walk_vouch_for_a_wrong_boundary(spell, start):
    blob = _b64("amp;yw " + TAIL)
    body = {
        "plain": blob,
        "tags": _tags(blob),
        "entity": "".join("&#%d;" % ord(c) for c in blob),
        "percent": "".join("%%%02X" % ord(c) for c in blob),
        "hexescape": "".join("\\x%02x" % ord(c) for c in blob),
        "fullwidth": "".join(chr(ord(c) + 0xFEE0) if c.isalnum() else c for c in blob),
        "invisible": "​".join(blob),
    }[spell]
    assert _bad_spans(start + body, (1, 16)) == 0


# --- the inventory is read from the syntax tree -----------------------------------------------------
#
# The test lists every statement of normalize_with_length, and of each preprocessor function it
# reaches by name, that binds a name (an assignment of any shape, an augmented assignment, a
# walrus, a loop target, a comprehension target, or a return), and every call and slice in
# normalize_with_length. Each one has a row below. A statement that is not in a row is reported, so
# a step added as a function, as a method call, as a slice, as a concatenation, as a format string
# or through a variable is found whatever its right-hand side looks like. What the test checks is
# that the statements it can see are the statements the rows describe; it does not claim to
# see a step that is made somewhere it does not read.

PRODUCER_STEPS = {
    # writes characters into the plain view that were not in the raw text, or removes some
    "strip_invisible", "normalize_unicode", "replace_homoglyphs", "decode_html_entities",
    "decode_url_encoding", "decode_hex_escapes", "decode_shadow_ascii", "decode_base64_segments",
}
AFTER_THE_PASSES = {"decode_leetspeak", "strip_delimiter_padding", "collapse_whitespace"}
VIEWS_BEHIND_THE_SEPARATOR = {"decode_rot13"}
RECURSION = {"normalize", "normalize_with_length"}
BUILTINS = {"len", "range"}
METHODS_ON_THE_TEXT = {
    "text.replace": "the separator character is read as a blank (recorded as a blank change)",
    "text.lower": "lower-casing after the passes",
    "re.sub": "the l-for-I view, behind the separator",
}
SLICES = {"text[::-1]": "the reversed view, behind the separator"}

_SEP = "' ' + VIEW_SEP + ' '"
STATEMENTS = {
    # normalize_with_length, in order
    "normalize_with_length: text = text.replace(VIEW_SEP, ' ')": "separator read as a blank",
    "normalize_with_length: shadow = decode_shadow_ascii(text)": "producer: shadow view",
    "normalize_with_length: text = strip_invisible(text)": "producer",
    "normalize_with_length: text = normalize_unicode(text)": "producer",
    "normalize_with_length: text = replace_homoglyphs(text)": "producer",
    "normalize_with_length: DECODE_MAX_PASSES = 3": "bound on the loop",
    "normalize_with_length: for _ in range(DECODE_MAX_PASSES)": "the decoding loop",
    "normalize_with_length: before = text": "loop bookkeeping",
    "normalize_with_length: text = decode_html_entities(text, record)": "producer",
    "normalize_with_length: text = decode_url_encoding(text)": "producer",
    "normalize_with_length: text = decode_hex_escapes(text)": "producer",
    "normalize_with_length: text = decode_base64_segments(text, record)": "producer",
    "normalize_with_length: text = decode_leetspeak(text)": "after the passes",
    "normalize_with_length: text = strip_delimiter_padding(text)": "after the passes",
    "normalize_with_length: text = collapse_whitespace(text)": "after the passes",
    "normalize_with_length: folded_length = len(text)": "length gate",
    "normalize_with_length: rot = decode_rot13(text)": "rot13 view, behind the separator",
    "normalize_with_length: text = text + " + _SEP + " + rot": "rot13 view, behind the separator",
    "normalize_with_length: text = text + " + _SEP + " + text[::-1]": "reversed view, behind the separator",
    "normalize_with_length: text = text.lower()": "lower-casing after the passes",
    "normalize_with_length: shape_variant = re.sub('\\\\bl(?=[a-z])', 'i', text)": "l-for-I view",
    "normalize_with_length: text = text + " + _SEP + " + shape_variant": "l-for-I view, behind the separator",
    "normalize_with_length: text = text + " + _SEP + " + normalize_with_length(shadow, record)[0]":
        "shadow view's own pipeline, behind the separator",
    "normalize_with_length: return (text, folded_length)": "the result",
    # the functions it reaches
    "strip_invisible: return INVISIBLE_CHARS.sub('', text)": "producer",
    "normalize_unicode: return unicodedata.normalize('NFKC', text)": "producer",
    "replace_homoglyphs: return ''.join((HOMOGLYPHS.get(c, c) for c in text))": "producer",
    "replace_homoglyphs: comp c in text": "producer",
    "decode_html_entities: return text": "producer (the fallback keeps the whole input)",
    "decode_html_entities: return html.unescape(text)": "producer",
    "decode_url_encoding: return text": "producer (nothing to decode)",
    "decode_url_encoding: return unquote(text)": "producer",
    "decode_hex_escapes: return re.sub('\\\\\\\\x([0-9A-Fa-f]{2})', _hex_sub, text)": "producer",
    "decode_hex_escapes: return text": "producer (nothing to decode)",
    "decode_hex_escapes: return chr(int(match.group(1), 16))": "producer",
    "decode_hex_escapes: return match.group(0)": "producer (left as it was)",
    "decode_shadow_ascii: return SHADOW_ASCII.sub(lambda m: chr(ord(m.group()) - 917504), text)": "producer: shadow view",
    "decode_shadow_ascii: return None": "producer: shadow view",
    "decode_base64_segments: return re.sub('[A-Za-z0-9+/]{20,}={0,2}', _try_decode, text)": "producer (the recorded step)",
    "decode_base64_segments: segment = match.group(0)": "producer",
    "decode_base64_segments: return segment": "producer (left as it was)",
    "decode_base64_segments: decoded = base64.b64decode(segment).decode('utf-8', errors='ignore')": "producer",
    "decode_base64_segments: return decoded": "producer",
    "decode_leetspeak: return ''.join((LEET.get(c, c) for c in text))": "after the passes",
    "decode_leetspeak: comp c in text": "after the passes",
    "strip_delimiter_padding: text = re.sub('\\\\b([a-zA-Z])[.\\\\-_]([a-zA-Z])([.\\\\-_][a-zA-Z])+\\\\b', "
    "lambda m: m.group(0).replace('.', '').replace('-', '').replace('_', ''), text)": "after the passes",
    "strip_delimiter_padding: parts = re.split('(\\\\s{2,})', text)": "after the passes",
    "strip_delimiter_padding: collapsed_parts = []": "after the passes",
    "strip_delimiter_padding: for part in parts": "after the passes",
    "strip_delimiter_padding: collapsed = re.sub('(?<!\\\\w)([a-zA-Z] ){2,}[a-zA-Z](?!\\\\w)', _collapse_spaced_word, part)":
        "after the passes",
    "strip_delimiter_padding: return m.group(0).replace(' ', '')": "after the passes",
    "strip_delimiter_padding: text = ''.join(collapsed_parts)": "after the passes",
    "strip_delimiter_padding: return text": "after the passes",
    "collapse_whitespace: text = re.sub('[\\\\t\\\\r\\\\x0b\\\\x0c]+', ' ', text)": "after the passes",
    "collapse_whitespace: text = re.sub(' {2,}', ' ', text)": "after the passes",
    "collapse_whitespace: return text.strip()": "after the passes",
    "decode_rot13: return codecs.decode(text, 'rot_13')": "rot13 view",
    "decode_rot13: return text": "rot13 view",
}

# The producer rows are exercised by the table in test_negation_later_hits_round18.py.


def _source_of(name, overrides):
    if overrides and name in overrides:
        return overrides[name]
    return inspect.getsource(getattr(preprocessor, name))


def _functions_reached(overrides=None):
    """{name: source} of normalize_with_length and each preprocessor function it reaches by name."""
    seen = {}

    def visit(name):
        if name in seen:
            return
        seen[name] = _source_of(name, overrides)
        for node in ast.walk(ast.parse(textwrap.dedent(seen[name]))):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                target = getattr(preprocessor, node.func.id, None)
                if inspect.isfunction(target) and target.__module__ == preprocessor.__name__:
                    visit(node.func.id)

    visit("normalize_with_length")
    return seen


def _statements(name, source):
    """Every statement in the function that binds a name or returns a value, as 'function: source'."""
    keys = []
    for node in ast.walk(ast.parse(textwrap.dedent(source))):
        if isinstance(node, (ast.Assign, ast.AugAssign, ast.AnnAssign, ast.NamedExpr, ast.Return)):
            keys.append("%s: %s" % (name, ast.unparse(node)))
        elif isinstance(node, (ast.For, ast.AsyncFor)):
            keys.append("%s: for %s in %s" % (name, ast.unparse(node.target), ast.unparse(node.iter)))
        elif isinstance(node, ast.comprehension):
            keys.append("%s: comp %s in %s" % (name, ast.unparse(node.target), ast.unparse(node.iter)))
    return keys


def unlisted_steps(overrides=None):
    """What normalize_with_length and the functions it reaches do that no row names."""
    found = []
    reached = _functions_reached(overrides)
    for name, source in reached.items():
        if name not in PRODUCER_STEPS | AFTER_THE_PASSES | VIEWS_BEHIND_THE_SEPARATOR | RECURSION:
            found.append("function " + name)
        for key in _statements(name, source):
            if key not in STATEMENTS:
                found.append("statement " + key)
    root = ast.parse(textwrap.dedent(reached["normalize_with_length"]))
    for node in ast.walk(root):
        if isinstance(node, ast.Call):
            callee = ast.unparse(node.func)
            if isinstance(node.func, ast.Name):
                if callee not in (PRODUCER_STEPS | AFTER_THE_PASSES | VIEWS_BEHIND_THE_SEPARATOR | RECURSION | BUILTINS):
                    found.append("call " + callee)
            elif callee not in METHODS_ON_THE_TEXT:
                found.append("call " + callee)
        elif isinstance(node, ast.Subscript) and isinstance(node.slice, ast.Slice):
            if ast.unparse(node) not in SLICES:
                found.append("slice " + ast.unparse(node))
    return found


def test_the_pipeline_as_it_is_has_a_row_for_every_step():
    assert unlisted_steps() == []


def test_every_statement_row_names_a_statement_the_pipeline_still_has():
    present = set()
    for name, source in _functions_reached().items():
        present.update(_statements(name, source))
    assert set(STATEMENTS) <= present, sorted(set(STATEMENTS) - present)


_ADDED = [
    "    text = decode_added_step(text)\n",              # a new decoder
    "    text = transform_added_step(text)\n",           # a new transform
    "    text = text.replace(chr(65), chr(66))\n",       # a method call on the text
    "    text = text.swapcase()\n",
    "    text = text.translate({65: 66})\n",
    "    text = text[1:]\n",                             # a slice
    "    step = decode_added_step\n    text = step(text)\n",
    "    text = text + chr(65)\n",                       # a concatenation, no call in it
    "    text = chr(65) + text\n",
    "    text += 'x'\n",                                 # an augmented assignment
    "    text = f'{text}x'\n",                           # a format string
    "    text = '%s!' % text\n",
    "    text = text if text else 'x'\n",                # a conditional expression
    "    text = ''.join(text)\n",
    "    (text := text + 'x')\n",                        # a walrus
    "    shadow = shadow + 'x'\n",                       # the shadow view
    "    other = text\n    text = other + 'x'\n",        # through a second name
]


@pytest.mark.parametrize("line", _ADDED)
def test_a_step_added_to_the_pipeline_without_a_row_is_found(line):
    source = inspect.getsource(preprocessor.normalize_with_length)
    changed = source.replace("    shadow = decode_shadow_ascii(text)", line + "    shadow = decode_shadow_ascii(text)")
    assert changed != source
    assert unlisted_steps({"normalize_with_length": changed}), line


def test_a_new_return_value_is_found():
    source = inspect.getsource(preprocessor.normalize_with_length)
    changed = source.replace("return text, folded_length", "return text + 'x', folded_length")
    assert changed != source
    assert unlisted_steps({"normalize_with_length": changed})


@pytest.mark.parametrize("name,old,new", [
    ("collapse_whitespace", "    return text.strip()", "    text = text + 'x'\n    return text.strip()"),
    ("decode_leetspeak", "    return ", "    text = text + 'x'\n    return "),
    ("strip_invisible", "    return ", "    text = text + 'x'\n    return "),
])
def test_a_statement_added_to_a_function_it_reaches_is_found(name, old, new):
    source = inspect.getsource(getattr(preprocessor, name))
    changed = source.replace(old, new, 1)
    assert changed != source
    assert unlisted_steps({name: changed}), name


def test_every_row_names_a_step_the_pipeline_still_has():
    reached = set(_functions_reached())
    assert (PRODUCER_STEPS | AFTER_THE_PASSES | VIEWS_BEHIND_THE_SEPARATOR) <= reached


# --- the stop is counted, not sorted -----------------------------------------------------------------

class _Counted(str):
    """A blob that counts how often it is asked which of two comes first."""
    asked = 0

    def __lt__(self, other):
        _Counted.asked += 1
        return str.__lt__(self, other)

    __gt__ = __le__ = __ge__ = __lt__


@pytest.mark.parametrize("runs", [128, 1024])
def test_comparing_the_pipeline_record_with_the_runs_asks_no_blob_which_comes_first(runs, monkeypatch):
    raw = " ".join(_b64("sample paragraph number %d" % i) for i in range(runs))
    record = []
    normalize_with_length(raw, record)
    assert len(record) == runs
    record = [_Counted(blob) for blob in record]
    real = engine._record_of
    monkeypatch.setattr(engine, "_record_of", lambda run: tuple(_Counted(b) for b in real(run)))
    _Counted.asked = 0
    stops = engine._stops_of(raw, record)
    assert len(stops) == runs
    assert _Counted.asked == 0


def test_blobs_that_repeat_are_counted_as_often_as_the_pipeline_made_them():
    # Two equal runs are two records; one record against two runs is a mismatch and every run stops.
    blob = _b64("sample paragraph repeated here")
    raw = blob + " " + blob
    record = []
    normalize_with_length(raw, record)
    assert len(record) == 2
    assert len(engine._stops_of(raw, record)) == 2
    assert engine._stops_of(raw, record[:1]) == engine._stops_of(raw, record[:1] * 2)[:2]
