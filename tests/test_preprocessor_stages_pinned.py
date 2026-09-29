"""Each normalize() stage that had no test of its own is pinned here.

Every fixture is ordinary text. Each test reads one view of the normalized
string, so removing one stage turns only that stage's test red. The plain view
is the text before the first VIEW_SEP. The enrichment views follow it.
"""

import base64

from sunglasses.preprocessor import VIEW_SEP, normalize


def _views(text):
    return [view.strip() for view in normalize(text).split(VIEW_SEP)]


def _plain(text):
    return _views(text)[0]


def test_a_compatibility_ligature_folds_to_its_letters():
    # Fullwidth letters would not do here, since the homoglyph table maps them too.
    assert _plain("ﬁsh tea") == "fish tea"


def test_a_cyrillic_look_alike_becomes_its_latin_letter():
    assert _plain("сoffee") == "coffee"


def test_html_entities_are_decoded():
    assert _plain("fish &amp; chips") == "fish & chips"


def test_percent_encoding_is_decoded():
    assert _plain("green%20tea") == "green tea"


def test_hex_escapes_are_decoded():
    assert _plain("\\x74ea time") == "tea time"


def test_a_tab_becomes_one_space():
    # strip_delimiter_padding already collapses a run of two or more, so a
    # single tab is the case that only collapse_whitespace handles.
    assert _plain("green\ttea") == "green tea"


def test_short_and_long_inputs_are_lowercased():
    assert _plain("Green Tea") == "green tea"
    long_text = "Green Tea " * 300
    assert len(long_text) > 2000
    assert _plain(long_text) == ("green tea " * 300).strip()


def test_a_short_input_gains_a_reversed_view():
    assert "aet neerg" in _views("green tea")


def test_a_short_input_gains_a_shape_view():
    assert "iemon tea" in _views("lemon tea")


def _nested(text, depth):
    for _ in range(depth):
        text = base64.b64encode(text.encode()).decode()
    return text


def test_nested_base64_decodes_three_layers_and_stops_there():
    phrase = "the weather is sunny today"
    assert _plain(_nested(phrase, 3)) == phrase
    four_deep = normalize(_nested(phrase, 4))
    assert phrase not in four_deep
