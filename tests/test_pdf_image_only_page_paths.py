"""Painted pictures that are not a plain Do on the page: names, appearances and glyphs.

Three review findings on the image only page check sit here.

A resource name is read the way the resource dictionary reads it, so a picture drawn
under a name that is not plain ASCII is still found, directly and inside a form. A name
the check cannot match is reported, and a plain name the resources do not hold, which
draws nothing, is not.

The normal appearance of an annotation is a form the page paints, so the pictures in it
count.

A Type3 font paints through its glyph procedures. Which glyphs a page shows is not read,
so a font that the page selects counts when any of its procedures paints a picture. A
font that is only defined, and a procedure that only draws vectors, do not.
"""

import pytest

from test_pdf_image_only_page import _extract, _head, _image, _page, _stream, _write

pytest.importorskip("PyPDF2")

FORM = b"/Type /XObject /Subtype /Form /BBox [0 0 612 792]"


def _warned(result):
    return [w for w in result.warnings if "inspected" in w or "not read" in w]


# 1. Names ---------------------------------------------------------------------------------
NAMES = {
    "ascii": (b"Im0", b"Im0"),
    "utf8": (b"Im\xc3\xa9", b"Im\xc3\xa9"),
    "gbk": (b"Im\xd6\xd0", b"Im\xd6\xd0"),
    "escaped_utf8_in_the_dictionary": (b"Im#c3#a9", b"Im\xc3\xa9"),
    "escaped_utf8_in_the_content": (b"Im\xc3\xa9", b"Im#c3#a9"),
    "escaped_ascii": (b"I#6d0", b"Im0"),
}


def named_pdf(path, key, used, nested):
    if nested:
        objs = _head(3) + [
            _page(b"/XObject << /Fm0 6 0 R >>", contents=4),
            _stream(b"", b"/Fm0 Do"),
            _image(),
            _stream(FORM + b" /Resources << /XObject << /" + key + b" 5 0 R >> >>", b"/" + used + b" Do"),
        ]
        return _write(path, objs)
    objs = _head(3) + [
        _page(b"/XObject << /" + key + b" 5 0 R >>", contents=4),
        _stream(b"", b"q 612 0 0 792 0 0 cm /" + used + b" Do Q"),
        _image(),
    ]
    return _write(path, objs)


@pytest.mark.parametrize("nested", [False, True], ids=["direct", "in_a_form"])
@pytest.mark.parametrize("name", sorted(NAMES))
def test_a_picture_drawn_under_any_spelling_of_its_name_is_found(tmp_path, name, nested):
    key, used = NAMES[name]
    result = _extract(named_pdf(tmp_path / "named.pdf", key, used, nested))
    assert result.complete is False, result.warnings
    assert any("page 1" in w for w in _warned(result)), result.warnings


def test_a_plain_name_the_resources_do_not_hold_draws_nothing(tmp_path):
    result = _extract(named_pdf(tmp_path / "missing.pdf", b"Im0", b"Other", False))
    assert not _warned(result), result.warnings


def test_a_name_that_is_not_plain_and_matches_nothing_is_reported(tmp_path):
    result = _extract(named_pdf(tmp_path / "missing.pdf", b"Im0", b"Im\xc3\xa9", False))
    assert result.complete is False, result.warnings
    assert any("could not be matched" in w for w in result.warnings), result.warnings


# 2. Appearances ---------------------------------------------------------------------------
def appearance_pdf(path, ap, form_resources=b"/XObject << /Im0 6 0 R >>", form_content=b"/Im0 Do"):
    objs = _head(3) + [
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R] >>",
        b"<< /Type /Annot /Subtype /Stamp /Rect [10 10 200 200] " + ap + b" >>",
        _stream(FORM + b" /Resources << " + form_resources + b" >>", form_content),
        _image(),
    ]
    return _write(path, objs)


AP_SHAPES = {
    "one_stream": b"/AP << /N 5 0 R >>",
    "states": b"/AP << /N << /On 5 0 R /Off 5 0 R >> >>",
}


@pytest.mark.parametrize("shape", sorted(AP_SHAPES))
def test_a_picture_in_the_normal_appearance_of_an_annotation_is_found(tmp_path, shape):
    result = _extract(appearance_pdf(tmp_path / "ap.pdf", AP_SHAPES[shape]))
    assert result.complete is False, result.warnings
    assert any("page 1" in w and "image" in w for w in result.warnings), result.warnings


def test_an_annotation_without_an_appearance_adds_no_warning(tmp_path):
    result = _extract(appearance_pdf(tmp_path / "ap.pdf", b"/Contents (a note)"))
    assert not _warned(result), result.warnings


def test_an_appearance_that_only_draws_vectors_and_holds_an_unused_picture_adds_no_warning(tmp_path):
    result = _extract(appearance_pdf(tmp_path / "ap.pdf", AP_SHAPES["one_stream"],
                                     form_content=b"0 0 100 100 re f"))
    assert not _warned(result), result.warnings


def test_more_appearance_states_than_the_bound_are_reported(tmp_path):
    states = b" ".join(b"/S%d 5 0 R" % i for i in range(70))
    result = _extract(appearance_pdf(tmp_path / "ap.pdf", b"/AP << /N << " + states + b" >> >>"))
    assert result.complete is False, result.warnings


# 3. Type3 glyphs --------------------------------------------------------------------------
def type3_pdf(path, content=b"BT /F1 200 Tf 40 400 Td (A) Tj ET", glyph=b"1000 0 d0 q 1000 0 0 1000 0 0 cm /Im0 Do Q",
              glyph_resources=b"/XObject << /Im0 7 0 R >>", page_extra=b""):
    objs = _head(3) + [
        _page(b"/Font << /F1 5 0 R >> " + page_extra, contents=4),
        _stream(b"", content),
        b"<< /Type /Font /Subtype /Type3 /FontBBox [0 0 1000 1000] /FontMatrix [.001 0 0 .001 0 0] "
        b"/CharProcs << /A 6 0 R >> /Encoding << /Type /Encoding /Differences [65 /A] >> "
        b"/FirstChar 65 /LastChar 65 /Widths [1000] /Resources << " + glyph_resources + b" >> >>",
        _stream(b"", glyph),
        _image(),
    ]
    return _write(path, objs)


def test_a_used_type3_font_whose_glyph_paints_a_picture_is_reported(tmp_path):
    result = _extract(type3_pdf(tmp_path / "t3.pdf"))
    assert result.complete is False, result.warnings
    assert any("page 1" in w and "glyph" in w for w in result.warnings), result.warnings


def test_a_used_type3_font_whose_glyph_holds_an_inline_picture_is_reported(tmp_path):
    glyph = b"1000 0 d0 BI /W 2 /H 2 /CS /RGB /BPC 8 ID " + bytes(range(12)) + b" EI"
    result = _extract(type3_pdf(tmp_path / "t3.pdf", glyph=glyph, glyph_resources=b""))
    assert result.complete is False, result.warnings


def test_a_type3_font_that_the_page_never_selects_is_not_reported(tmp_path):
    result = _extract(type3_pdf(tmp_path / "t3.pdf", content=b"BT 40 400 Td ET"))
    assert not _warned(result), result.warnings


def test_a_used_type3_font_whose_glyphs_draw_vectors_and_hold_an_unused_picture_is_not_reported(tmp_path):
    result = _extract(type3_pdf(tmp_path / "t3.pdf", glyph=b"1000 0 d0 0 0 500 500 re f"))
    assert not _warned(result), result.warnings


def test_a_type3_font_in_a_form_is_reported_under_the_page_that_draws_the_form(tmp_path):
    objs = _head(3) + [
        _page(b"/XObject << /Fm0 4 0 R >>", contents=5),
        _stream(FORM + b" /Resources << /Font << /F1 6 0 R >> >>", b"BT /F1 200 Tf (A) Tj ET"),
        _stream(b"", b"/Fm0 Do"),
        b"<< /Type /Font /Subtype /Type3 /FontBBox [0 0 1000 1000] /FontMatrix [.001 0 0 .001 0 0] "
        b"/CharProcs << /A 7 0 R >> /Encoding << /Type /Encoding /Differences [65 /A] >> "
        b"/FirstChar 65 /LastChar 65 /Widths [1000] /Resources << /XObject << /Im0 8 0 R >> >> >>",
        _stream(b"", b"1000 0 d0 /Im0 Do"),
        _image(),
    ]
    result = _extract(_write(tmp_path / "t3form.pdf", objs))
    assert result.complete is False, result.warnings
    assert any("page 1" in w and "glyph" in w for w in result.warnings), result.warnings


def test_a_type3_font_whose_glyph_selects_itself_terminates(tmp_path):
    result = _extract(type3_pdf(tmp_path / "t3.pdf", glyph=b"1000 0 d0 /F1 10 Tf (A) Tj",
                                glyph_resources=b"/Font << /F1 5 0 R >>"))
    assert not _warned(result), result.warnings
