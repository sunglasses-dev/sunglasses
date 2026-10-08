"""Which content counts as a drawn picture, and which form results may be shared.

Three review findings on the image only page check sit here. A form that borrows the
resources of the page that draws it must be read under each page, not once. An inline
image is found whatever order its dictionary keys come in and whatever unknown keys it
carries. Text that only looks like an operator, in a literal string, a hex string, a
comment or the data of an inline image, does not count as a drawn picture.
"""

import pytest

from test_pdf_image_only_page import (
    PIXELS, TEXT_STREAM, _extract, _head, _image, _page, _stream, _write,
)

pytest.importorskip("PyPDF2")

FORM = (b"/Type /XObject /Subtype /Form /BBox [0 0 612 792]")


def borrowed_resources_pdf(path, picture_on_page):
    """Two pages draw one form that has no resources of its own. The form draws /Im0.
    The picture is bound to /Im0 on one page only, and the other page leaves it out."""
    first = b"/XObject << /Fm0 5 0 R >>"
    second = b"/XObject << /Fm0 5 0 R /Im0 6 0 R >>"
    resources = (second, first) if picture_on_page == 1 else (first, second)
    objs = _head(3, 4) + [
        _page(resources[0], contents=7),
        _page(resources[1], contents=8),
        _stream(FORM, b"/Im0 Do"),
        _image(),
        _stream(b"", b"/Fm0 Do"),
        _stream(b"", b"/Fm0 Do"),
    ]
    return _write(path, objs)


def content_pdf(path, content, with_picture_resource=True):
    resources = b"/XObject << /Im0 5 0 R >>" if with_picture_resource else b""
    objs = _head(3) + [_page(resources, contents=4), _stream(b"", content)]
    if with_picture_resource:
        objs.append(_image())
    return _write(path, objs)


@pytest.mark.parametrize("picture_on_page", [1, 2])
def test_a_form_that_borrows_resources_is_read_under_each_page(tmp_path, picture_on_page):
    path = borrowed_resources_pdf(tmp_path / "borrowed.pdf", picture_on_page)
    result = _extract(path)
    assert result.complete is False
    named = [w for w in result.warnings if "image" in w]
    assert len(named) == 1
    assert f"page {picture_on_page}" in named[0]


INLINE_DICTS = {
    "unknown_first_key": b"/Foo 1 /W 2 /H 2 /CS /RGB /BPC 8",
    "unknown_key_in_the_middle": b"/W 2 /Foo (x) /H 2 /CS /RGB /BPC 8",
    "reordered_keys": b"/BPC 8 /CS /RGB /H 2 /W 2",
    "long_key_names": b"/Width 2 /Height 2 /ColorSpace /DeviceRGB /BitsPerComponent 8",
    "unknown_key_with_a_dictionary_value": b"/Foo << /A 1 >> /W 2 /H 2 /CS /RGB /BPC 8",
}


@pytest.mark.parametrize("name", sorted(INLINE_DICTS))
def test_an_inline_image_is_found_whatever_its_dictionary_looks_like(tmp_path, name):
    content = b"q 612 0 0 792 0 0 cm BI " + INLINE_DICTS[name] + b" ID " + PIXELS + b" EI Q"
    result = _extract(content_pdf(tmp_path / "inline.pdf", content, with_picture_resource=False))
    assert result.complete is False
    assert any("page 1" in w for w in result.warnings)


def test_an_inline_image_whose_data_holds_operator_text_counts_once(tmp_path):
    data = b"/Im0 Do BI X"
    assert len(data) == 2 * 2 * 3
    content = b"BI /W 2 /H 2 /CS /RGB /BPC 8 ID " + data + b" EI Q"
    result = _extract(content_pdf(tmp_path / "data.pdf", content))
    assert result.complete is False
    assert any("1 image(s) not read" in w for w in result.warnings), result.warnings


LOOKS_LIKE_A_PICTURE = {
    "literal_string": TEXT_STREAM + b" (the operator /Im0 Do is a draw) Tj",
    "literal_string_with_inline_text": TEXT_STREAM + b" (BI /W 2 /H 2 ID x EI) Tj",
    "nested_parentheses_in_a_string": b"BT (a (b /Im0 Do) c) Tj ET",
    "escaped_parenthesis_in_a_string": b"BT (a \\) /Im0 Do) Tj ET",
    "hex_string": b"BT <2f496d3020446f> Tj ET /Im0",
    "comment": b"% /Im0 Do\n0 0 m",
    "comment_with_inline_text": b"% BI /W 2 /H 2 ID x EI\n0 0 m",
    "name_that_spells_the_operator": b"/Do gs /BI gs",
}


@pytest.mark.parametrize("with_picture_resource", [False, True])
@pytest.mark.parametrize("name", sorted(LOOKS_LIKE_A_PICTURE))
def test_text_that_looks_like_an_operator_is_not_a_drawn_picture(
        tmp_path, name, with_picture_resource):
    path = content_pdf(tmp_path / "text.pdf", LOOKS_LIKE_A_PICTURE[name], with_picture_resource)
    result = _extract(path)
    assert result.complete is True, result.warnings
    assert not result.warnings


def test_a_real_draw_after_a_string_with_an_escaped_parenthesis_is_found(tmp_path):
    content = b"BT (a \\) b) Tj ET q 50 0 0 50 0 0 cm /Im0 Do Q"
    result = _extract(content_pdf(tmp_path / "after.pdf", content))
    assert result.complete is False
    assert any("page 1" in w for w in result.warnings)


def test_a_real_draw_after_a_comment_is_found(tmp_path):
    content = b"% note\n/Im0 Do"
    result = _extract(content_pdf(tmp_path / "after_comment.pdf", content))
    assert result.complete is False


def test_a_comment_between_the_name_and_the_operator_is_skipped(tmp_path):
    content = b"/Im0 % a comment\nDo"
    result = _extract(content_pdf(tmp_path / "split.pdf", content))
    assert result.complete is False
