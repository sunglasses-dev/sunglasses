"""Shapes the image only page check does not yet report.

Each row is a strict xfail with the reason it survives. When a row starts to
pass the strict flag fails the run, which is the prompt to move it into
test_pdf_image_only_page.py.
"""

import pytest

from test_pdf_image_only_page import _head, _image, _page, _stream, _write, pattern_image_pdf, vector_only_pdf, _extract
from test_pdf_image_only_page_softmask import GROUP, USE

pytest.importorskip("PyPDF2")


@pytest.mark.xfail(strict=True, reason="a page painted only with path operators holds no picture to count, so words drawn as outlines read as complete")
def test_vector_only_page_is_reported_unread(tmp_path):
    result = _extract(vector_only_pdf(tmp_path / "vector.pdf"))
    assert result.complete is False


@pytest.mark.xfail(strict=True, reason="a picture drawn inside a tiling pattern is reached through the pattern resources, which the walk does not open")
def test_picture_painted_by_a_pattern_is_reported_unread(tmp_path):
    result = _extract(pattern_image_pdf(tmp_path / "pattern.pdf"))
    assert result.complete is False


@pytest.mark.xfail(strict=True, reason="a picture drawn by a tiling pattern inside a mask group is reached through the pattern "
                                       "resources, which the walk does not open, in a mask as on a page")
def test_picture_painted_by_a_pattern_inside_a_mask_group_is_reported(tmp_path):
    pattern = _stream(b"/Type /Pattern /PatternType 1 /PaintType 1 /TilingType 1 /BBox [0 0 612 792] "
                      b"/XStep 612 /YStep 792 /Resources << /XObject << /Im0 8 0 R >> >>",
                      b"q 612 0 0 792 0 0 cm /Im0 Do Q")
    group = _stream(GROUP + b" /Resources << /Pattern << /P0 7 0 R >> >>", b"/Pattern cs /P0 scn 0 0 612 792 re f")
    objs = _head(3) + [
        _page(b"/ExtGState << /GS 5 0 R >>", contents=4),
        _stream(b"", USE),
        b"<< /Type /ExtGState /SMask << /S /Luminosity /G 6 0 R >> >>",
        group,
        pattern,
        _image(),
    ]
    result = _extract(_write(tmp_path / "pm.pdf", objs))
    assert result.complete is False
