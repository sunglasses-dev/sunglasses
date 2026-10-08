"""Shapes the image only page check does not yet report.

Each row is a strict xfail with the reason it survives. When a row starts to
pass the strict flag fails the run, which is the prompt to move it into
test_pdf_image_only_page.py.
"""

import pytest

from test_pdf_image_only_page import pattern_image_pdf, vector_only_pdf, _extract

pytest.importorskip("PyPDF2")


@pytest.mark.xfail(strict=True, reason="a page painted only with path operators holds no picture to count, so words drawn as outlines read as complete")
def test_vector_only_page_is_reported_unread(tmp_path):
    result = _extract(vector_only_pdf(tmp_path / "vector.pdf"))
    assert result.complete is False


@pytest.mark.xfail(strict=True, reason="a picture drawn inside a tiling pattern is reached through the pattern resources, which the walk does not open")
def test_picture_painted_by_a_pattern_is_reported_unread(tmp_path):
    result = _extract(pattern_image_pdf(tmp_path / "pattern.pdf"))
    assert result.complete is False
