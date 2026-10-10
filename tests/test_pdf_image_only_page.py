"""A PDF page whose words are stored as a picture is reported as not inspected.

Lab finding E5. A scanned page, or a screenshot printed to PDF, carries no text
objects. The extractor found nothing, raised nothing, and the result said allow
with the inspection marked complete. The image extractor already reports an
incomplete read when it cannot run OCR, and the PDF extractor now does the same
for a page that paints a picture. The pictures are judged apart from the text, so
a page with one stray character and a picture is named too. Only a picture that
the page content draws counts, so an unused resource entry does not. One bounded
visit covers the document, with shared forms read once. No OCR runs by default.
"""

import os
import subprocess
import sys
import zlib

import pytest

from sunglasses.extractors.dispatch import extract_file_sources

pytest.importorskip("PyPDF2")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEXT_STREAM = b"BT /F1 14 Tf 40 700 Td (Quarterly report. Figures are provisional.) Tj ET"
PIXELS = bytes(range(12))  # a 2 by 2 RGB image


def _stream(dict_body, data):
    return b"<< " + dict_body + b" /Length %d >>\nstream\n" % len(data) + data + b"\nendstream"


def _image():
    return _stream(b"/Type /XObject /Subtype /Image /Width 2 /Height 2 "
                   b"/ColorSpace /DeviceRGB /BitsPerComponent 8", PIXELS)


def _write(path, objs):
    """Write a PDF from an ordered list of object bodies. Object 1 is the catalog."""
    out = b"%PDF-1.4\n"
    offsets = []
    for i, obj in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + obj + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    with open(path, "wb") as fh:
        fh.write(out)
    return str(path)


def _page(resources, contents=5):
    return (b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents %d 0 R "
            b"/Resources << " % contents + resources + b" >> >>")


def _head(*pages):
    kids = b" ".join(b"%d 0 R" % p for p in pages)
    return [b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [" + kids + b"] /Count %d >>" % len(pages)]


def image_only_pdf(path):
    objs = _head(3) + [
        _page(b"/XObject << /Im0 4 0 R >>"),
        _image(),
        _stream(b"", b"q 612 0 0 792 0 0 cm /Im0 Do Q"),
    ]
    return _write(path, objs)


def text_pdf(path):
    objs = _head(3) + [
        _page(b"/Font << /F1 4 0 R >>"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        _stream(b"/Filter /FlateDecode", zlib.compress(TEXT_STREAM)),
    ]
    return _write(path, objs)


def text_and_image_pdf(path):
    objs = _head(3) + [
        _page(b"/Font << /F1 4 0 R >> /XObject << /Im0 6 0 R >>"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        _stream(b"", TEXT_STREAM + b" q 50 0 0 50 40 600 cm /Im0 Do Q"),
        _image(),
    ]
    return _write(path, objs)


def image_in_form_pdf(path):
    form = _stream(b"/Type /XObject /Subtype /Form /BBox [0 0 612 792] "
                   b"/Resources << /XObject << /Im0 6 0 R >> >>", b"/Im0 Do")
    objs = _head(3) + [
        _page(b"/XObject << /Fm0 4 0 R >>"),
        form,
        _stream(b"", b"/Fm0 Do"),
        _image(),
    ]
    return _write(path, objs)


def self_referencing_form_pdf(path):
    form = _stream(b"/Type /XObject /Subtype /Form /BBox [0 0 612 792] "
                   b"/Resources << /XObject << /Fm0 4 0 R >> >>", b"/Fm0 Do")
    objs = _head(3) + [
        _page(b"/XObject << /Fm0 4 0 R >>"),
        form,
        _stream(b"", b"/Fm0 Do"),
    ]
    return _write(path, objs)


def invisible_text_and_image_pdf(path):
    """One invisible character (text render mode 3) and a picture on the page."""
    objs = _head(3) + [
        _page(b"/Font << /F1 4 0 R >> /XObject << /Im0 6 0 R >>"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        _stream(b"", b"BT 3 Tr /F1 14 Tf 40 700 Td (x) Tj ET q 612 0 0 792 0 0 cm /Im0 Do Q"),
        _image(),
    ]
    return _write(path, objs)


def unused_image_resource_pdf(path):
    """A blank page whose resources list a picture that the content never draws."""
    objs = _head(3) + [_page(b"/XObject << /Im0 5 0 R >>", contents=4), _stream(b"", b""), _image()]
    return _write(path, objs)


def shared_form_pdf(path, pages=30, entries=1):
    """Many pages drawing one form that holds a picture, through shared resources."""
    first = 3
    form_no, image_no = first + pages, first + pages + 1
    contents0 = image_no + 1
    extra = b" ".join(b"/E%d %d 0 R" % (n, image_no) for n in range(entries))
    shared = b"/XObject << /Fm0 %d 0 R " % form_no + extra + b" >>"
    kids = [_page(shared, contents=contents0 + n) for n in range(pages)]
    form = _stream(b"/Type /XObject /Subtype /Form /BBox [0 0 612 792] "
                   b"/Resources << /XObject << /Im0 %d 0 R >> >>" % image_no, b"/Im0 Do")
    objs = _head(*range(first, first + pages)) + kids + [form, _image()]
    objs += [_stream(b"", b"/Fm0 Do") for _ in range(pages)]
    return _write(path, objs)


def vector_only_pdf(path):
    """A page painted with a filled rectangle only."""
    objs = _head(3) + [_page(b"", contents=4), _stream(b"", b"0 0 612 792 re f")]
    return _write(path, objs)


def pattern_image_pdf(path):
    """A picture painted through a tiling pattern fill."""
    pattern = _stream(b"/Type /Pattern /PatternType 1 /PaintType 1 /TilingType 1 "
                      b"/BBox [0 0 612 792] /XStep 612 /YStep 792 "
                      b"/Resources << /XObject << /Im0 6 0 R >> >>", b"q 612 0 0 792 0 0 cm /Im0 Do Q")
    objs = _head(3) + [
        _page(b"/Pattern << /P0 5 0 R >>", contents=4),
        _stream(b"", b"/Pattern cs /P0 scn 0 0 612 792 re f"),
        pattern,
        _image(),
    ]
    return _write(path, objs)


def blank_pdf(path):
    objs = _head(3) + [_page(b"", contents=4), _stream(b"", b"")]
    return _write(path, objs)


def two_page_pdf(path):
    objs = _head(3, 4) + [
        _page(b"/Font << /F1 6 0 R >>", contents=5),
        _page(b"/XObject << /Im0 7 0 R >>", contents=8),
        _stream(b"", TEXT_STREAM),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        _image(),
        _stream(b"", b"q 612 0 0 792 0 0 cm /Im0 Do Q"),
    ]
    return _write(path, objs)


def inline_image_pdf(path):
    inline = b"q 612 0 0 792 0 0 cm BI /W 2 /H 2 /CS /RGB /BPC 8 ID " + PIXELS + b" EI Q"
    objs = _head(3) + [_page(b"", contents=4), _stream(b"", inline)]
    return _write(path, objs)


def _extract(path):
    return extract_file_sources(str(path))


def test_fixture_page_holds_an_image_and_no_text(tmp_path):
    """Guard the fixture so the other tests prove something."""
    from PyPDF2 import PdfReader

    page = PdfReader(image_only_pdf(tmp_path / "scan.pdf")).pages[0]
    xobjects = page["/Resources"]["/XObject"].get_object()
    kinds = [str(xobjects[k].get_object().get("/Subtype")) for k in xobjects]
    assert kinds == ["/Image"]
    assert page.extract_text().strip() == ""


def test_extractor_names_the_page_it_did_not_read(tmp_path):
    from sunglasses.extractors.pdf import PDFExtractor

    extractor = PDFExtractor()
    extractor.extract(image_only_pdf(tmp_path / "scan.pdf"))
    assert len(extractor.failures) == 1
    assert "page 1" in extractor.failures[0]
    assert "1 image" in extractor.failures[0]


def test_dispatch_marks_the_read_incomplete(tmp_path):
    result = _extract(image_only_pdf(tmp_path / "scan.pdf"))
    assert result.complete is False
    assert any("page 1" in w for w in result.warnings)


def test_engine_scan_file_is_not_a_clean_bill(shared_engine, tmp_path):
    result = shared_engine.scan_file(image_only_pdf(tmp_path / "scan.pdf"))
    assert result.inspection_complete is False
    assert result.extraction_complete is False
    assert any("page 1" in w for w in result.extraction_warnings)


def test_scanner_scan_auto_is_not_a_clean_bill(tmp_path):
    from sunglasses.scanner import SunglassesScanner

    result = SunglassesScanner().scan_auto(image_only_pdf(tmp_path / "scan.pdf"))
    assert result["inspection_complete"] is False
    assert any("page 1" in w for w in result["warnings"])


def test_cli_exits_three_for_an_unread_page(tmp_path):
    pdf = image_only_pdf(tmp_path / "scan.pdf")
    proc = subprocess.run([sys.executable, "-m", "sunglasses.cli", "scan", "--file", pdf],
                          capture_output=True, text=True, cwd=REPO)
    assert proc.returncode == 3, proc.stdout + proc.stderr
    assert "INCOMPLETE" in (proc.stdout + proc.stderr).upper()


def test_image_inside_a_form_is_found(tmp_path):
    result = _extract(image_in_form_pdf(tmp_path / "form.pdf"))
    assert result.complete is False
    assert any("page 1" in w for w in result.warnings)


def test_form_that_contains_itself_terminates(tmp_path):
    result = _extract(self_referencing_form_pdf(tmp_path / "loop.pdf"))
    assert result.complete is True


def test_unread_page_is_named_among_read_pages(tmp_path):
    from sunglasses.extractors.pdf import PDFExtractor

    extractor = PDFExtractor()
    sources = extractor.extract(two_page_pdf(tmp_path / "two.pdf"))
    assert [label for label, _ in sources] == ["page:1"]
    assert len(extractor.failures) == 1
    assert "page 2" in extractor.failures[0]


def test_failures_do_not_carry_over_to_the_next_document(tmp_path):
    from sunglasses.extractors.pdf import PDFExtractor

    extractor = PDFExtractor()
    extractor.extract(image_only_pdf(tmp_path / "scan.pdf"))
    extractor.extract(text_pdf(tmp_path / "text.pdf"))
    assert extractor.failures == []


def test_page_with_text_and_a_picture_names_the_picture(tmp_path):
    from sunglasses.extractors.pdf import PDFExtractor

    extractor = PDFExtractor()
    sources = extractor.extract(text_and_image_pdf(tmp_path / "mixed.pdf"))
    assert [label for label, _ in sources] == ["page:1"]
    assert len(extractor.failures) == 1 and "page 1" in extractor.failures[0]
    result = _extract(text_and_image_pdf(tmp_path / "mixed.pdf"))
    assert result.complete is False
    assert [label for label, _ in result.sources] == ["page:1"]


def test_one_invisible_character_does_not_hide_the_picture(tmp_path):
    result = _extract(invisible_text_and_image_pdf(tmp_path / "invisible.pdf"))
    assert result.complete is False
    assert any("page 1" in w and "1 image" in w for w in result.warnings)


def test_inline_image_page_is_reported_unread(tmp_path):
    result = _extract(inline_image_pdf(tmp_path / "inline.pdf"))
    assert result.complete is False
    assert any("page 1" in w for w in result.warnings)


def test_pages_that_share_a_form_read_it_once(tmp_path, monkeypatch):
    from sunglasses.extractors import pdf as pdf_module
    from sunglasses.extractors.pdf import PDFExtractor

    reads = []
    original = pdf_module._ImageWalk._content
    monkeypatch.setattr(pdf_module._ImageWalk, "_content",
                        lambda self, holder: reads.append(1) or original(self, holder))
    pages = 30
    extractor = PDFExtractor()
    extractor.extract(shared_form_pdf(tmp_path / "shared.pdf", pages=pages, entries=200))
    assert len(extractor.failures) == pages
    assert all("1 image" in f for f in extractor.failures)
    assert len(reads) == pages + 1  # one read per page and a single read of the form


def test_a_long_resource_list_is_not_walked_per_page(tmp_path, monkeypatch):
    from sunglasses.extractors import pdf as pdf_module
    from sunglasses.extractors.pdf import PDFExtractor

    resolved = []
    original = pdf_module._resolve
    monkeypatch.setattr(pdf_module, "_resolve", lambda obj: resolved.append(1) or original(obj))
    small, large = PDFExtractor(), PDFExtractor()
    small.extract(shared_form_pdf(tmp_path / "small.pdf", pages=20, entries=1))
    few = len(resolved)
    resolved.clear()
    large.extract(shared_form_pdf(tmp_path / "large.pdf", pages=20, entries=400))
    assert len(resolved) <= few + 10


def test_content_past_the_limit_marks_the_rest_unread(tmp_path, monkeypatch):
    from sunglasses.extractors import pdf as pdf_module
    from sunglasses.extractors.pdf import PDFExtractor

    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 40)
    extractor = PDFExtractor()
    extractor.extract(shared_form_pdf(tmp_path / "limit.pdf", pages=30))
    stopped = [f for f in extractor.failures if "not checked for images" in f]
    assert len(stopped) == 1
    assert len(extractor.failures) < 30
    assert _extract(shared_form_pdf(tmp_path / "limit.pdf", pages=30)).complete is False


# Controls: shapes that stay complete.

def test_text_page_stays_complete(tmp_path):
    result = _extract(text_pdf(tmp_path / "text.pdf"))
    assert result.complete is True
    assert not result.warnings


def test_blank_page_with_an_unused_picture_resource_stays_complete(tmp_path):
    result = _extract(unused_image_resource_pdf(tmp_path / "unused.pdf"))
    assert result.complete is True
    assert not result.warnings


def test_blank_page_stays_complete(tmp_path):
    result = _extract(blank_pdf(tmp_path / "blank.pdf"))
    assert result.complete is True
    assert not result.warnings


def test_clean_text_pdf_still_exits_zero(tmp_path):
    pdf = text_pdf(tmp_path / "text.pdf")
    proc = subprocess.run([sys.executable, "-m", "sunglasses.cli", "scan", "--file", pdf],
                          capture_output=True, text=True, cwd=REPO)
    assert proc.returncode == 0, proc.stdout + proc.stderr
