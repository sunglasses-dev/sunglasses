"""Lab finding A3: a shape that survives the fix, kept as a strict xfail.

A widget can carry its visible text only in its appearance stream (/AP /N, a content
stream with Tj operators) and no /V. A viewer draws the appearance and a reader sees the
words, but the extractor reads neither page.extract_text() (annotation appearances are not
page content) nor the stream, and nothing is recorded as unread. Reading /AP streams means
running a content stream text extractor on each annotation. That is the image-only page
class (drawn content outside the text layer) and stays open with it.
"""
import pytest

from sunglasses.engine import SunglassesEngine
from test_pdf_containers import Doc, PAYLOAD, _s, _stream


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


@pytest.mark.xfail(strict=True, reason="a widget whose text lives only in its appearance stream is neither read nor reported as unread")
def test_appearance_stream_only_widget_is_found_or_reported_unread(engine, tmp_path):
    d = Doc()
    ap = d.add(_stream(f"/Tx BMC BT /Helv 12 Tf 2 2 Td ({_s(PAYLOAD)}) Tj ET EMC".encode(),
                       b"/Type /XObject /Subtype /Form /BBox [0 0 450 40] "
                       b"/Resources << /Font << /Helv << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >>"))
    d.widget((f"<< /Type /Annot /Subtype /Widget /FT /Tx /T (drawn) /Rect [50 600 500 640] "
              f"/AP << /N {ap} 0 R >> /F 4 >>").encode())
    path = tmp_path / "appearance_only.pdf"
    path.write_bytes(d.build())
    r = engine.scan_file(str(path))
    assert r.threat_found or not r.inspection_complete, (
        f"decision={r.decision!r}, complete={r.inspection_complete}, sources={r.extraction_sources}")


# Locations the review of the fifth round found that are neither read nor recorded. Main
# does not read them either, so none of them is a regression; each is a strict xfail with
# the reason it survives, and each becomes its own follow up.
def _scan_one(engine, tmp_path, data):
    path = tmp_path / "survivor.pdf"
    path.write_bytes(data)
    return engine.scan_file(str(path))


def _found_or_reported(r):
    return r.threat_found or not r.inspection_complete


@pytest.mark.parametrize("key", ["TU", "DV", "RV", "Opt"])
@pytest.mark.xfail(strict=True, reason="a widget that is on a page but in no /AcroForm field tree has only its /V read; its other text keys are neither read nor recorded")
def test_orphan_widget_text_keys_are_found_or_reported_unread(engine, tmp_path, key):
    d = Doc()
    value = f"[({_s(PAYLOAD)})]" if key == "Opt" else f"({_s(PAYLOAD)})"
    d.widget((f"<< /Type /Annot /Subtype /Widget /FT /Tx /T (orphan) /Rect [0 0 1 1] /{key} {value} /F 4 >>").encode(),
             field=False)
    r = _scan_one(engine, tmp_path, d.build())
    assert _found_or_reported(r), (r.decision, r.inspection_complete, r.extraction_sources)


@pytest.mark.xfail(strict=True, reason="the /A action of a field that is in /AcroForm but on no page is not walked")
def test_action_of_a_field_on_no_page_is_found_or_reported_unread(engine, tmp_path):
    d = Doc()
    n = d.add((f"<< /Type /Annot /Subtype /Widget /FT /Btn /T (off) /Rect [0 0 1 1] "
               f"/A << /S /JavaScript /JS ({_s(PAYLOAD)}) >> >>").encode())
    d.fields.append(n)
    r = _scan_one(engine, tmp_path, d.build())
    assert _found_or_reported(r), (r.decision, r.inspection_complete, r.extraction_sources)


@pytest.mark.xfail(strict=True, reason="a file reachable only through the assets of a RichMedia annotation is neither read nor recorded")
def test_rich_media_asset_is_found_or_reported_unread(engine, tmp_path):
    d = Doc()
    stream = d.add(_stream(PAYLOAD.encode(), b"/Type /EmbeddedFile"))
    spec = d.add(f"<< /Type /Filespec /F (a.txt) /EF << /F {stream} 0 R >> >>".encode())
    d.widget((f"<< /Type /Annot /Subtype /RichMedia /Rect [0 0 1 1] "
              f"/RichMediaContent << /Assets << /Names [(a.txt) {spec} 0 R] >> >> >>").encode(), field=False)
    r = _scan_one(engine, tmp_path, d.build())
    assert _found_or_reported(r), (r.decision, r.inspection_complete, r.extraction_sources)


@pytest.mark.xfail(strict=True, reason="a page listed only under /Names /Templates is not a page of the document, so its /AA is not walked")
def test_additional_action_on_a_template_page_is_found_or_reported_unread(engine, tmp_path):
    d = Doc()
    template = d.add((f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 1 1] "
                      f"/AA << /O << /S /JavaScript /JS ({_s(PAYLOAD)}) >> >> >>").encode())
    d.catalog_extra = f"/Names << /Templates << /Names [(t) {template} 0 R] >> >>".encode()
    r = _scan_one(engine, tmp_path, d.build())
    assert _found_or_reported(r), (r.decision, r.inspection_complete, r.extraction_sources)
