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
