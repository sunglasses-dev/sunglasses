"""Fifth round on the PDF containers: nested PDFs without a header, UTF-16 literals,
page text in a large object stream, charged walk work, and three more locations.

Review of the fourth round found these gaps:

* a nested PDF with no "%PDF-" header was read as text, because the reader opens a PDF
  from its cross reference tail and does not need the header;
* a literal string value with UTF-16 units that do not decode became text with NUL
  characters and no failure;
* page text held in an object stream past the attachment bound was no longer read, so
  main blocked the file and this head allowed it;
* walk work was not charged: a shared array re-read for every key, and a shared
  annotation array re-read for every page, cost thousands of times the input;
* an object stream was inflated a second time, uncharged, by the reader;
* script actions on outline items, files listed in /AF and a widget value held on its
  /Parent were neither read nor recorded.
"""
import zlib

import pytest

from PyPDF2.generic import EncodedStreamObject

from sunglasses.engine import SunglassesEngine
from sunglasses.extractors import pdf as pdf_module
from sunglasses.extractors.pdf import PDFExtractor

from test_pdf_containers import (
    PAYLOAD, Doc, _attachment_doc, _build, _inner_pdf, _s, _stream, _warnings,
)

BLOCKING = ("block", "quarantine")


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def _scan(engine, tmp_path, name, data):
    return engine.scan_file(_write(tmp_path, name, data))


def _extract(tmp_path, name, data):
    extractor = PDFExtractor()
    return extractor, extractor.extract(_write(tmp_path, name, data))


def _texts(out):
    return " ".join(t for _, t in out)


# 1. A nested PDF with no header ----------------------------------------------------------
def test_a_nested_pdf_without_a_header_is_named_a_pdf_and_not_read_as_text(engine, tmp_path):
    inner = _inner_pdf().replace(b"%PDF-", b"%ABC-")
    direct = _scan(engine, tmp_path, "direct.pdf", inner)
    assert direct.decision in BLOCKING
    outer = _scan(engine, tmp_path, "outer.pdf", _attachment_doc(_stream(inner, b"/Type /EmbeddedFile"), "inner.pdf"))
    assert not outer.inspection_complete
    assert any("PDF" in w and "not inspected" in w for w in _warnings(outer)), _warnings(outer)


@pytest.mark.parametrize("head", [b"", b"junk\x00\x01", b"%PDF-1.7\n"], ids=["none", "junk", "header"])
def test_the_cross_reference_tail_names_a_pdf_with_or_without_a_header(head):
    body = head + b"1 0 obj << >> endobj\nxref\n0 1\ntrailer << >>\nstartxref\n123\n%%EOF\n"
    assert PDFExtractor._container_kind(body) == "PDF"


def test_text_that_only_mentions_the_markers_stays_text():
    assert PDFExtractor._container_kind(b"The startxref keyword and the %%EOF marker end a PDF.") is None
    assert PDFExtractor._container_kind(b"startxref is followed by an offset") is None


# 2. A literal UTF-16 string that does not decode ----------------------------------------
BAD16 = b"\xfe\xff" + PAYLOAD.encode("utf-16-be") + b"\xd8\x00"
GOOD16 = b"\xfe\xff" + PAYLOAD.encode("utf-16-be")


def _utf16_doc(kind, raw):
    d = Doc()
    if kind == "field":
        d.widget(f"<< /Type /Annot /Subtype /Widget /FT /Tx /T (f) /Rect [0 0 1 1] /V <{raw.hex()}> >>".encode())
    elif kind == "array":
        d.widget(f"<< /Type /Annot /Subtype /Widget /FT /Ch /T (f) /Rect [0 0 1 1] /V [ <{raw.hex()}> ] >>".encode())
    else:
        d.catalog_extra = f"/OpenAction << /S /JavaScript /JS <{raw.hex()}> >>".encode()
    return d.build()


@pytest.mark.parametrize("kind", ["field", "array", "script"])
def test_a_literal_utf16_value_that_does_not_decode_is_recorded(engine, tmp_path, kind):
    r = _scan(engine, tmp_path, f"bad_{kind}.pdf", _utf16_doc(kind, BAD16))
    assert not r.inspection_complete
    assert any("UTF-16" in w for w in _warnings(r)), _warnings(r)
    assert r.decision in BLOCKING        # what does decode is still read


@pytest.mark.parametrize("kind", ["field", "array", "script"])
def test_a_literal_utf16_value_that_decodes_is_read_and_adds_no_warning(engine, tmp_path, kind):
    r = _scan(engine, tmp_path, f"good_{kind}.pdf", _utf16_doc(kind, GOOD16))
    assert r.decision in BLOCKING
    assert not any("UTF-16" in w for w in _warnings(r)), _warnings(r)


# 3. Page text in an object stream larger than the attachment bound -----------------------
def _objstm_pages_doc(pad):
    content = f"BT /F1 12 Tf 50 700 Td ({_s(PAYLOAD)}) Tj ET".encode()
    filed = {1: b"<< /Type /Catalog /Pages 5 0 R >>", 2: b"<< >>", 3: b"<< >>", 4: _stream(content)}
    packed = {5: b"<< /Type /Pages /Kids [6 0 R] /Count 1 >>",
              6: b"<< /Type /Page /Parent 5 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 << /Type /Font "
                 b"/Subtype /Type1 /BaseFont /Helvetica >> >> >> /Contents 4 0 R >>"}
    header, body = b"", b""
    for n, item in packed.items():
        header += f"{n} {len(body)} ".encode()
        body += item + b"\n"
    stm, xr = 7, 8
    out = bytearray(b"%PDF-1.7\n")
    off = {}
    for n, item in filed.items():
        off[n] = len(out)
        out += f"{n} 0 obj\n".encode() + item + b"\nendobj\n"
    off[stm] = len(out)
    out += (f"{stm} 0 obj\n".encode()
            + _stream(zlib.compress(header + body + b" " * pad, 9),
                      f"/Type /ObjStm /N {len(packed)} /First {len(header)} /Filter /FlateDecode".encode())
            + b"\nendobj\n")
    off[xr] = len(out)
    ent = bytearray()
    idx = {n: i for i, n in enumerate(packed)}
    for n in range(xr + 1):
        if n == 0:
            ent += bytes([0, 0, 0, 0, 0, 0xFF, 0xFF])
        elif n in idx:
            ent += bytes([2]) + stm.to_bytes(4, "big") + idx[n].to_bytes(2, "big")
        else:
            ent += bytes([1]) + off[n].to_bytes(4, "big") + b"\x00\x00"
    out += f"{xr} 0 obj\n".encode() + _stream(bytes(ent), f"/Type /XRef /Size {xr + 1} /Root 1 0 R /W [1 4 2]".encode()) + b"\nendobj\n"
    out += f"startxref\n{off[xr]}\n%%EOF\n".encode()
    return bytes(out)


@pytest.mark.parametrize("pad", [0, (1 << 20) + 4096, 6 << 20])
def test_page_text_in_an_object_stream_past_the_attachment_bound_is_read(engine, tmp_path, pad):
    r = _scan(engine, tmp_path, "pages.pdf", _objstm_pages_doc(pad))
    assert r.decision in BLOCKING and r.inspection_complete, _warnings(r)


def test_an_object_stream_past_the_document_budget_is_reported_and_not_inflated(engine, tmp_path, monkeypatch):
    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 1 << 20)
    r = _scan(engine, tmp_path, "pages.pdf", _objstm_pages_doc(4 << 20))
    assert not r.inspection_complete
    assert any("limit" in w or "object stream" in w for w in _warnings(r)), _warnings(r)


def test_an_accepted_object_stream_is_inflated_once(tmp_path, monkeypatch):
    import PyPDF2.filters as filters
    real = filters.decode_stream_data
    native = []

    def counting(stream):
        if stream.get("/Type") == "/ObjStm":
            native.append(1)
        return real(stream)

    monkeypatch.setattr(filters, "decode_stream_data", counting)
    extractor, out = _extract(tmp_path, "pages.pdf", _objstm_pages_doc((1 << 20) + 4096))
    assert PAYLOAD in _texts(out)
    assert native == [], "the reader inflated the object stream a second time"
    assert extractor.budget.read < 2 * ((1 << 20) + 4200)


# 4. Walk work is charged and shared arrays are read once ---------------------------------
def _count_visits(monkeypatch):
    visits = []
    real = PDFExtractor._identity

    def counting(obj):
        visits.append(1)
        return real(obj)

    monkeypatch.setattr(PDFExtractor, "_identity", staticmethod(counting))
    return visits


def test_fields_that_share_one_array_read_it_once(tmp_path, monkeypatch):
    d = Doc()
    arr = d.add(("[" + " ".join(["0"] * 4096) + "]").encode())
    for i in range(100):
        d.fields.append(d.add(
            f"<< /FT /Ch /T (f{i}) /V {arr} 0 R /DV {arr} 0 R /RV {arr} 0 R /TU {arr} 0 R /Opt {arr} 0 R >>".encode()))
    visits = _count_visits(monkeypatch)
    extractor, _ = _extract(tmp_path, "shared.pdf", d.build())
    assert len(visits) < 30_000, len(visits)
    assert extractor.budget.read < 1 << 20


def test_pages_that_share_one_annotation_array_read_each_widget_once(tmp_path, monkeypatch):
    ints = ("[" + " ".join(["0"] * 4096) + "]").encode()
    pages, widgets = 20, 50
    w0 = 6
    wids = list(range(w0, w0 + widgets))
    p0 = w0 + widgets
    pids = list(range(p0, p0 + pages))
    objs = [b"<< /Type /Catalog /Pages 2 0 R >>", None, _stream(b"BT /F1 12 Tf 50 700 Td (x) Tj ET"), ints,
            ("[" + " ".join(f"{w} 0 R" for w in wids) + "]").encode()]
    objs += [b"<< /Type /Annot /Subtype /Widget /Rect [0 0 1 1] /V 4 0 R >>" for _ in wids]
    objs += [b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 3 0 R /Annots 5 0 R >>" for _ in pids]
    objs[1] = ("<< /Type /Pages /Kids [" + " ".join(f"{p} 0 R" for p in pids) + f"] /Count {pages} >>").encode()
    visits = _count_visits(monkeypatch)
    extractor, _ = _extract(tmp_path, "pages.pdf", _build(objs))
    assert len(visits) < 40_000, len(visits)


def test_a_shared_widget_value_is_still_found_once_for_the_document(engine, tmp_path):
    d = Doc()
    shared = d.add(f"[ ({_s(PAYLOAD)}) ]".encode())
    d.widget(f"<< /Type /Annot /Subtype /Widget /FT /Tx /T (a) /Rect [0 0 1 1] /V {shared} 0 R >>".encode())
    d.widget(f"<< /Type /Annot /Subtype /Widget /FT /Tx /T (b) /Rect [0 0 1 1] /V {shared} 0 R >>".encode())
    assert _scan(engine, tmp_path, "shared.pdf", d.build()).decision in BLOCKING


def test_visiting_members_of_distinct_arrays_spends_the_document_budget(tmp_path, monkeypatch):
    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 1 << 20)
    d = Doc()
    for i in range(40):
        arr = d.add(("[" + " ".join(["0"] * 4000) + "]").encode())
        d.fields.append(d.add(f"<< /FT /Ch /T (f{i}) /V {arr} 0 R >>".encode()))
    extractor, _ = _extract(tmp_path, "distinct.pdf", d.build())
    assert any("limit" in f and "not inspected" in f for f in extractor.failures), extractor.failures
    assert extractor.budget.read <= pdf_module._ReadBudget.MAX_BYTES


# 5. Locations that were neither read nor recorded -----------------------------------------
def test_a_script_on_an_outline_item_is_read(engine, tmp_path):
    d = Doc()
    o = d.add(b"<< /Type /Outlines /First 6 0 R /Last 6 0 R /Count 1 >>")
    d.add(f"<< /Title (x) /Parent {o} 0 R /A << /S /JavaScript /JS ({_s(PAYLOAD)}) >> >>".encode())
    d.catalog_extra = f"/Outlines {o} 0 R".encode()
    r = _scan(engine, tmp_path, "outline.pdf", d.build())
    assert r.decision in BLOCKING


def test_a_script_on_a_nested_and_a_later_outline_item_is_read(tmp_path):
    d = Doc()
    o = d.add(b"<< /Type /Outlines /First 6 0 R /Last 7 0 R /Count 2 >>")
    d.add(f"<< /Title (a) /Parent {o} 0 R /Next 7 0 R /First 8 0 R /Last 8 0 R >>".encode())
    d.add(f"<< /Title (b) /Parent {o} 0 R /Prev 6 0 R /A << /S /JavaScript /JS ({_s('later ' + PAYLOAD)}) >> >>".encode())
    d.add(f"<< /Title (c) /Parent 6 0 R /A << /S /JavaScript /JS ({_s('nested ' + PAYLOAD)}) >> >>".encode())
    d.catalog_extra = f"/Outlines {o} 0 R".encode()
    _, out = _extract(tmp_path, "outline.pdf", d.build())
    text = _texts(out)
    assert "later " in text and "nested " in text


def test_an_outline_that_points_back_at_itself_ends(tmp_path):
    d = Doc()
    o = d.add(b"<< /Type /Outlines /First 6 0 R /Last 6 0 R /Count 1 >>")
    d.add(f"<< /Title (a) /Parent {o} 0 R /Next 6 0 R /First 6 0 R >>".encode())
    d.catalog_extra = f"/Outlines {o} 0 R".encode()
    extractor, _ = _extract(tmp_path, "loop.pdf", d.build())
    assert not extractor.failures, extractor.failures


def test_outline_items_past_the_cap_are_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(PDFExtractor, "MAX_OUTLINE_ITEMS", 20)
    d = Doc()
    o = d.add(b"<< /Type /Outlines /First 6 0 R /Count 40 >>")
    for i in range(40):
        nxt = f"/Next {6 + i + 1} 0 R" if i < 39 else ""
        d.add(f"<< /Title (t{i}) /Parent {o} 0 R {nxt} >>".encode())
    d.catalog_extra = f"/Outlines {o} 0 R".encode()
    extractor, _ = _extract(tmp_path, "cap.pdf", d.build())
    assert any("outline items beyond 20" in f for f in extractor.failures), extractor.failures


def test_an_associated_file_listed_only_in_the_catalog_is_read(engine, tmp_path):
    d = Doc()
    st = d.add(_stream(PAYLOAD.encode(), b"/Type /EmbeddedFile"))
    sp = d.add(f"<< /Type /Filespec /F (a.txt) /UF (a.txt) /AFRelationship /Data /EF << /F {st} 0 R >> >>".encode())
    d.catalog_extra = f"/AF [{sp} 0 R]".encode()
    assert _scan(engine, tmp_path, "af.pdf", d.build()).decision in BLOCKING


def test_an_associated_file_that_is_not_text_is_reported(engine, tmp_path):
    d = Doc()
    st = d.add(_stream(b"\x00\x01\x02\x03" * 100, b"/Type /EmbeddedFile"))
    sp = d.add(f"<< /Type /Filespec /F (a.bin) /EF << /F {st} 0 R >> >>".encode())
    d.catalog_extra = f"/AF [{sp} 0 R]".encode()
    r = _scan(engine, tmp_path, "af.pdf", d.build())
    assert not r.inspection_complete and _warnings(r)


def test_a_file_in_both_the_name_tree_and_the_af_array_is_read_once(tmp_path):
    d = Doc()
    st = d.add(_stream(PAYLOAD.encode(), b"/Type /EmbeddedFile"))
    sp = d.add(f"<< /Type /Filespec /F (a.txt) /UF (a.txt) /EF << /F {st} 0 R >> >>".encode())
    d.catalog_extra = (f"/AF [{sp} 0 R] /Names << /EmbeddedFiles << /Names [(a.txt) {sp} 0 R] >> >>").encode()
    _, out = _extract(tmp_path, "both.pdf", d.build())
    assert sum(PAYLOAD in t for _, t in out) == 1


def test_a_widget_outside_the_form_whose_value_sits_on_its_parent_is_read(engine, tmp_path):
    d = Doc()
    par = d.add(f"<< /FT /Tx /T (p) /V ({_s(PAYLOAD)}) >>".encode())
    d.widget(f"<< /Type /Annot /Subtype /Widget /Parent {par} 0 R /Rect [0 0 1 1] >>".encode(), field=False)
    assert _scan(engine, tmp_path, "parent.pdf", d.build()).decision in BLOCKING


def test_a_parent_chain_that_loops_ends(tmp_path):
    d = Doc()
    a = d.add(b"<< /FT /Tx /T (a) /Parent 6 0 R >>")
    d.add(f"<< /FT /Tx /T (b) /Parent {a} 0 R /V ({_s(PAYLOAD)}) >>".encode())
    d.widget(f"<< /Type /Annot /Subtype /Widget /Parent {a} 0 R /Rect [0 0 1 1] >>".encode(), field=False)
    extractor, out = _extract(tmp_path, "loop.pdf", d.build())
    assert PAYLOAD in _texts(out) and not extractor.failures, extractor.failures


def test_a_parent_field_that_the_form_walk_read_is_not_read_twice(tmp_path):
    d = Doc()
    par = d.add(f"<< /FT /Tx /T (p) /V ({_s(PAYLOAD)}) >>".encode())
    d.fields.append(par)
    d.widget(f"<< /Type /Annot /Subtype /Widget /Parent {par} 0 R /Rect [0 0 1 1] >>".encode(), field=False)
    _, out = _extract(tmp_path, "twice.pdf", d.build())
    assert sum(PAYLOAD in t for _, t in out) == 1


def test_a_parent_chain_deeper_than_the_bound_is_reported(tmp_path):
    d = Doc()
    top = d.add(f"<< /FT /Tx /T (t) /V ({_s(PAYLOAD)}) >>".encode())
    prev = top
    for i in range(40):
        prev = d.add(f"<< /T (n{i}) /Parent {prev} 0 R >>".encode())
    d.widget(f"<< /Type /Annot /Subtype /Widget /Parent {prev} 0 R /Rect [0 0 1 1] >>".encode(), field=False)
    extractor, _ = _extract(tmp_path, "deep.pdf", d.build())
    assert any("nested deeper" in f for f in extractor.failures), extractor.failures
