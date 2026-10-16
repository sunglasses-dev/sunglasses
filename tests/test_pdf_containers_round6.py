"""Sixth round on the PDF containers: a nested PDF behind long trailing data, object streams in
ordinary filter chains, page text ahead of the metadata, and an end-of-line inside /Length.

Review of the fifth round found these gaps:

* a header-less nested PDF was named only when the cross reference tail stood in the last
  2 KiB with an unsigned offset, while the reader finds the tail from the end of the data
  with any amount after it and accepts a signed offset;
* an object stream with a PNG predictor or an ASCII85 and Flate chain was refused, so the page
  tree in it was never resolved and the file that main blocked came back allow and incomplete;
* the metadata was read before the page tree, so an /Info object stream padded past the budget
  used it up before any page was read;
* a stream whose /Length includes the end-of-line before endstream was recorded as holding data
  after its compressed stream.
"""
import base64
import zlib

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.extractors import pdf as pdf_module
from sunglasses.extractors.pdf import PDFExtractor

from test_pdf_containers import (
    PAYLOAD, Doc, _attachment_doc, _inner_pdf, _s, _stream, _warnings,
)

BLOCKING = ("block", "quarantine")


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _scan(engine, tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return engine.scan_file(str(path))


def _tail(offset=b"123", after=b""):
    return b"1 0 obj << >> endobj\nxref\n0 1\ntrailer << >>\nstartxref\n" + offset + b"\n%%EOF\n" + after


# 1. The cross reference tail is found wherever it stands, with a signed offset --------------
@pytest.mark.parametrize("after", [b"", b"x" * 100, b"y\n" * 3000, b"z" * (1 << 20)],
                         ids=["none", "short", "past_2k", "megabyte"])
@pytest.mark.parametrize("offset", [b"123", b"+123", b"0123"], ids=["plain", "signed", "zeros"])
def test_a_tail_followed_by_data_is_still_named_a_pdf(offset, after):
    assert PDFExtractor._container_kind(_tail(offset, after)) == "PDF"


def test_a_signed_negative_offset_is_named_too():
    # The reader parses the offset with int(), so a minus sign reaches it as well.
    assert PDFExtractor._container_kind(_tail(b"-5")) == "PDF"


@pytest.mark.parametrize("text", [
    b"The startxref keyword and the %%EOF marker end a PDF.",
    b"startxref is followed by an offset",
    b"startxref %%EOF",
    b"startxref x12 %%EOF",
])
def test_text_that_only_mentions_the_markers_stays_text(text):
    assert PDFExtractor._container_kind(text) is None


@pytest.mark.parametrize("after", [b"q" * 5000, b""], ids=["long_tail", "no_tail"])
@pytest.mark.parametrize("offset", [b"+123", b"123"], ids=["signed", "plain"])
def test_a_header_less_nested_pdf_with_a_long_tail_or_signed_offset_is_reported(engine, tmp_path, offset, after):
    inner = _inner_pdf().replace(b"%PDF-", b"%ABC-")
    inner = inner.replace(b"startxref\n", b"startxref\n" + (b"+" if offset == b"+123" else b""))
    inner += after
    direct = _scan(engine, tmp_path, "direct.pdf", inner)
    assert direct.decision in BLOCKING
    outer = _scan(engine, tmp_path, "outer.pdf", _attachment_doc(_stream(inner, b"/Type /EmbeddedFile"), "inner.pdf"))
    assert not outer.inspection_complete
    assert any("PDF" in w and "not inspected" in w for w in _warnings(outer)), _warnings(outer)


# 2. An object stream in an ordinary filter chain still gives its pages ------------------------
def _encode(data, kind):
    if kind == "flate":
        return zlib.compress(data, 9), b"/Filter /FlateDecode"
    if kind == "predictor":
        return (zlib.compress(b"\x00" + data, 9),
                b"/Filter /FlateDecode /DecodeParms << /Predictor 12 /Colors 1 /BitsPerComponent 8 /Columns %d >>"
                % len(data))
    if kind == "a85flate":
        return (base64.a85encode(zlib.compress(data, 9), adobe=False) + b"~>",
                b"/Filter [/ASCII85Decode /FlateDecode]")
    if kind == "hexflate":
        return zlib.compress(data, 9).hex().encode() + b">", b"/Filter [/ASCIIHexDecode /FlateDecode]"
    if kind == "a85":
        return base64.a85encode(data, adobe=False) + b"~>", b"/Filter /ASCII85Decode"
    raise ValueError(kind)


def xref_pdf(filed, objstms, info=None, filt="flate"):
    """A PDF with an xref stream. `filed` maps number to body; `objstms` maps an object stream's
    number to (packed {number: body}, pad)."""
    top = max(list(filed) + list(objstms) + [n for packed, _ in objstms.values() for n in packed])
    xr = top + 1
    out = bytearray(b"%PDF-1.7\n")
    off, where = {}, {}
    for n, body in filed.items():
        off[n] = len(out)
        out += f"{n} 0 obj\n".encode() + body + b"\nendobj\n"
    for stm, (packed, pad) in objstms.items():
        header, body = b"", b""
        for n, item in packed.items():
            header += f"{n} {len(body)} ".encode()
            body += item + b"\n"
            where[n] = (stm, list(packed).index(n))
        data, filter_part = _encode(header + body + b" " * pad, filt)
        off[stm] = len(out)
        out += (f"{stm} 0 obj\n".encode()
                + _stream(data, f"/Type /ObjStm /N {len(packed)} /First {len(header)} ".encode() + filter_part)
                + b"\nendobj\n")
    off[xr] = len(out)
    ent = bytearray()
    for n in range(xr + 1):
        if n == 0:
            ent += bytes([0, 0, 0, 0, 0, 0xFF, 0xFF])
        elif n in where:
            ent += bytes([2]) + where[n][0].to_bytes(4, "big") + where[n][1].to_bytes(2, "big")
        elif n in off:
            ent += bytes([1]) + off[n].to_bytes(4, "big") + b"\x00\x00"
        else:
            ent += bytes([0, 0, 0, 0, 0, 0, 0])
    extra = f" /Info {info} 0 R" if info else ""
    out += (f"{xr} 0 obj\n".encode()
            + _stream(bytes(ent), f"/Type /XRef /Size {xr + 1} /Root 1 0 R{extra} /W [1 4 2]".encode())
            + b"\nendobj\n")
    out += f"startxref\n{off[xr]}\n%%EOF\n".encode()
    return bytes(out)


PAGE = (b"<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 << /Type /Font "
        b"/Subtype /Type1 /BaseFont /Helvetica >> >> >> /Contents 4 0 R >>")


def _content():
    return _stream(f"BT /F1 12 Tf 50 700 Td ({_s(PAYLOAD)}) Tj ET".encode())


def pages_in_objstm(filt, pad=0):
    filed = {1: b"<< /Type /Catalog /Pages 5 0 R >>", 2: b"<< >>", 3: b"<< >>", 4: _content()}
    packed = {5: b"<< /Type /Pages /Kids [6 0 R] /Count 1 >>", 6: PAGE % 5}
    return xref_pdf(filed, {7: (packed, pad)}, filt=filt)


@pytest.mark.parametrize("filt", ["flate", "predictor", "a85flate", "a85"])
def test_page_text_in_an_object_stream_in_an_ordinary_filter_chain_is_read(engine, tmp_path, filt):
    r = _scan(engine, tmp_path, "pages.pdf", pages_in_objstm(filt, pad=2000))
    assert r.decision in BLOCKING, (filt, _warnings(r))
    assert r.inspection_complete, (filt, _warnings(r))


@pytest.mark.parametrize("filt", ["predictor", "a85flate", "a85"])
def test_an_object_stream_in_a_filter_chain_past_the_budget_is_not_inflated_in_full(engine, tmp_path, monkeypatch, filt):
    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 1 << 20)
    r = _scan(engine, tmp_path, "pages.pdf", pages_in_objstm(filt, pad=6 << 20))
    assert not r.inspection_complete
    assert any("limit" in w or "object stream" in w for w in _warnings(r)), _warnings(r)


def test_a_filter_chain_object_stream_is_decoded_once(tmp_path, monkeypatch):
    import PyPDF2.filters as filters
    real = filters.decode_stream_data
    native = []

    def counting(stream):
        if stream.get("/Type") == "/ObjStm":
            native.append(1)
        return real(stream)

    monkeypatch.setattr(filters, "decode_stream_data", counting)
    path = tmp_path / "p.pdf"
    path.write_bytes(pages_in_objstm("a85flate", pad=2000))
    extractor = PDFExtractor()
    out = extractor.extract(str(path))
    assert PAYLOAD in " ".join(t for _, t in out)
    assert len(native) <= 1, native


# 3. The page tree and the page text are read before the metadata ------------------------------
def info_in_padded_objstm(pad):
    """The page tree is packed in a small object stream and /Info in another, padded one."""
    filed = {1: b"<< /Type /Catalog /Pages 2 0 R >>", 4: _content()}
    packed_pages = {2: b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>", 3: PAGE % 2}
    return xref_pdf(filed, {7: (packed_pages, 0), 5: ({6: b"<< /Title (a title) /Author (someone) >>"}, pad)}, info=6)


def test_an_info_object_stream_past_the_budget_does_not_hide_the_page_text(engine, tmp_path, monkeypatch):
    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 1 << 20)
    r = _scan(engine, tmp_path, "info.pdf", info_in_padded_objstm(4 << 20))
    assert r.decision in BLOCKING, _warnings(r)
    assert not r.inspection_complete        # the metadata was not read, and that is said
    assert any("object stream" in w or "limit" in w for w in _warnings(r)), _warnings(r)


def test_the_same_file_inside_the_budget_is_read_whole(engine, tmp_path):
    r = _scan(engine, tmp_path, "info.pdf", info_in_padded_objstm(0))
    assert r.decision in BLOCKING and r.inspection_complete, _warnings(r)


def test_the_sources_keep_their_order_metadata_first(tmp_path):
    path = tmp_path / "info.pdf"
    path.write_bytes(info_in_padded_objstm(0))
    labels = [label for label, _ in PDFExtractor().extract(str(path))]
    assert labels[0].startswith("metadata:") and any(l.startswith("page:") for l in labels), labels
    assert [l for l in labels if l.startswith("metadata:")] == labels[:len([l for l in labels if l.startswith("metadata:")])]


# 4. An end-of-line inside /Length is not data after the stream -------------------------------
@pytest.mark.parametrize("eol", [b"\n", b"\r\n", b"\r", b" \n"])
def test_a_length_that_includes_the_end_of_line_is_not_trailing_data(engine, tmp_path, eol):
    raw = zlib.compress(b"A plain note about the quarterly figures.") + eol
    r = _scan(engine, tmp_path, "eol.pdf", _attachment_doc(_stream(raw, b"/Type /EmbeddedFile /Filter /FlateDecode"), "n.txt"))
    assert r.inspection_complete, _warnings(r)


def test_real_trailing_data_after_a_compressed_stream_is_still_recorded(engine, tmp_path):
    raw = zlib.compress(b"A plain note.") + b"trailing bytes that are not whitespace"
    r = _scan(engine, tmp_path, "tail.pdf", _attachment_doc(_stream(raw, b"/Type /EmbeddedFile /Filter /FlateDecode"), "n.txt"))
    assert not r.inspection_complete
    assert any("after the end" in w for w in _warnings(r)), _warnings(r)


# 5. A stream in an ordinary filter chain is read, bounded, for an attachment too ---------------
@pytest.mark.parametrize("filt", ["a85flate", "predictor"])
def test_an_attachment_in_an_ordinary_filter_chain_is_read(engine, tmp_path, filt):
    data, filter_part = _encode(PAYLOAD.encode(), filt)
    r = _scan(engine, tmp_path, "att.pdf", _attachment_doc(_stream(data, b"/Type /EmbeddedFile " + filter_part), "n.txt"))
    assert r.decision in BLOCKING, (filt, _warnings(r))


def test_an_attachment_in_an_ordinary_chain_past_the_bound_is_reported(engine, tmp_path):
    data, filter_part = _encode(b"A" * ((1 << 20) + 10), "a85flate")
    r = _scan(engine, tmp_path, "att.pdf", _attachment_doc(_stream(data, b"/Type /EmbeddedFile " + filter_part), "n.txt"))
    assert not r.inspection_complete
    assert any("larger than" in w or "limit" in w for w in _warnings(r)), _warnings(r)


def test_a_filter_the_reader_cannot_decode_is_reported_and_not_raised(engine, tmp_path):
    r = _scan(engine, tmp_path, "att.pdf", _attachment_doc(_stream(b"abc", b"/Type /EmbeddedFile /Filter /Crypt"), "n.txt"))
    assert not r.inspection_complete
    assert any("not inspected" in w for w in _warnings(r)), _warnings(r)


def test_a_hex_filter_chain_is_reported_not_inspected_and_not_raised(engine, tmp_path):
    # The reader itself cannot decode this filter from bytes, as on main.
    data, filter_part = _encode(PAYLOAD.encode(), "hexflate")
    r = _scan(engine, tmp_path, "att.pdf", _attachment_doc(_stream(data, b"/Type /EmbeddedFile " + filter_part), "n.txt"))
    assert not r.inspection_complete
    assert any("not inspected" in w for w in _warnings(r)), _warnings(r)


def _lzw_encode(raw):
    """An LZW encoder written to match the widths the reader's decoder expects."""
    table = {bytes([i]): i for i in range(256)}
    nxt, bits, emitted = 258, 9, 0
    out = []

    def emit(code):
        nonlocal bits, emitted
        out.append(format(code, f"0{bits}b"))
        emitted += 1
        if 258 + max(0, emitted - 1) >= (1 << bits) - 1 and bits < 12:
            bits += 1

    out.append(format(256, "09b"))
    word = b""
    for byte in raw:
        joined = word + bytes([byte])
        if joined in table:
            word = joined
            continue
        emit(table[word])
        table[joined] = nxt
        nxt += 1
        word = bytes([byte])
        if nxt >= 4094:
            out.append(format(256, f"0{bits}b"))
            table = {bytes([i]): i for i in range(256)}
            nxt, bits, emitted = 258, 9, 0
    if word:
        emit(table[word])
    out.append(format(257, f"0{bits}b"))
    text = "".join(out)
    text += "0" * (-len(text) % 8)
    return bytes(int(text[i:i + 8], 2) for i in range(0, len(text), 8))


@pytest.mark.parametrize("raw", [b"-----A---B", b"abcabcabc" * 400, bytes(range(256)) * 40, b"A" * 20000])
def test_an_lzw_stream_is_counted_the_way_the_reader_decodes_it(raw):
    import PyPDF2.filters as filters
    data = _lzw_encode(raw)
    assert filters.LZWDecode.decode(data) == raw.decode("latin-1")
    assert pdf_module._lzw_length(data, 1 << 30) == len(raw)


def test_an_lzw_stream_missing_its_stop_code_is_not_sized():
    data = _lzw_encode(b"hello hello hello")
    assert pdf_module._lzw_length(data[:-2], 1 << 30) is None


def test_an_lzw_bomb_is_counted_and_stopped_at_the_limit():
    data = _lzw_encode(b"A" * 2_000_000)
    assert len(data) < 8000
    assert pdf_module._lzw_length(data, 10_000) > 10_000


def test_an_lzw_attachment_is_read_within_the_bound_and_a_bomb_is_not_decoded(engine, tmp_path, monkeypatch):
    import PyPDF2.filters as filters
    ok = _lzw_encode(PAYLOAD.encode())
    r = _scan(engine, tmp_path, "ok.pdf", _attachment_doc(_stream(ok, b"/Type /EmbeddedFile /Filter /LZWDecode"), "n.txt"))
    assert r.decision in BLOCKING
    decoded = []
    real = filters.LZWDecode.decode
    monkeypatch.setattr(filters.LZWDecode, "decode", staticmethod(lambda *a, **k: decoded.append(1) or real(*a, **k)))
    bomb = _lzw_encode(b"A" * 3_000_000)
    r = _scan(engine, tmp_path, "bomb.pdf", _attachment_doc(_stream(bomb, b"/Type /EmbeddedFile /Filter /LZWDecode"), "n.txt"))
    assert not decoded and not r.inspection_complete
    assert any("larger than" in w for w in _warnings(r)), _warnings(r)
