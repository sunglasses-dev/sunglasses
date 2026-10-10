"""Seventh round on the PDF containers: one bounded decoder for every filter chain, the cross
reference tail in all the forms the reader accepts, and walks over arrays that are shared.

Review of the sixth round found these gaps:

* a stream was decoded before it was charged: a chain such as Flate then ASCII85 was run through
  the sizing probe, which kept its intermediate output uncharged, and then through the reader's
  own decode, a second time. A gzip header or a bad checksum made the probe fail, and the stream
  then fell through to the reader's unbounded decode. A Flate stream with a predictor and a
  missing end took the reader's byte by byte fallback, which is quadratic;
* a page tree in a gzip or bad checksum object stream, which main reads, was refused;
* the cross reference tail was not found when the offset stood on the same line as startxref
  or when other text stood after the keyword;
* a /Kids array shared by many fields or name tree nodes was iterated once per parent.
"""
import gzip
import struct
import zlib

import pytest
from PyPDF2.generic import EncodedStreamObject, NameObject, NumberObject

from sunglasses.engine import SunglassesEngine
from sunglasses.extractors import pdf as pdf_module
from sunglasses.extractors.pdf import PDFExtractor

import test_pdf_containers as base
from test_pdf_containers import (
    PAYLOAD, Doc, _build_object_stream, _s, _stream, _warnings,
)

BLOCKING = ("block", "quarantine")


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _scan(engine, tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return engine.scan_file(str(path))


def _encoded(data, *filters, parms=None):
    stream = EncodedStreamObject()
    stream._data = data
    if len(filters) == 1:
        stream[NameObject('/Filter')] = NameObject(filters[0])
    elif filters:
        from PyPDF2.generic import ArrayObject
        stream[NameObject('/Filter')] = ArrayObject([NameObject(f) for f in filters])
    if parms is not None:
        stream[NameObject('/DecodeParms')] = parms
    return stream


def _a85(data):
    import base64
    return base64.a85encode(data) + b"~>"


def _bad_adler(data):
    packed = bytearray(zlib.compress(data, 9))
    packed[-1] ^= 0xFF
    return bytes(packed)


def _count_reader_decodes(monkeypatch, stream=None):
    """Count the reader's own decodes, so a test can assert that the shared decoder never
    falls through to them."""
    from PyPDF2 import filters as pdf_filters
    calls = []
    for owner, name in ((pdf_filters.FlateDecode, "decode"), (pdf_filters, "decompress")):
        real = getattr(owner, name)

        def counted(*args, _real=real, _name=name, **kwargs):
            calls.append(_name)
            return _real(*args, **kwargs)

        monkeypatch.setattr(owner, name, staticmethod(counted) if owner is not pdf_filters else counted)
    return calls


# 1. The decoder: stages, charge, and no fall through ----------------------------------------
def test_a_gzip_stream_is_inflated_and_a_bad_checksum_is_kept():
    text = (PAYLOAD + " ") * 50
    for packed in (gzip.compress(text.encode()), _bad_adler(text.encode())):
        got = pdf_module._decode_bounded(_encoded(packed, '/FlateDecode'), 1 << 20)
        assert got.state == "ok" and got.data == text.encode(), got.state


def test_a_truncated_flate_stream_keeps_what_it_holds_and_says_so():
    text = (PAYLOAD + "\n") * 400
    packed = zlib.compress(text.encode(), 9)
    got = pdf_module._decode_bounded(_encoded(packed[:len(packed) // 2], '/FlateDecode'), 1 << 20)
    assert got.state == "ok" and got.data and text.encode().startswith(got.data)
    assert any("ends before" in n for n in got.notes), got.notes


def test_every_stage_of_a_chain_is_charged_and_the_chain_is_refused_when_the_sum_is_over():
    final = b"A" * 600_000
    middle = _a85(final)                      # about 750 KB of text
    packed = zlib.compress(middle, 9)
    chain = _encoded(packed, '/FlateDecode', '/ASCII85Decode')
    ok = pdf_module._decode_bounded(chain, 4 << 20)
    assert ok.state == "ok" and ok.data == final and ok.spent == len(packed) + len(middle) + len(final)
    # The final output fits in a megabyte; the stage in front of it does not leave room.
    refused = pdf_module._decode_bounded(chain, 1 << 20)
    assert refused.state == "big" and refused.data is None


def test_the_ascii85_stage_is_counted_before_it_is_decoded(monkeypatch):
    from PyPDF2 import filters as pdf_filters
    monkeypatch.setattr(pdf_filters.ASCII85Decode, "decode",
                        staticmethod(lambda *a, **k: pytest.fail("decoded past the bound")))
    bomb = b"z" * 400_000 + b"~>"             # one character stands for four bytes
    got = pdf_module._decode_bounded(_encoded(bomb, '/ASCII85Decode'), 1 << 20)
    assert got.state == "big"


@pytest.mark.parametrize("filters", [
    ('/LZWDecode', '/ASCII85Decode'), ('/Crypt', '/FlateDecode'), ('/ASCIIHexDecode',),
    ('/RunLengthDecode',), ('/DCTDecode',),
], ids=lambda f: "+".join(x[1:5] for x in f))
def test_a_chain_with_a_filter_that_is_not_sized_is_refused_and_not_decoded(monkeypatch, filters):
    calls = _count_reader_decodes(monkeypatch)
    got = pdf_module._decode_bounded(_encoded(zlib.compress(b"x" * 100), *filters), 1 << 20)
    assert got.state == "unsized" and got.data is None and calls == []


def test_a_flate_bomb_is_stopped_at_the_room_and_charged_that_much():
    bomb = zlib.compress(b"\0" * (200 << 20), 9)
    assert len(bomb) < 300_000
    got = pdf_module._decode_bounded(_encoded(bomb, '/FlateDecode'), 1 << 20)
    assert got.state == "big" and got.spent == (1 << 20) + 1


def test_a_png_predictor_is_applied_to_the_bounded_output_and_matches_the_reader():
    rows = b"".join(b"\x01" + bytes((i + j) % 256 for j in range(16)) for i in range(200))
    parms = None
    from PyPDF2.generic import DictionaryObject
    parms = DictionaryObject({NameObject('/Predictor'): NumberObject(11), NameObject('/Columns'): NumberObject(16)})
    stream = _encoded(zlib.compress(rows), '/FlateDecode', parms=parms)
    got = pdf_module._decode_bounded(stream, 1 << 20)
    assert got.state == "ok" and got.data == stream.get_data()


def test_a_truncated_predictor_stream_does_not_reach_the_readers_fallback(monkeypatch):
    from PyPDF2.generic import DictionaryObject
    parms = DictionaryObject({NameObject('/Predictor'): NumberObject(12), NameObject('/Columns'): NumberObject(8)})
    packed = zlib.compress(bytes(range(256)) * 4000, 9)
    stream = _encoded(packed[:-6], '/FlateDecode', parms=parms)
    calls = _count_reader_decodes(monkeypatch)
    got = pdf_module._decode_bounded(stream, 1 << 24)
    assert got.state in ("ok", "error")
    assert calls == [], calls


# 2. Through the extractor ---------------------------------------------------------------------
def _attachment(body, filters):
    return base._attachment_doc(_stream(body, b"/Type /EmbeddedFile /Filter " + filters))


def test_an_attachment_in_a_chain_is_charged_for_the_stage_in_front_of_the_last(engine, tmp_path, monkeypatch):
    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 1 << 20)
    monkeypatch.setattr(PDFExtractor, "MAX_ATTACHMENT_BYTES", 1 << 20)
    final = (PAYLOAD + "\n").encode() * 8000        # about 700 KB
    body = zlib.compress(_a85(final), 9)
    r = _scan(engine, tmp_path, "chain.pdf", _attachment(body, b"[/FlateDecode /ASCII85Decode]"))
    assert not r.inspection_complete and r.decision == "allow", (r.decision, _warnings(r))


def test_an_attachment_in_a_chain_that_fits_is_read_once(engine, tmp_path, monkeypatch):
    calls = _count_reader_decodes(monkeypatch)
    body = zlib.compress(_a85(PAYLOAD.encode()), 9)
    r = _scan(engine, tmp_path, "chain_ok.pdf", _attachment(body, b"[/FlateDecode /ASCII85Decode]"))
    assert r.decision in BLOCKING and r.inspection_complete, _warnings(r)
    # The page text is the reader's own decode; the chain of the attachment is not.
    assert calls.count("decode") <= 2, calls


@pytest.mark.parametrize("kind", ["gzip", "adler"])
def test_a_gzip_or_bad_checksum_attachment_is_read(engine, tmp_path, kind):
    data = PAYLOAD.encode()
    body = gzip.compress(data) if kind == "gzip" else _bad_adler(data)
    r = _scan(engine, tmp_path, f"{kind}.pdf", _attachment(body, b"/FlateDecode"))
    assert r.decision in BLOCKING, (r.decision, _warnings(r))


@pytest.mark.parametrize("kind", ["gzip", "adler"])
def test_a_page_tree_in_a_gzip_or_bad_checksum_object_stream_is_read(engine, tmp_path, monkeypatch, kind):
    """Main reads these streams, so the page text in them is scanned there. The file must
    not go from block to allow."""
    real = zlib.compress

    def as_gzip(data, level=-1):
        packer = zlib.compressobj(9, zlib.DEFLATED, 31)
        return packer.compress(data) + packer.flush()

    monkeypatch.setattr(zlib, "compress", as_gzip if kind == "gzip" else (
        lambda data, level=-1: _bad_adler_with(real, data)))
    d = Doc()
    d.fields.append(len(d.objs) + 3)
    data = _build_object_stream(d, [f"<< /FT /Tx /T (packed) /V ({_s(PAYLOAD)}) >>".encode()])
    monkeypatch.undo()
    r = _scan(engine, tmp_path, f"objstm_{kind}.pdf", data)
    assert r.decision == "block" and r.inspection_complete, (kind, r.decision, _warnings(r))


def _bad_adler_with(real, data):
    packed = bytearray(real(data, 9))
    packed[-1] ^= 0xFF
    return bytes(packed)


def test_a_truncated_predictor_attachment_does_not_use_the_readers_fallback(engine, tmp_path, monkeypatch):
    from PyPDF2 import filters as pdf_filters
    packed = zlib.compress((b"a" * 200 + b"\n") * 600, 9)[:-5]
    seen = []
    real = pdf_filters.decompress

    def watched(data, *a, **k):
        seen.append(len(data))
        return real(data, *a, **k)

    monkeypatch.setattr(pdf_filters, "decompress", watched)
    body = packed
    r = _scan(engine, tmp_path, "cut_pred.pdf", base._attachment_doc(_stream(
        body, b"/Type /EmbeddedFile /Filter /FlateDecode /DecodeParms << /Predictor 12 /Columns 8 >>")))
    assert all(n < len(packed) for n in seen), seen
    assert not r.inspection_complete or r.decision in BLOCKING


# 3. The cross reference tail in every form the reader accepts ---------------------------------
@pytest.mark.parametrize("tail", [
    b"startxref123\n%%EOF",
    b"startxref 123 %%EOF",
    b"startxref\n123\n%%EOF",
    b"startxref junk here\n123\n%%EOF",
    b"startxref\t\x0c\n+123%%EOF",
], ids=["same_line", "spaces", "newline", "junk_after_keyword", "tab_form_feed"])
def test_the_tail_is_found_in_every_form_the_reader_opens(tail):
    assert PDFExtractor._container_kind(b"1 0 obj << >> endobj\n" + tail) == "PDF", tail


@pytest.mark.parametrize("text", [
    b"The keyword startxref appears here and %%EOF there.",
    b"startxref is followed by words, then %%EOF",
    b"startxref\nnot a number\n%%EOF",
])
def test_text_that_only_mentions_the_markers_stays_text(text):
    assert PDFExtractor._container_kind(text) is None


@pytest.mark.parametrize("form", [b"startxref547\n%%EOF\n", b"startxref junk here\n547\n%%EOF\n"],
                         ids=["same_line", "junk_after_keyword"])
def test_a_header_less_nested_pdf_with_such_a_tail_is_reported_not_inspected(engine, tmp_path, form):
    inner = base._inner_pdf().replace(b"%PDF-", b"%ABC-")
    inner = inner.replace(b"startxref\n547\n%%EOF\n", form)
    assert form in inner
    direct = _scan(engine, tmp_path, "direct.pdf", inner)
    assert direct.decision in BLOCKING
    outer = _scan(engine, tmp_path, "outer.pdf",
                  base._attachment_doc(_stream(inner, b"/Type /EmbeddedFile"), "inner.pdf"))
    assert not outer.inspection_complete
    assert any("PDF" in w and "not inspected" in w for w in _warnings(outer)), _warnings(outer)


# 4. Walks over a /Kids array that many parents share ------------------------------------------
def _shared_kids_doc(parents, kids):
    d = Doc()
    leaf = [d.add(base._text_field(f"leaf{i}", value="x")) for i in range(kids)]
    shared = d.add(b"[" + b" ".join(f"{n} 0 R".encode() for n in leaf) + b"]")
    top = [d.add(f"<< /T (p{i}) /Kids {shared} 0 R >>".encode()) for i in range(parents)]
    d.fields.extend(top)
    return d.build()


def test_a_kids_array_shared_by_many_fields_is_walked_once(tmp_path, monkeypatch):
    path = tmp_path / "shared_kids.pdf"
    path.write_bytes(_shared_kids_doc(300, 300))
    extractor = PDFExtractor()
    real = extractor._identity
    count = [0]

    def counting(obj):
        count[0] += 1
        return real(obj)

    monkeypatch.setattr(extractor, "_identity", counting)
    extractor.extract(str(path))
    assert count[0] < 20 * 300, count[0]          # 300 x 300 would be 90,000


def _shared_name_tree_doc(nodes):
    d = Doc()
    first = len(d.objs) + 1
    ids = list(range(first + 1, first + 1 + nodes))
    shared = d.add(b"[" + b" ".join(f"{n} 0 R".encode() for n in ids) + b"]")
    for i in range(nodes):
        assert d.add(f"<< /Kids {shared} 0 R >>".encode()) == ids[i]
    root = d.add(b"<< /Kids [" + b" ".join(f"{n} 0 R".encode() for n in ids) + b"] >>")
    d.catalog_extra = f"/Names << /JavaScript {root} 0 R >>".encode()
    return d.build()


def test_name_tree_nodes_that_share_a_kids_array_cost_a_linear_amount(tmp_path, monkeypatch):
    path = tmp_path / "shared_tree.pdf"
    path.write_bytes(_shared_name_tree_doc(600))
    extractor = PDFExtractor()
    real = extractor._identity
    count = [0]

    def counting(obj):
        count[0] += 1
        return real(obj)

    monkeypatch.setattr(extractor, "_identity", counting)
    extractor.extract(str(path))
    assert count[0] < 20 * 600, count[0]          # 600 x 600 would be 360,000


def test_the_shared_array_walks_still_read_every_distinct_field(engine, tmp_path):
    r = _scan(engine, tmp_path, "shared_ok.pdf", _shared_kids_doc(5, 5))
    labels = list(r.extraction_sources)
    assert sum(1 for x in labels if x.startswith("form:") and x.endswith(":V")) >= 5, labels
