"""Lab finding A3, round 4: what the container reads still left unread, and what they cost.

Six shapes sit here, each one a text that failed on the previous head and passes now, next
to a control that has to keep its old result.

1. A nested PDF behind a long run of blanks is a PDF for the reader, so it is reported as a
   file that was not inspected. A text file that only mentions a PDF stays text.
2. A stream that is inflated and then rejected for its size was free. Every inflation now
   spends from the document budget, and none starts once the budget is spent.
3. A string or array value was free. Its bytes (encoded, with the separators) are charged.
4. The guard on compressed object streams stands before the first read, so a widget that
   only the annotation check reaches does not force a large inflation.
5. A file specification with more than one embedded stream reads each distinct stream.
6. A UTF-16 value that does not decode, and compressed data after the end of a stream, are
   reported and are not turned into an empty success.
"""
import zlib

import pytest

from PyPDF2.generic import EncodedStreamObject, NameObject

from sunglasses.engine import SunglassesEngine
from sunglasses.extractors import pdf as pdf_module
from sunglasses.extractors.pdf import PDFExtractor

from test_pdf_containers import (
    PAYLOAD, Doc, _attachment_doc, _build_object_stream, _inner_pdf, _stream, _warnings,
)

BOM = b"\xff\xfe"


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def _scan(engine, tmp_path, name, data):
    return engine.scan_file(_write(tmp_path, name, data))


def _extract(tmp_path, name, data, extractor=None):
    extractor = extractor or PDFExtractor()
    return extractor, extractor.extract(_write(tmp_path, name, data))


def _named_pdf_unread(result, name):
    return any(name in w and "PDF" in w and "not inspected" in w for w in _warnings(result))


# 1. A nested PDF behind a long prefix.
@pytest.mark.parametrize("prefix", [b" " * 1100, BOM + b" " * 1100, b"\n" * 5000, BOM + b" " * 70000],
                         ids=["blanks", "bom_blanks", "newlines", "bom_long"])
def test_a_nested_pdf_behind_a_long_prefix_is_reported_not_inspected(engine, tmp_path, prefix):
    inner = prefix + _inner_pdf()
    if len(inner) % 2:
        inner += b" "
    outer = _attachment_doc(_stream(inner, b"/Type /EmbeddedFile"), "inner.pdf")
    result = _scan(engine, tmp_path, "outer.pdf", outer)
    assert not result.inspection_complete
    assert _named_pdf_unread(result, "inner.pdf"), _warnings(result)


@pytest.mark.parametrize("prefix", [b" " * 1100, BOM + b" " * 1100], ids=["blanks", "bom_blanks"])
def test_the_same_prefixed_pdf_scanned_directly_still_blocks(engine, tmp_path, prefix):
    data = prefix + _inner_pdf()
    if len(data) % 2:
        data += b" "
    assert _scan(engine, tmp_path, "direct.pdf", data).decision == "block"


def test_a_text_attachment_after_a_long_run_of_blanks_is_still_read(engine, tmp_path):
    text = b" " * 3000 + PAYLOAD.encode()
    result = _scan(engine, tmp_path, "blanks.pdf", _attachment_doc(_stream(text), "note.txt"))
    assert result.decision == "block"
    assert result.inspection_complete, _warnings(result)


def test_a_text_attachment_that_mentions_the_pdf_marker_is_still_read(engine, tmp_path):
    text = b" " * 3000 + b"The file starts with %PDF- and ends with %%EOF. " + PAYLOAD.encode()
    result = _scan(engine, tmp_path, "mention.pdf", _attachment_doc(_stream(text), "note.txt"))
    assert result.decision == "block"
    assert result.inspection_complete, _warnings(result)


# 2. A rejected inflation is charged, and none starts after the budget is spent.
_REAL_INFLATER = zlib.decompressobj


class _CountingInflater:
    calls = []

    def __init__(self, *args, **kwargs):
        self.inner = _REAL_INFLATER(*args, **kwargs)

    def decompress(self, raw, *args):
        out = self.inner.decompress(raw, *args)
        self.calls.append(len(out))
        return out

    def __getattr__(self, name):
        return getattr(self.inner, name)


def _flate_stream(size):
    stream = EncodedStreamObject()
    stream._data = zlib.compress(b" " * size)
    stream[NameObject("/Filter")] = NameObject("/FlateDecode")
    return stream


def test_a_stream_rejected_for_its_size_spends_from_the_budget(monkeypatch):
    _CountingInflater.calls = []
    monkeypatch.setattr(pdf_module.zlib, "decompressobj", _CountingInflater)
    extractor = PDFExtractor()
    extractor.MAX_ATTACHMENT_BYTES = 100
    extractor.budget.MAX_BYTES = 150
    streams = [_flate_stream(200) for _ in range(8)]    # kept alive: the cache keys on identity
    for i, stream in enumerate(streams):
        extractor._bounded_stream_bytes(stream, f"s{i}")
    assert extractor.budget.read == 150
    assert sum(_CountingInflater.calls) <= 150 + 3, _CountingInflater.calls
    assert len(_CountingInflater.calls) <= 3, _CountingInflater.calls
    assert any("limit" in f for f in extractor.failures), extractor.failures


def test_no_inflation_starts_once_the_budget_is_spent(monkeypatch):
    _CountingInflater.calls = []
    monkeypatch.setattr(pdf_module.zlib, "decompressobj", _CountingInflater)
    extractor = PDFExtractor()
    extractor.budget.MAX_BYTES = 0
    assert extractor._bounded_stream_bytes(_flate_stream(10), "s") is None
    assert _CountingInflater.calls == []


def test_a_stream_that_fits_is_charged_what_it_decoded(monkeypatch):
    extractor = PDFExtractor()
    extractor.MAX_ATTACHMENT_BYTES = 1000
    stream = _flate_stream(300)
    assert extractor._bounded_stream_bytes(stream, "s") == b" " * 300
    assert extractor.budget.read == 300 + len(stream._data)   # the input and what it made


# 3. A string value or an array is charged by its encoded bytes.
def test_a_string_value_beyond_the_budget_is_cut_and_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 100)
    d = Doc()
    d.widget(f"<< /Type /Annot /Subtype /Widget /FT /Tx /T (field) /V ({'a' * 200}) >>".encode())
    extractor, _ = _extract(tmp_path, "scalar.pdf", d.build())
    assert any("limit" in f for f in extractor.failures), extractor.failures
    assert extractor.budget.read >= 100


def test_an_array_is_charged_in_encoded_bytes_and_separators(monkeypatch):
    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 150)
    extractor = PDFExtractor()
    first, second = "é" * 50, "è" * 50   # 50 characters, 100 bytes each
    extractor._as_text([first, second])
    assert any("limit" in f for f in extractor.failures), (extractor.budget.read, extractor.failures)


def test_a_small_scalar_value_is_charged_and_still_read(tmp_path):
    d = Doc()
    d.widget(f"<< /Type /Annot /Subtype /Widget /FT /Tx /T (field) /V ({PAYLOAD}) >>".encode())
    extractor, out = _extract(tmp_path, "small.pdf", d.build())
    assert any(PAYLOAD in text for _, text in out)
    assert extractor.budget.read >= len(PAYLOAD)
    assert not extractor.failures, extractor.failures


# 4. The object stream guard stands before the first read.
def _annotation_object_stream_doc(pad):
    d = Doc()
    ref = len(d.objs) + 3
    d.annots.append(ref)
    return _build_object_stream(d, [b"<< /Subtype /Widget /FT /Tx /T (neutral) /V (ordinary) >>"], pad=pad)


def test_an_oversized_object_stream_behind_an_annotation_is_not_inflated(tmp_path, monkeypatch):
    fresh = []
    original = EncodedStreamObject.get_data

    def tracked(self):
        first = getattr(self, "decoded_self", None) is None
        result = original(self)
        if self.get("/Type") == "/ObjStm":
            fresh.append((first, len(result)))
        return result

    monkeypatch.setattr(EncodedStreamObject, "get_data", tracked)
    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 1 << 20)
    extractor, _ = _extract(tmp_path, "annot_bomb.pdf", _annotation_object_stream_doc(4 << 20))
    big = [n for first, n in fresh if first and n > extractor.MAX_ATTACHMENT_BYTES]
    assert big == [], fresh
    assert any("object stream" in f and "not inspected" in f for f in extractor.failures), extractor.failures


def test_a_small_object_stream_behind_an_annotation_is_still_read(tmp_path):
    extractor, _ = _extract(tmp_path, "annot_small.pdf", _annotation_object_stream_doc(0))
    assert not extractor.failures, extractor.failures


def test_the_object_stream_guard_is_in_place_before_the_first_check(tmp_path, monkeypatch):
    order = []
    guard = PDFExtractor._bounded_object_streams
    metadata = PDFExtractor._extract_metadata

    def guarded(self, reader):
        order.append("guard")
        return guard(self, reader)

    def read_metadata(self, reader):
        order.append("metadata")
        return metadata(self, reader)

    monkeypatch.setattr(PDFExtractor, "_bounded_object_streams", guarded)
    monkeypatch.setattr(PDFExtractor, "_extract_metadata", read_metadata)
    _extract(tmp_path, "order.pdf", Doc().build())
    assert order[:2] == ["guard", "metadata"], order


# 5. Every distinct embedded stream of one file specification is read.
def _dual_ef_doc(first, second, key_first=b"/UF", key_second=b"/F"):
    d = Doc()
    a = d.add(_stream(first))
    b = d.add(_stream(second))
    spec = d.add(b"<< /F (a.txt) /UF (a.txt) /EF << " + key_first + b" " + str(a).encode() + b" 0 R "
                 + key_second + b" " + str(b).encode() + b" 0 R >> >>")
    d.catalog_extra = f"/Names << /EmbeddedFiles << /Names [(a) {spec} 0 R] >> >>".encode()
    return d.build()


@pytest.mark.parametrize("order", ["payload_second", "payload_first"])
def test_the_second_embedded_text_stream_is_read(engine, tmp_path, order):
    texts = (b"ordinary text", PAYLOAD.encode())
    if order == "payload_first":
        texts = texts[::-1]
    result = _scan(engine, tmp_path, "dual_text.pdf", _dual_ef_doc(*texts))
    assert result.decision == "block"


def test_the_second_embedded_pdf_stream_is_reported_not_inspected(engine, tmp_path):
    result = _scan(engine, tmp_path, "dual_pdf.pdf", _dual_ef_doc(b"ordinary text", _inner_pdf()))
    assert not result.inspection_complete
    assert _named_pdf_unread(result, "a.txt"), _warnings(result)


def test_two_alternatives_that_share_one_stream_are_read_once(tmp_path):
    d = Doc()
    shared = d.add(_stream(b"ordinary text"))
    spec = d.add(f"<< /F (a.txt) /UF (a.txt) /EF << /UF {shared} 0 R /F {shared} 0 R >> >>".encode())
    d.catalog_extra = f"/Names << /EmbeddedFiles << /Names [(a) {spec} 0 R] >> >>".encode()
    extractor, out = _extract(tmp_path, "shared_ef.pdf", d.build())
    assert [label for label, _ in out if label.startswith("attachment:")] == ["attachment:a.txt"]
    assert extractor._attachments_read == 1


def test_the_alternatives_count_toward_the_attachment_bound(tmp_path):
    d = Doc()
    streams = [d.add(_stream(f"text {i}".encode())) for i in range(4)]
    spec = d.add(("<< /F (a.txt) /UF (a.txt) /EF << /UF %d 0 R /F %d 0 R /DOS %d 0 R /Mac %d 0 R >> >>"
                  % tuple(streams)).encode())
    d.catalog_extra = f"/Names << /EmbeddedFiles << /Names [(a) {spec} 0 R] >> >>".encode()
    extractor = PDFExtractor()
    extractor.MAX_ATTACHMENTS = 2
    _, out = _extract(tmp_path, "many_ef.pdf", d.build(), extractor)
    assert len([1 for label, _ in out if label.startswith("attachment:")]) == 2
    assert any("attachments beyond 2" in f for f in extractor.failures), extractor.failures


# 6. A value that does not decode, and data after the end of a stream.
def _utf16_field(stream_bytes):
    d = Doc()
    s = d.add(_stream(stream_bytes))
    d.fields = [d.add(f"<< /FT /Tx /T (neutral) /V {s} 0 R >>".encode())]
    return d.build()


def test_a_utf16_value_with_a_stray_byte_is_read_and_reported(engine, tmp_path):
    result = _scan(engine, tmp_path, "utf16.pdf", _utf16_field(BOM + PAYLOAD.encode("utf-16-le") + b"\x00"))
    assert result.decision == "block"
    assert not result.inspection_complete
    assert any("not valid" in w for w in _warnings(result)), _warnings(result)


@pytest.mark.parametrize("where", ["field_v", "field_rv", "script"])
def test_a_utf16_value_that_does_not_decode_is_never_an_empty_success(engine, tmp_path, where):
    broken = BOM + b"\x00"
    d = Doc()
    s = d.add(_stream(broken))
    if where == "script":
        d.catalog_extra = f"/OpenAction << /S /JavaScript /JS {s} 0 R >>".encode()
    else:
        key = "V" if where == "field_v" else "RV"
        d.fields = [d.add(f"<< /FT /Tx /T (neutral) /{key} {s} 0 R >>".encode())]
    result = _scan(engine, tmp_path, "broken.pdf", d.build())
    assert not result.inspection_complete
    assert any("not valid" in w for w in _warnings(result)), _warnings(result)


def test_a_valid_utf16_value_stays_complete(engine, tmp_path):
    result = _scan(engine, tmp_path, "utf16_ok.pdf", _utf16_field(BOM + PAYLOAD.encode("utf-16-le")))
    assert result.decision == "block"
    assert result.inspection_complete, _warnings(result)


def test_data_after_the_end_of_a_compressed_stream_is_reported(engine, tmp_path):
    data = zlib.compress(b"ordinary text") + zlib.compress(b"other text")
    outer = _attachment_doc(_stream(data, b"/Filter /FlateDecode"), "a.txt")
    result = _scan(engine, tmp_path, "trailing.pdf", outer)
    assert not result.inspection_complete
    assert any("after the end" in w for w in _warnings(result)), _warnings(result)


def test_the_text_before_the_trailing_data_is_still_scanned(engine, tmp_path):
    data = zlib.compress(PAYLOAD.encode()) + zlib.compress(b"other text")
    outer = _attachment_doc(_stream(data, b"/Filter /FlateDecode"), "a.txt")
    assert _scan(engine, tmp_path, "trailing_text.pdf", outer).decision == "block"


def test_one_finished_stream_stays_complete(engine, tmp_path):
    outer = _attachment_doc(_stream(zlib.compress(b"ordinary text"), b"/Filter /FlateDecode"), "a.txt")
    result = _scan(engine, tmp_path, "single.pdf", outer)
    assert result.inspection_complete, _warnings(result)
