"""Lab finding A3: what the container reads cost, and what they report when they stop early.

Four shapes sit here. A nested PDF behind a UTF-16 byte order mark is a PDF, so it is
reported as a file that was not inspected and is not taken for text. A value array that
shares its members through indirect references is read once per member and not once per
path, within a bound on members, depth and output. A document whose decoded budget is
spent stops decoding the streams that come later, and a stream that several fields share
is decoded once. A Flate stream that does not reach its end is reported as cut short.

One budget belongs to the document and is created before the first check reads anything,
so a check added in front of the container reads, such as the image check of a sibling
change, charges the same budget.
"""
import time
import zlib

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses.extractors import pdf as pdf_module
from sunglasses.extractors.pdf import PDFExtractor

from test_pdf_containers import (
    PAYLOAD, Doc, _attachment_doc, _inner_pdf, _stream, _warnings,
)

BOM = b"\xff\xfe"


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


def _scan(engine, tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return engine.scan_file(str(path))


def _extract(tmp_path, name, data, extractor=None):
    path = tmp_path / name
    path.write_bytes(data)
    extractor = extractor or PDFExtractor()
    return extractor, extractor.extract(str(path))


def _bom_pdf() -> bytes:
    data = BOM + _inner_pdf()
    return data + b"\n" if len(data) % 2 else data


def test_a_pdf_behind_a_byte_order_mark_scans_as_a_pdf(engine, tmp_path):
    result = _scan(engine, tmp_path, "bom_inner.pdf", _bom_pdf())
    assert result.decision == "block"


def test_a_nested_pdf_behind_a_byte_order_mark_is_reported_not_inspected(engine, tmp_path):
    outer = _attachment_doc(_stream(_bom_pdf(), b"/Type /EmbeddedFile"), "inner.pdf")
    result = _scan(engine, tmp_path, "bom_outer.pdf", outer)
    assert not result.inspection_complete
    assert any("inner.pdf" in w and "PDF" in w and "not inspected" in w
               for w in _warnings(result)), _warnings(result)


def test_a_text_attachment_behind_a_byte_order_mark_is_still_read(engine, tmp_path):
    text = BOM + PAYLOAD.encode("utf-16-le")
    result = _scan(engine, tmp_path, "bom_text.pdf", _attachment_doc(_stream(text), "note.txt"))
    assert result.decision == "block"


def _array_graph(depth: int) -> bytes:
    d = Doc()
    node = d.add(b"(ordinary)")
    for _ in range(depth):
        node = d.add(f"[{node} 0 R {node} 0 R]".encode())
    field = d.add(f"<< /FT /Ch /T (choice) /Opt {node} 0 R >>".encode())
    d.fields = [field]
    return d.build()


def test_a_shared_value_array_is_read_once_per_member(tmp_path):
    started = time.perf_counter()
    extractor, sources = _extract(tmp_path, "dag.pdf", _array_graph(14))
    assert time.perf_counter() - started < 60
    assert sum(len(text) for _, text in sources) < 4096
    assert extractor.failures == []


def test_a_shared_value_array_past_the_depth_bound_is_cut_and_reported(tmp_path):
    started = time.perf_counter()
    extractor, sources = _extract(tmp_path, "dag_deep.pdf", _array_graph(24))
    assert time.perf_counter() - started < 60
    assert sum(len(text) for _, text in sources) < 4096
    assert any("array" in f and "not inspected" in f for f in extractor.failures), extractor.failures


def test_a_value_array_past_the_member_bound_is_reported_unread(tmp_path, monkeypatch):
    monkeypatch.setattr(PDFExtractor, "MAX_ARRAY_MEMBERS", 50)
    d = Doc()
    members = " ".join(f"(member{i})" for i in range(200))
    field = d.add(f"<< /FT /Ch /T (choice) /Opt [{members}] >>".encode())
    d.fields = [field]
    extractor, sources = _extract(tmp_path, "wide.pdf", d.build())
    assert any("array" in f and "not inspected" in f for f in extractor.failures), extractor.failures
    assert sum(len(text) for _, text in sources) < 2048


def test_a_value_array_past_the_depth_bound_is_reported_unread(tmp_path, monkeypatch):
    monkeypatch.setattr(PDFExtractor, "MAX_ARRAY_DEPTH", 4)
    d = Doc()
    nested = "(deep)"
    for _ in range(10):
        nested = f"[{nested}]"
    field = d.add(f"<< /FT /Ch /T (choice) /Opt {nested} >>".encode())
    d.fields = [field]
    extractor, _ = _extract(tmp_path, "deep.pdf", d.build())
    assert any("array" in f and "not inspected" in f for f in extractor.failures), extractor.failures


def test_a_small_value_array_is_still_read(tmp_path):
    d = Doc()
    field = d.add(b"<< /FT /Ch /T (choice) /Opt [(first) [(second) (third)]] >>")
    d.fields = [field]
    extractor, sources = _extract(tmp_path, "small.pdf", d.build())
    joined = " ".join(text for _, text in sources)
    assert "first" in joined and "second" in joined and "third" in joined
    assert extractor.failures == []


def _count_inflations(monkeypatch):
    calls = []
    real = zlib.decompressobj

    def counting(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(pdf_module.zlib, "decompressobj", counting)
    return calls


def _flate_fields(count: int, shared: bool) -> bytes:
    d = Doc()
    body = zlib.compress(b"ordinary " * 10000)
    shared_ref = d.add(_stream(body, b"/Filter /FlateDecode"))
    for i in range(count):
        ref = shared_ref if shared else d.add(_stream(body, b"/Filter /FlateDecode"))
        d.fields.append(d.add(f"<< /FT /Tx /T (f{i}) /V {ref} 0 R >>".encode()))
    return d.build()


def test_a_spent_budget_stops_the_decoding_of_later_streams(tmp_path, monkeypatch):
    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 100_000)
    calls = _count_inflations(monkeypatch)
    extractor, _ = _extract(tmp_path, "spent.pdf", _flate_fields(25, shared=False))
    assert len(calls) <= 2, len(calls)
    assert extractor.budget.read <= 100_000
    assert any("limit" in f and "not inspected" in f for f in extractor.failures), extractor.failures


def test_a_stream_that_several_fields_share_is_decoded_once(tmp_path, monkeypatch):
    calls = _count_inflations(monkeypatch)
    _extract(tmp_path, "shared.pdf", _flate_fields(25, shared=True))
    assert len(calls) == 1, len(calls)


def test_a_shared_stream_is_charged_each_time_it_is_used(tmp_path, monkeypatch):
    monkeypatch.setattr(pdf_module._ReadBudget, "MAX_BYTES", 100_000)
    extractor, _ = _extract(tmp_path, "shared_spent.pdf", _flate_fields(25, shared=True))
    assert extractor.budget.read <= 100_000
    assert any("limit" in f and "not inspected" in f for f in extractor.failures), extractor.failures


def _unfinished_flate(text: bytes) -> bytes:
    packer = zlib.compressobj()
    return packer.compress(text) + packer.flush(zlib.Z_SYNC_FLUSH)


def test_a_flate_stream_that_does_not_end_is_reported_cut_short(engine, tmp_path):
    data = _attachment_doc(_stream(_unfinished_flate(b"ordinary text"), b"/Filter /FlateDecode"), "partial.txt")
    result = _scan(engine, tmp_path, "unfinished.pdf", data)
    assert not result.inspection_complete
    assert any("partial.txt" in w and "not inspected" in w for w in _warnings(result)), _warnings(result)


def test_the_text_before_the_cut_of_an_unfinished_stream_is_still_scanned(engine, tmp_path):
    data = _attachment_doc(_stream(_unfinished_flate(PAYLOAD.encode()), b"/Filter /FlateDecode"), "partial.txt")
    result = _scan(engine, tmp_path, "unfinished_payload.pdf", data)
    assert result.decision == "block"


def test_a_finished_flate_stream_stays_complete(engine, tmp_path):
    body = zlib.compress(b"ordinary text")
    data = _attachment_doc(_stream(body, b"/Filter /FlateDecode"), "whole.txt")
    result = _scan(engine, tmp_path, "finished.pdf", data)
    assert result.inspection_complete


def test_the_document_budget_exists_before_the_first_check_reads(tmp_path, monkeypatch):
    seen = []
    for name in ("_extract_metadata", "_extract_form_fields", "_extract_attachments"):
        real = getattr(PDFExtractor, name)

        def spy(self, *args, _real=real, **kwargs):
            seen.append(self.budget)
            return _real(self, *args, **kwargs)

        monkeypatch.setattr(PDFExtractor, name, spy)
    _extract(tmp_path, "plain.pdf", Doc().build())
    assert len(seen) == 3
    assert seen[0] is seen[1] is seen[2]


def test_a_second_document_starts_with_a_fresh_budget(tmp_path):
    extractor = PDFExtractor()
    _extract(tmp_path, "one.pdf", _flate_fields(3, shared=False), extractor)
    first = extractor.budget.read
    _extract(tmp_path, "two.pdf", Doc().build(), extractor)
    assert first > 0
    assert extractor.budget.read == 0
