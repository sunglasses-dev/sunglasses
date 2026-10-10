"""Fifteenth round on the shared decoder: a stream that was decoded once is not handed back to a
later caller without that caller's own cap being applied.

A form value can resolve an object stream, and the object stream is decoded within what the
document budget has left, not within the attachment cap, because it can hold the page tree and the
page text. The decoded bytes were cached. A file spec that named the same stream then got the cached
bytes back after only a document-budget check, so an attachment larger than the cap was read, with
no failure recorded. The cache now keeps how much the stages produced beside the bytes, and every
cached return applies the cap of the caller that asks, records the refusal, and does not decode
again.
"""
import zlib

from sunglasses.extractors import pdf as pdf_module
from sunglasses.extractors.pdf import PDFExtractor

CAP = PDFExtractor.MAX_ATTACHMENT_BYTES


def _pdf(path, size):
    """A form whose value is inside an object stream, and a file spec whose attachment is the same
    stream. The decoded stream is `size` bytes."""
    payload = b'7 0 << /FT /Tx /T (field) /V (value) >>'
    payload += b' ' * (size - len(payload))
    compressed = zlib.compress(payload)
    objects = {
        1: b'<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(item.txt) 5 0 R] >> >> '
           b'/AcroForm << /Fields [7 0 R] >> >>',
        2: b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        3: b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << >> /Contents 4 0 R >>',
        4: b'<< /Length 0 >>\nstream\n\nendstream',
        5: b'<< /Type /Filespec /F (item.txt) /EF << /F 6 0 R >> >>',
        6: b'<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length '
           + str(len(compressed)).encode() + b' >>\nstream\n' + compressed + b'\nendstream',
    }
    data = b'%PDF-1.5\n'
    offsets = {}
    for number, body in objects.items():
        offsets[number] = len(data)
        data += str(number).encode() + b' 0 obj\n' + body + b'\nendobj\n'
    offsets[8] = len(data)
    entries = ([(0, 0, 65535)] + [(1, offsets[i], 0) for i in range(1, 7)]
               + [(2, 6, 0), (1, offsets[8], 0)])
    xref = b''.join(bytes([kind]) + a.to_bytes(4, 'big') + b.to_bytes(2, 'big') for kind, a, b in entries)
    data += (b'8 0 obj\n<< /Type /XRef /Size 9 /Root 1 0 R /W [1 4 2] /Length ' + str(len(xref)).encode()
             + b' >>\nstream\n' + xref + b'\nendstream\nendobj\nstartxref\n' + str(offsets[8]).encode()
             + b'\n%%EOF\n')
    path.write_bytes(data)
    return str(path)


def _run(path):
    extractor = PDFExtractor()
    results = extractor.extract(path)
    sources = [text for label, text in results if label.startswith('attachment:')]
    caps = [f for f in extractor.failures if 'larger than' in f]
    return extractor, sources, caps


def test_a_cached_object_stream_one_byte_over_the_cap_is_not_an_attachment(tmp_path):
    extractor, sources, caps = _run(_pdf(tmp_path / 'over.pdf', CAP + 1))
    assert sources == [], [len(s) for s in sources]
    assert len(caps) == 1 and 'attachment' in caps[0], extractor.failures


def test_a_cached_object_stream_at_the_cap_is_still_an_attachment(tmp_path):
    extractor, sources, caps = _run(_pdf(tmp_path / 'at.pdf', CAP))
    assert [len(s) for s in sources] == [CAP]
    assert caps == []


def test_the_cap_is_applied_to_the_cached_stream_without_decoding_it_again(tmp_path, monkeypatch):
    real = pdf_module._decode_bounded
    calls = []

    def spy(stream, *args, **kwargs):
        # Only the shared object stream is counted; another walk may decode streams of its own.
        if getattr(stream, 'get', lambda k: None)('/Type') == '/ObjStm':
            calls.append(1)
        return real(stream, *args, **kwargs)

    monkeypatch.setattr(pdf_module, '_decode_bounded', spy)
    _, sources, caps = _run(_pdf(tmp_path / 'once.pdf', CAP + 1))
    assert sources == [] and len(caps) == 1
    assert len(calls) == 1, len(calls)


def test_a_stream_cached_under_a_larger_cap_is_refused_by_a_smaller_one_directly():
    extractor = PDFExtractor()
    extractor.failures = []
    stream = {'/Filter': '/FlateDecode'}
    class S(dict):
        _data = zlib.compress(bytes(2000))
    s = S(stream)
    assert extractor._bounded_stream_bytes(s, 'object stream 1', cap=1 << 20) == bytes(2000)
    assert extractor._bounded_stream_bytes(s, 'attachment', cap=1000) is None
    assert any('larger than 1000 bytes' in f for f in extractor.failures), extractor.failures
    assert extractor._bounded_stream_bytes(s, 'attachment', cap=2000) == bytes(2000)
