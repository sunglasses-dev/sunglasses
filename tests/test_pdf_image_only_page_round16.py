"""Sixteenth round on the image-only page walk, through the extractor: a decode parameter of a
content stream can point into an object stream, and the reader then inflates that object stream
itself. That inflation is part of the document and is bounded by what the document budget has
left; it must not run outside the ledger.

The fixture is a widget whose appearance stream names a decode parameter held in a compressed
object stream. The check is made through PDFExtractor.extract, with a spy on the reader's own
Flate decode, so it covers the object stream guard and the image walk together.
"""
import zlib

import pytest
from PyPDF2 import filters as pdf_filters

from sunglasses.extractors import pdf as pdf_module
from sunglasses.extractors.pdf import PDFExtractor


def _stream(keys, data):
    return b'<< ' + keys + b' /Length ' + str(len(data)).encode() + b' >>\nstream\n' + data + b'\nendstream'


def _fixture(padding):
    """Returns the file and the size of the decoded object stream."""
    objdata = b'6 0 << /Predictor 1 >>' + b' ' * padding
    objects = {
        1: b'<< /Type /Catalog /Pages 2 0 R >>',
        2: b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        3: b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Resources << >> /Annots [9 0 R] >>',
        4: b'null',
        5: _stream(b'/Type /XObject /Subtype /Form /BBox [0 0 1 1] /Filter [/FlateDecode /FlateDecode] '
                   b'/DecodeParms 6 0 R', zlib.compress(zlib.compress(bytes(512)))),
        7: _stream(b'/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode', zlib.compress(objdata)),
        9: b'<< /Type /Annot /Subtype /Widget /Rect [0 0 1 1] /AP << /N 5 0 R >> >>',
    }
    data = b'%PDF-1.5\n'
    offsets = {}
    for number, body in sorted(objects.items()):
        offsets[number] = len(data)
        data += str(number).encode() + b' 0 obj\n' + body + b'\nendobj\n'
    offsets[8] = len(data)
    entries = []
    for number in range(10):
        kind, a, b = ((0, 0, 65535) if number == 0 else (2, 7, 0) if number == 6
                      else (1, offsets.get(number, 0), 0))
        entries.append(bytes([kind]) + a.to_bytes(4, 'big') + b.to_bytes(2, 'big'))
    data += (b'8 0 obj\n' + _stream(b'/Type /XRef /Root 1 0 R /Size 10 /W [1 4 2]', b''.join(entries))
             + b'\nendobj\nstartxref\n' + str(offsets[8]).encode() + b'\n%%EOF\n')
    return data, len(objdata)


def _run(tmp_path, monkeypatch, padding, budget):
    raw, size = _fixture(padding)
    path = tmp_path / 'nested.pdf'
    path.write_bytes(raw)
    monkeypatch.setattr(pdf_module._ReadBudget, 'MAX_BYTES', budget)
    native = []
    real = pdf_filters.FlateDecode.decode

    def spy(data, decode_parms=None, **kwargs):
        out = real(data, decode_parms, **kwargs)
        native.append(len(out))
        return out

    monkeypatch.setattr(pdf_filters.FlateDecode, 'decode', staticmethod(spy))
    extractor = PDFExtractor()
    extractor.extract(str(path))
    return extractor, native, size


def test_an_object_stream_behind_a_decode_parameter_is_not_inflated_outside_the_ledger(tmp_path, monkeypatch):
    extractor, native, size = _run(tmp_path, monkeypatch, padding=4096, budget=2048)
    assert size > 2048
    assert native == [], native


def test_an_object_stream_that_fits_is_charged_to_the_document_budget(tmp_path, monkeypatch):
    extractor, native, size = _run(tmp_path, monkeypatch, padding=4096, budget=1 << 20)
    assert native == [], native
    assert extractor.budget.read >= size, (extractor.budget.read, size)
