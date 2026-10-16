"""Seventeenth round on the object stream guard, through the extractor.

The guard decodes a compressed object stream once, charged, at the first lookup into it, and hands
the bytes to the reader so the reader's own decode does not run. It must never leave the reader to
decode a stream itself. Two ways it could: a lookup inside the guard that fails (at one depth of
calls and not at another) was read as "the reader will raise the same error", the verdict "fits"
was kept, and a later lookup from a shallower place let the reader inflate the stream natively and
unpaid; and a reader that does not hand back the stream object the guard decoded. Both are refused
now, and the page is reported as not checked.

The fixture is two widgets whose appearance streams name the same decode parameter, held in a
compressed object stream. The spy is on the reader's own Flate decode.
"""
import decimal
import sys
import zlib

import pytest
from PyPDF2 import PdfReader
from PyPDF2 import filters as pdf_filters

from sunglasses.extractors import pdf as pdf_module
from sunglasses.extractors.pdf import PDFExtractor

STREAM_NUMBER = 7


def _stream(keys, data):
    return b'<< ' + keys + b' /Length ' + str(len(data)).encode() + b' >>\nstream\n' + data + b'\nendstream'


def _form():
    return _stream(b'/Type /XObject /Subtype /Form /BBox [0 0 1 1] /Filter [/FlateDecode /FlateDecode] '
                   b'/DecodeParms 6 0 R', zlib.compress(zlib.compress(bytes(512))))


def _fixture(padding=4096):
    objdata = b'6 0 << /Predictor 1 >>' + b' ' * padding
    objects = {
        1: b'<< /Type /Catalog /Pages 2 0 R >>',
        2: b'<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
        3: b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Resources << >> /Annots [9 0 R 11 0 R] >>',
        4: b'null',
        5: _form(),
        7: _stream(b'/Type /ObjStm /N 1 /First 4 /Filter /FlateDecode', zlib.compress(objdata)),
        9: b'<< /Type /Annot /Subtype /Widget /Rect [0 0 1 1] /AP << /N 5 0 R >> >>',
        10: _form(),
        11: b'<< /Type /Annot /Subtype /Widget /Rect [0 0 1 1] /AP << /N 10 0 R >> >>',
    }
    data = b'%PDF-1.5\n'
    offsets = {}
    for number, body in sorted(objects.items()):
        offsets[number] = len(data)
        data += str(number).encode() + b' 0 obj\n' + body + b'\nendobj\n'
    offsets[8] = len(data)
    entries = []
    for number in range(12):
        kind, a, b = ((0, 0, 65535) if number == 0 else (2, 7, 0) if number == 6
                      else (1, offsets.get(number, 0), 0))
        entries.append(bytes([kind]) + a.to_bytes(4, 'big') + b.to_bytes(2, 'big'))
    data += (b'8 0 obj\n' + _stream(b'/Type /XRef /Root 1 0 R /Size 12 /W [1 4 2]', b''.join(entries))
             + b'\nendobj\nstartxref\n' + str(offsets[8]).encode() + b'\n%%EOF\n')
    return data


def _run(tmp_path, monkeypatch, budget=1 << 20):
    path = tmp_path / 'guard.pdf'
    path.write_bytes(_fixture())
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
    return extractor, native


def test_a_lookup_that_fails_deep_and_works_shallow_leaves_no_stream_to_the_reader(tmp_path, monkeypatch):
    # the first lookup of the object stream raises, as a call stack that is too deep does; the second
    # lookup, from the other widget, would have worked
    real = PdfReader.get_object
    seen = []

    def get_object(self, indirect_reference):
        number = getattr(indirect_reference, 'idnum', indirect_reference)
        if number == STREAM_NUMBER and not seen:
            seen.append(number)
            raise RecursionError('too deep')
        return real(self, indirect_reference)

    monkeypatch.setattr(PdfReader, 'get_object', get_object)
    extractor, native = _run(tmp_path, monkeypatch)
    assert seen == [STREAM_NUMBER], 'the fixture did not make the first lookup fail'
    assert native == [], native


def test_a_reader_that_does_not_keep_the_object_stream_is_not_left_to_decode_it(tmp_path, monkeypatch):
    # the guard decodes the stream it was handed; a reader that resolves a new object stream on every
    # lookup would decode that one itself, so the guard refuses it
    real = PdfReader.cache_indirect_object

    def cache(self, generation, idnum, obj):
        if idnum == STREAM_NUMBER:
            return obj
        return real(self, generation, idnum, obj)

    monkeypatch.setattr(PdfReader, 'cache_indirect_object', cache)
    extractor, native = _run(tmp_path, monkeypatch)
    assert native == [], native


def test_an_ordinary_reader_still_gets_the_object_stream_decoded_once_and_charged(tmp_path, monkeypatch):
    extractor, native = _run(tmp_path, monkeypatch)
    assert native == [], native
    assert extractor.budget.read >= 4096, extractor.budget.read


class _Counting(decimal.Decimal):
    built = 0

    def as_tuple(self):
        type(self).built += 1
        return super().as_tuple()


def test_the_size_of_a_number_object_follows_its_digits_on_this_runtime():
    # _decimal_fits reads the size before it builds the tuple of digits; if a runtime stopped
    # reporting digits in the size this fails here, and not in the field
    assert sys.getsizeof(decimal.Decimal('1.' + '7' * 100000)) > pdf_module._DECIMAL_SIZE
    assert sys.getsizeof(decimal.Decimal('1e-30')) <= pdf_module._DECIMAL_SIZE
    assert sys.getsizeof(decimal.Decimal('12.' + '3' * pdf_module._MAX_NUMBER)) <= pdf_module._DECIMAL_SIZE


@pytest.mark.parametrize('digits', [10 ** 3, 10 ** 5, 10 ** 6])
def test_a_number_object_with_many_digits_is_turned_away_before_its_digits_are_built(digits):
    value = _Counting('1.' + '7' * digits)
    assert pdf_module._decimal_fits(value) is False
    assert _Counting.built == 0


def test_a_number_object_within_the_size_is_still_judged_by_its_digits_and_exponent():
    assert pdf_module._decimal_fits(decimal.Decimal('4.0')) is True
    assert pdf_module._decimal_fits(decimal.Decimal('1e-999999')) is False
    assert pdf_module._decimal_fits(decimal.Decimal('1.' + '7' * 40)) is False
    assert pdf_module._decimal_fits(decimal.Decimal('1.' + '7' * (pdf_module._MAX_NUMBER - 1))) is True
