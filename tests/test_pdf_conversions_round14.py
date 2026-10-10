"""Fourteenth round, the review of the charge inventory: a decode parameter that is read as a number.

The inventory named the dereferences and the decode steps and left the conversions out. The one
that mattered is in the decode parameters: `int(predictor)`, `int(columns)` and `int(bits)` were
called on whatever the dictionary held, so a text or byte value of any length was scanned to find
out that it is not a number. A value longer than any number written in a PDF is now refused
before it is converted, and the stream is reported as an error the way a value that is not a
number was.
"""
import zlib

from sunglasses.extractors import pdf as pdf_module


class _Stream(dict):
    def __init__(self, data=b"", **entries):
        super().__init__(entries)
        self._data = data


def test_a_decode_parameter_longer_than_any_number_is_not_converted(monkeypatch):
    seen = []
    real = int

    def counting(value, *args):
        seen.append(len(value) if isinstance(value, (str, bytes)) else 0)
        return real(value, *args)

    monkeypatch.setattr(pdf_module, "int", counting, raising=False)
    params = {"/Predictor": "1" * 100_000, "/Columns": 10}
    stream = _Stream(zlib.compress(bytes(22)), **{"/Filter": ["/FlateDecode"], "/DecodeParms": [params]})
    result = pdf_module._decode_bounded(stream, 1 << 20, lambda: 32)
    assert result.state == "error", result.state
    assert max(seen, default=0) < 100, seen


def test_a_long_byte_value_is_refused_the_same_way(monkeypatch):
    params = {"/Columns": b"9" * 100_000}
    stream = _Stream(zlib.compress(bytes(22)), **{"/Filter": ["/FlateDecode"], "/DecodeParms": [params]})
    assert pdf_module._decode_bounded(stream, 1 << 20, lambda: 32).state == "error"


def test_ordinary_parameters_are_read_as_before():
    params = {"/Predictor": 12, "/Columns": 10, "/BitsPerComponent": 8}
    assert pdf_module._predictor_of(params, lambda: 0) == (12, 10, 8)
    assert pdf_module._predictor_of({"/Predictor": "12", "/Columns": b"10"}, lambda: 0) == (12, 10, 8)
    assert pdf_module._predictor_of(None, lambda: 0) == (1, 1, 8)
    stream = _Stream(zlib.compress(bytes(22)), **{"/Filter": "/FlateDecode"})
    assert pdf_module._decode_bounded(stream, 1 << 20, lambda: 32).state == "ok"


def test_a_value_that_is_not_a_number_but_is_short_still_errors():
    stream = _Stream(zlib.compress(bytes(22)), **{"/Filter": ["/FlateDecode"], "/DecodeParms": [{"/Columns": "ten"}]})
    assert pdf_module._decode_bounded(stream, 1 << 20, lambda: 32).state == "error"
