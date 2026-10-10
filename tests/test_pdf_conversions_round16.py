"""Sixteenth round on the conversion of decode parameters: a number object is length-capped too.

The fourteenth round refused a text or byte value longer than any number before `int()` was called
on it, and left a number object as it stood. A decimal number object (the reader's FloatObject)
holds every digit that was written in the file, and `int()` on it is not linear in the digits, so
a parameter with a hundred thousand digits was converted at a cost nothing had charged. A number
object with more digits than any number written in a PDF, or an exponent that large, is now refused
the way a long text value is, and the stream is reported as an error.
"""
import io
import zlib

from PyPDF2.generic import FloatObject, read_object

from sunglasses.extractors import pdf as pdf_module


class _Stream(dict):
    def __init__(self, data=b"", **entries):
        super().__init__(entries)
        self._data = data


def _float(text):
    # the reader parses a number inside a dictionary, as a decode parameter is written in a file
    return read_object(io.BytesIO(b"<< /N " + text.encode() + b" >>"), None)["/N"]


def _stream(params):
    return _Stream(zlib.compress(bytes(22)), **{"/Filter": ["/FlateDecode"], "/DecodeParms": [params]})


def test_a_number_object_with_more_digits_than_any_number_is_not_converted(monkeypatch):
    seen = []
    real = int

    def counting(value, *args):
        if isinstance(value, FloatObject):
            seen.append(len(value.as_tuple().digits))
        return real(value, *args)

    monkeypatch.setattr(pdf_module, "int", counting, raising=False)
    params = {"/Columns": _float("9" * 10_001 + ".0")}
    assert isinstance(params["/Columns"], FloatObject)
    result = pdf_module._decode_bounded(_stream(params), 1 << 20, lambda: 32)
    assert result.state == "error", result.state
    assert max(seen, default=0) <= pdf_module._MAX_NUMBER, seen


def test_a_number_object_with_a_huge_exponent_is_refused_too():
    params = {"/Columns": FloatObject("1E+400")}
    assert pdf_module._decode_bounded(_stream(params), 1 << 20, lambda: 32).state == "error"


def test_ordinary_number_objects_are_read_as_before():
    params = {"/Predictor": _float("12.0"), "/Columns": _float("10.0"), "/BitsPerComponent": _float("8.0")}
    assert pdf_module._predictor_of(params, lambda: 0) == (12, 10, 8)
    assert pdf_module._decode_bounded(_stream(params), 1 << 20, lambda: 32).state == "ok"


def test_a_number_object_at_the_longest_length_is_still_read():
    longest = pdf_module._MAX_NUMBER
    value = _float("1" + "0" * (longest - 1) + ".0")
    assert len(value.as_tuple().digits) == longest + 1
    refused = {"/Columns": value}
    assert pdf_module._decode_bounded(_stream(refused), 1 << 20, lambda: 32).state == "error"
    fits = _float("1" + "0" * (longest - 2) + ".0")
    assert len(fits.as_tuple().digits) == longest
    assert pdf_module._whole(fits) == 10 ** (longest - 2)
