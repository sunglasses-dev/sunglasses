"""Eighth round on the PDF containers: the predictor is bounded before it runs.

Review of the seventh round found that the bounded decoder handed the predictor dimensions of
a stream to the reader's PNG predictor unchecked:

* an empty decoded stream passes the predictor's rectangularity check, and the predictor then
  allocates a row of the declared length, so a few compressed bytes asked for as much memory
  as the dimensions named, whatever was left of the document budget;
* the predictor's output was made before the budget was asked whether it fit.
"""
import zlib

import pytest
from PyPDF2 import filters as pdf_filters

from sunglasses.extractors import pdf as pdf_module


class _Stream(dict):
    pass


def _stream(payload=b"", columns=1, predictor=12, bits=8):
    s = _Stream()
    s["/Filter"] = "/FlateDecode"
    s["/DecodeParms"] = {"/Predictor": predictor, "/Columns": columns, "/BitsPerComponent": bits}
    s._data = zlib.compress(payload)
    return s


@pytest.fixture
def predictor_calls(monkeypatch):
    calls = []
    real = pdf_filters.FlateDecode._decode_png_prediction

    def spy(data, columns, rowlength):
        calls.append((len(data), columns, rowlength))
        if rowlength > 100_000:
            # What the real predictor would allocate for this row is the thing under test.
            return b""
        return real(data, columns, rowlength)

    monkeypatch.setattr(pdf_filters.FlateDecode, "_decode_png_prediction", staticmethod(spy))
    return calls


@pytest.mark.parametrize("columns", [10 ** 6, 10 ** 9, 2 ** 40])
def test_an_empty_stream_never_reaches_the_predictor_whatever_its_columns(predictor_calls, columns):
    stream = _stream(b"", columns)
    result = pdf_module._decode_bounded(stream, 1_000_000)
    assert predictor_calls == []
    assert result.state == "ok" and result.spent == len(stream._data)   # the input only


@pytest.mark.parametrize("columns", [10 ** 6, 10 ** 9, 2 ** 40])
def test_a_row_longer_than_what_is_left_of_the_budget_is_refused_before_the_predictor(predictor_calls, columns):
    result = pdf_module._decode_bounded(_stream(b"\x00" * 10, columns), 1_000_000)
    assert predictor_calls == []
    assert result.state == "big"


@pytest.mark.parametrize("bits", [16, 64])
def test_the_row_is_measured_in_bytes_not_columns(predictor_calls, bits):
    # 1000 columns of 16 or 64 bits are 2000 or 8000 bytes a row, more than a budget of 1500.
    result = pdf_module._decode_bounded(_stream(b"\x00" * 10, 1000, bits=bits), 1500)
    assert predictor_calls == []
    assert result.state == "big"


def test_the_output_is_reserved_before_the_predictor_runs(predictor_calls):
    # Nine rows of nine columns inflate to 90 bytes; the predictor would add 90 more.
    result = pdf_module._decode_bounded(_stream(b"\x00" * 90, 9), 100)
    assert predictor_calls == []
    assert result.state == "big"


@pytest.mark.parametrize("columns,bits", [(0, 8), (-5, 8), (4, 0), (4, -8)])
def test_dimensions_that_cannot_describe_a_row_are_an_error_before_the_predictor(predictor_calls, columns, bits):
    result = pdf_module._decode_bounded(_stream(b"\x00" * 10, columns, bits=bits), 1_000_000)
    assert predictor_calls == []
    assert result.state == "error"


def test_an_ordinary_predicted_stream_is_still_decoded_and_charged():
    rows = [b"\x01\x01\x01\x01\x01", b"\x01\x02\x02\x02\x02"]
    stream = _stream(b"".join(rows), 4)
    result = pdf_module._decode_bounded(stream, 1_000_000)
    assert result.state == "ok"
    assert result.data == bytes([1, 2, 3, 4, 2, 4, 6, 8])
    assert result.spent == len(stream._data) + 10 + 8
