"""Tenth round on the PDF containers: a predictor that fails is still charged for its output.

Review of the image only page PR found that the bounded decoder charged the PNG predictor's
output only after the reader returned, so a predictor that failed after it had made rows kept
the charge for the inflated stream and nothing for the rows. The decoder is the same function
in both PRs, so the container walk had the same gap.
"""
import zlib

import pytest
from PyPDF2 import filters as pdf_filters

from sunglasses.extractors import pdf as pdf_module


class _Stream(dict):
    pass


def _predicted(payload, columns):
    s = _Stream()
    s["/Filter"] = "/FlateDecode"
    s["/DecodeParms"] = {"/Predictor": 12, "/Columns": columns, "/BitsPerComponent": 8}
    s._data = zlib.compress(payload)
    return s


@pytest.fixture
def failing_predictor(monkeypatch):
    def spy(data, columns, rowlength):
        raise ValueError("a row of the wrong filter type, after earlier rows were made")

    monkeypatch.setattr(pdf_filters.FlateDecode, "_decode_png_prediction", staticmethod(spy))


@pytest.mark.parametrize("size,columns", [(90, 9), (1000, 9), (10_000, 99)])
def test_a_predictor_that_fails_keeps_the_charge_for_the_output_it_may_have_made(
        failing_predictor, size, columns):
    result = pdf_module._decode_bounded(_predicted(b"\x00" * size, columns), 1_000_000)
    assert result.state == "error"
    # The inflated stream, and room for the predictor's output, which can be as long again.
    assert result.spent >= 2 * size, result.spent


def test_the_charge_for_a_predictor_that_succeeds_is_what_it_made():
    rows = [b"\x01\x01\x01\x01\x01", b"\x01\x02\x02\x02\x02"]
    stream = _predicted(b"".join(rows), 4)
    result = pdf_module._decode_bounded(stream, 1_000_000)
    assert result.state == "ok"
    assert result.data == bytes([1, 2, 3, 4, 2, 4, 6, 8])
    assert result.spent == len(stream._data) + 10 + 8   # the input, the inflated stream, the rows
