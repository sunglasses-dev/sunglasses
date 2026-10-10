"""Eighth round on the image only page check: the decoder bounds the predictor before it runs,
and the picture walk pays for a chain it refuses.

* an empty decoded stream passes the reader's predictor rectangularity check, and the predictor
  then allocates a row of the declared length, so a few compressed bytes asked for as much
  memory as the dimensions named;
* the predictor's output was made before the budget was asked whether it fit;
* a content chain refused after its first stages (a filter that is not sized, a stage that
  fails) was dropped without being charged, so it could repeat on every page for free.
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
    result = pdf_module._decode_bounded(_stream(b"", columns), 1_000_000)
    assert predictor_calls == []
    assert result.state == "ok" and result.spent == 0


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
    result = pdf_module._decode_bounded(_stream(b"".join(rows), 4), 1_000_000)
    assert result.state == "ok"
    assert result.data == bytes([1, 2, 3, 4, 2, 4, 6, 8])
    assert result.spent == 10 + 8


# A content stream that is decoded and then refused is still paid for.
class _ContentStream(dict):
    def __init__(self, payload, extra):
        super().__init__(extra)
        self._data = zlib.compress(payload)

    def get_data(self):  # the walk must never call the reader's own decode
        raise AssertionError("the reader's decode was used")


def _walk():
    return pdf_module._ImageWalk(pdf_module._ReadBudget())


@pytest.mark.parametrize("state,extra,entries", [
    ("unsized", {"/Filter": ["/FlateDecode", "/RunLengthDecode"]}, 2),
    ("error", {"/Filter": ["/FlateDecode"], "/DecodeParms": {"/Predictor": 99}}, 1),
])
def test_a_refused_content_chain_is_charged_for_the_stages_it_decoded(state, extra, entries):
    walk = _walk()
    stream = _ContentStream(b"\x00" * 100_000, extra)
    with pytest.raises(ValueError):
        walk._content(stream)
    # The stages that were decoded, plus one visit for each entry of the filter list.
    assert walk.budget.read == 100_000 + entries * walk.VISIT_COST, state


@pytest.mark.parametrize("extra", [
    {"/Filter": ["/FlateDecode", "/RunLengthDecode"]},
    {"/Filter": ["/FlateDecode"], "/DecodeParms": {"/Predictor": 99}},
])
def test_the_same_refused_chain_on_many_pages_exhausts_the_shared_budget(extra):
    walk = _walk()
    stopped_at = None
    for page in range(200):
        try:
            walk._content(_ContentStream(b"\x00" * (1 << 20), extra))
        except ValueError:
            continue
        except pdf_module._WalkBudget:
            stopped_at = page
            break
    assert stopped_at is not None and stopped_at <= 65, stopped_at
