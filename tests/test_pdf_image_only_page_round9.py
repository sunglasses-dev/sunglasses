"""Ninth round on the image only page check: what a failed predictor and a content array cost.

Review of the eighth round found two places where work was done before the budget was asked:

* a PNG predictor that fails after it has produced rows was charged only for what the stream
  inflated to, so the output it had already made cost nothing;
* a page content array was resolved whole, and every stream in it was decoded under the one
  visit charged for the page, so an array of empty streams was read for free.
"""
import zlib

import pytest
from PyPDF2 import filters as pdf_filters

from sunglasses.extractors import pdf as pdf_module


class _Stream(dict):
    """A stream the way PyPDF2 hands one over: a dictionary with its raw bytes."""

    def __init__(self, payload=b"", flate=True, **entries):
        super().__init__(entries)
        if flate:
            self["/Filter"] = "/FlateDecode"
        self._data = zlib.compress(payload) if flate else payload

    def get_data(self):
        raise AssertionError("the reader's own decode must never be used")


def _predicted(payload, columns, **kwargs):
    stream = _Stream(payload, **kwargs)
    stream["/DecodeParms"] = {"/Predictor": 12, "/Columns": columns, "/BitsPerComponent": 8}
    return stream


# 1. A predictor that fails after it has made output is charged for that output.
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


def test_a_predictor_that_fails_cannot_be_repeated_for_free(failing_predictor):
    budget = pdf_module._ReadBudget()
    walk = pdf_module._ImageWalk(budget)
    stopped = None
    for page in range(200):
        try:
            walk._content(_predicted(b"\x00" * (1 << 20), 1 << 10))
        except ValueError:
            continue
        except pdf_module._WalkBudget:
            stopped = page
            break
    # 64 MiB at two MiB a page is 32 pages; without the reservation it is 64.
    assert stopped is not None and stopped <= 34, stopped


def test_the_charge_for_a_predictor_that_succeeds_is_what_it_made():
    rows = [b"\x01\x01\x01\x01\x01", b"\x01\x02\x02\x02\x02"]
    result = pdf_module._decode_bounded(_predicted(b"".join(rows), 4), 1_000_000)
    assert result.state == "ok"
    assert result.data == bytes([1, 2, 3, 4, 2, 4, 6, 8])
    assert result.spent == 10 + 8


# 2. A content array is paid for entry by entry.
class _Entry:
    """An array entry that counts how often it is resolved."""
    resolutions = 0

    def __init__(self, stream):
        self._stream = stream

    def get_object(self):
        type(self).resolutions += 1
        return self._stream


def _empty():
    return _Stream(b"")


def _walk():
    return pdf_module._ImageWalk(pdf_module._ReadBudget())


def _decode_counter(monkeypatch):
    calls = {"n": 0}
    real = pdf_module._decode_bounded

    def counted(*args, **kwargs):
        calls["n"] += 1
        return real(*args, **kwargs)

    monkeypatch.setattr(pdf_module, "_decode_bounded", counted)
    return calls


def test_a_content_array_of_empty_streams_stops_when_the_allowance_is_gone(monkeypatch):
    _Entry.resolutions = 0
    calls = _decode_counter(monkeypatch)
    walk = _walk()
    walk.budget.read = walk.budget.MAX_BYTES - 32
    holder = {"/Contents": [_Entry(_empty()) for _ in range(20_000)]}
    with pytest.raises(pdf_module._WalkBudget):
        walk._content(holder)
    assert calls["n"] <= 2, calls["n"]
    assert _Entry.resolutions <= 3, _Entry.resolutions


def test_every_entry_of_a_content_array_is_charged_even_when_it_decodes_to_nothing():
    walk = _walk()
    holder = {"/Contents": [_empty() for _ in range(100)]}
    assert walk._content(holder) == b"\n".join([b""] * 100)
    # The charge also covers the separator the join puts between two entries.
    assert walk.budget.read >= 100 * walk.VISIT_COST


def test_a_single_content_stream_is_not_charged_twice():
    walk = _walk()
    walk._content({"/Contents": _empty()})
    assert walk.budget.read == 0
    walk._content(_empty())
    assert walk.budget.read == 0


def test_a_content_array_inside_the_allowance_is_still_read():
    parts = [_Stream(b"q"), _Stream(b"Q")]
    assert _walk()._content({"/Contents": parts}) == b"q\nQ"
