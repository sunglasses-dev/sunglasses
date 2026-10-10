"""Eleventh round on the PDF containers: the decoder's setup is paid for entry by entry.

Review of the tenth round found two walks that touched objects before the budget was asked:

* the filter list of a stream and the list of its decode parameters were resolved whole, in the
  caller and again in the decoder, so a stream with twenty thousand filters cost twenty thousand
  resolutions whatever was left of the document budget;
* an annotation that an /Annots array listed again was recognised before it was charged, so the
  repeats of one entry cost nothing.

Every touch of an entry of an array is now behind one charge, taken before the entry is resolved,
and an inflate call that fails is charged for the most it could have produced.
"""
import zlib

import pytest

from sunglasses.extractors import pdf as pdf_module
from sunglasses.extractors.pdf import PDFExtractor

ENTRIES = 20_000
LEFT = 64   # bytes of the document budget left to the walk under test


class _Counted:
    """An object that counts how often it is resolved."""
    resolutions = 0

    def __init__(self, target):
        self._target = target

    def get_object(self):
        type(self).resolutions += 1
        return self._target


@pytest.fixture(autouse=True)
def _reset():
    _Counted.resolutions = 0


class _Stream(dict):
    def __init__(self, data=b"", **entries):
        super().__init__(entries)
        self._data = data


class _Charges:
    """A charge that counts its calls and stops the walk after `limit` of them."""

    def __init__(self, limit=None):
        self.calls, self.limit = 0, limit

    def __call__(self):
        if self.limit is not None and self.calls >= self.limit:
            raise pdf_module._WalkBudget()
        self.calls += 1


def _spent_extractor(left=LEFT):
    extractor = PDFExtractor()
    extractor.failures = []
    extractor.budget.read = extractor.budget.MAX_BYTES - left
    return extractor


# 1. The filter list is charged entry by entry.
def test_a_filter_array_is_not_resolved_once_the_charge_is_refused():
    stream = _Stream(zlib.compress(b"x"), **{"/Filter": [_Counted("/FlateDecode")] * 8})
    with pytest.raises(pdf_module._WalkBudget):
        pdf_module._decode_bounded(stream, 1 << 20, _Charges(limit=0))
    assert _Counted.resolutions == 0


def test_a_filter_array_is_resolved_only_as_far_as_it_was_paid_for():
    stream = _Stream(zlib.compress(b"x"), **{"/Filter": [_Counted("/FlateDecode")] * 8})
    with pytest.raises(pdf_module._WalkBudget):
        pdf_module._decode_bounded(stream, 1 << 20, _Charges(limit=3))
    assert _Counted.resolutions == 3, _Counted.resolutions


def test_a_filter_chain_longer_than_any_real_one_is_refused_before_it_is_touched():
    charge = _Charges()
    stream = _Stream(b"x", **{"/Filter": [_Counted("/FlateDecode")] * ENTRIES})
    result = pdf_module._decode_bounded(stream, 1 << 20, charge)
    assert result.state == "unsized"
    assert _Counted.resolutions == 0 and charge.calls == 0


def test_a_decode_parameter_array_is_charged_before_each_entry_is_resolved():
    stream = _Stream(zlib.compress(b"x" * 100),
                     **{"/Filter": "/FlateDecode",
                        "/DecodeParms": [_Counted({"/Predictor": 1})] * 8})
    with pytest.raises(pdf_module._WalkBudget):
        pdf_module._decode_bounded(stream, 1 << 20, _Charges(limit=2))
    assert _Counted.resolutions == 2, _Counted.resolutions


def test_a_decode_parameter_array_longer_than_any_real_one_is_refused_unread():
    charge = _Charges()
    stream = _Stream(zlib.compress(b"x" * 100),
                     **{"/Filter": "/FlateDecode",
                        "/DecodeParms": [_Counted({"/Predictor": 1})] * ENTRIES})
    result = pdf_module._decode_bounded(stream, 1 << 20, charge)
    assert result.state == "error"
    assert _Counted.resolutions == 0 and charge.calls == 0


def test_an_ordinary_chain_is_charged_once_per_entry_and_still_decodes():
    charge = _Charges()
    stream = _Stream(zlib.compress(b"hello"),
                     **{"/Filter": ["/FlateDecode"], "/DecodeParms": [{"/Predictor": 1}]})
    result = pdf_module._decode_bounded(stream, 1 << 20, charge)
    assert result.state == "ok" and result.data == b"hello"
    assert charge.calls == 2


# 2. The extractor passes the document budget to the decoder.
def test_the_extractor_stops_resolving_a_filter_array_when_the_budget_is_gone():
    extractor = _spent_extractor()
    stream = _Stream(zlib.compress(b"x"), **{"/Filter": [_Counted("/FlateDecode")] * 12})
    assert extractor._decode_stream(stream, "attachment") is None
    assert _Counted.resolutions <= LEFT // PDFExtractor.VISIT_COST, _Counted.resolutions
    assert any("limit" in f and "not inspected" in f for f in extractor.failures), extractor.failures


def test_the_extractor_names_a_filter_chain_it_will_not_read():
    extractor = PDFExtractor()
    extractor.failures = []
    stream = _Stream(b"x", **{"/Filter": [_Counted("/FlateDecode")] * ENTRIES})
    assert extractor._decode_stream(stream, "attachment") is None
    assert _Counted.resolutions == 0
    assert any("attachment" in f and "not inspected" in f for f in extractor.failures), extractor.failures


# 3. Every annotation entry is charged, and an array that was read is not read again.
def _annots(n):
    return [{"/Subtype": "/Link"} for _ in range(n)]


def test_an_annotation_listed_again_is_charged_each_time():
    extractor = PDFExtractor()
    extractor.failures = []
    one = {"/Subtype": "/Link"}
    before = extractor.budget.read
    extractor._extract_page_extras({"/Annots": [one] * 1000}, 0)
    assert extractor.budget.read - before >= 1000 * PDFExtractor.VISIT_COST


def test_a_list_of_repeats_stops_when_the_budget_is_gone_and_says_so():
    extractor = _spent_extractor()
    one = {"/Subtype": "/Link"}
    extractor._extract_page_extras({"/Annots": [one] * ENTRIES}, 0)
    assert any("limit" in f and "not inspected" in f for f in extractor.failures), extractor.failures


def test_an_annots_array_shared_by_pages_is_read_once():
    extractor = PDFExtractor()
    extractor.failures = []
    shared = _annots(100)
    extractor._extract_page_extras({"/Annots": shared}, 0)
    after_first = extractor.budget.read
    for index in range(1, 50):
        extractor._extract_page_extras({"/Annots": shared}, index)
    assert extractor.budget.read == after_first


# 4. A failing inflate call is charged for the most it could have made.
def _damaged(size=1 << 22):
    """A stream whose first part inflates and which then meets a block that is not valid."""
    packer = zlib.compressobj()
    return packer.compress(bytes(size)) + packer.flush(zlib.Z_SYNC_FLUSH) + b"\x07" * 8


def test_no_inflate_call_asks_for_more_than_one_step(monkeypatch):
    asked = []
    real = zlib.decompressobj

    def spy(*args, **kwargs):
        inner = real(*args, **kwargs)

        class Wrapped:
            def __getattr__(self, name):
                return getattr(inner, name)

            def decompress(self, data, max_length=0):
                asked.append(max_length)
                return inner.decompress(data, max_length)

        return Wrapped()

    monkeypatch.setattr(pdf_module.zlib, "decompressobj", spy)
    pdf_module._inflate(zlib.compress(bytes(1 << 22)), 1 << 30)
    assert asked and max(asked) <= pdf_module._INFLATE_STEP, max(asked)


def test_a_damaged_stream_is_charged_for_the_call_that_failed():
    stream = _Stream(_damaged(), **{"/Filter": "/FlateDecode"})
    assert pdf_module._inflate(stream._data, 1 << 30)[3] is True
    result = pdf_module._decode_bounded(stream, 1 << 30)
    assert result.spent >= pdf_module._INFLATE_STEP, result.spent


def test_a_stream_that_is_not_damaged_is_charged_for_what_it_made_only():
    stream = _Stream(zlib.compress(bytes(5000)), **{"/Filter": "/FlateDecode"})
    result = pdf_module._decode_bounded(stream, 1 << 30)
    assert result.state == "ok" and result.spent == 5000
