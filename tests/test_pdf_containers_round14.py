"""Fourteenth round on the PDF containers, at the caller: an attachment is judged on what it
decodes to, not on its input and output together, and the extractor's budget holds the decoder's
spend before a decode parameter is resolved.
"""
import os
import zlib

from sunglasses.extractors import pdf as pdf_module
from sunglasses.extractors.pdf import PDFExtractor


class _Stream(dict):
    def __init__(self, data=b"", **entries):
        super().__init__(entries)
        self._data = data


class _Deref:
    def __init__(self, budget, target):
        self.budget, self.target, self.seen = budget, target, None

    def get_object(self):
        self.seen = self.budget.read
        return self.target


def _extractor():
    extractor = PDFExtractor()
    extractor.failures = []
    return extractor


def _stored(payload):
    # A stored (level 0) Flate stream: the input is as long as the output plus a few bytes.
    return zlib.compress(payload, 0)


def test_an_attachment_whose_input_and_output_each_fit_the_cap_is_read():
    payload = os.urandom(600)
    raw = _stored(payload)
    cap = 1000
    assert len(raw) <= cap and len(payload) <= cap and len(raw) + len(payload) > cap
    stream = _Stream(raw, **{"/Filter": ["/FlateDecode"]})
    extractor = _extractor()
    assert extractor._decode_stream(stream, "attachment", cap) == payload
    assert extractor.failures == []


def test_an_attachment_that_decodes_past_the_cap_is_refused_and_says_so():
    stream = _Stream(zlib.compress(bytes(2000)), **{"/Filter": ["/FlateDecode"]})
    extractor = _extractor()
    assert extractor._decode_stream(stream, "attachment", 1000) is None
    assert extractor.failures == ["attachment larger than 1000 bytes; not inspected"]


def test_an_unfiltered_attachment_past_the_cap_is_refused_and_one_under_it_is_read():
    extractor = _extractor()
    assert extractor._decode_stream(_Stream(bytes(1001)), "attachment", 1000) is None
    assert extractor.failures == ["attachment larger than 1000 bytes; not inspected"]
    extractor = _extractor()
    assert extractor._decode_stream(_Stream(bytes(1000)), "attachment", 1000) == bytes(1000)


def test_a_refusal_by_the_document_budget_does_not_blame_the_cap():
    extractor = _extractor()
    extractor.budget.read = extractor.budget.MAX_BYTES - 400
    stream = _Stream(zlib.compress(bytes(5000)), **{"/Filter": ["/FlateDecode"]})
    assert extractor._decode_stream(stream, "attachment", 10_000_000) is None
    assert not any("larger than" in message for message in extractor.failures), extractor.failures


def test_the_budget_holds_the_decoder_spend_when_a_decode_parameter_is_resolved():
    extractor = _extractor()
    raw = zlib.compress(bytes(300))
    deref = _Deref(extractor.budget, [{"/Predictor": 1}])
    stream = _Stream(raw, **{"/Filter": ["/FlateDecode"], "/DecodeParms": deref})
    assert extractor._decode_stream(stream, "attachment") == bytes(300)
    assert deref.seen >= len(raw) + 300, deref.seen


def test_the_whole_is_charged_once():
    def spent(params):
        extractor = _extractor()
        stream = _Stream(zlib.compress(bytes(300)), **{"/Filter": ["/FlateDecode"], "/DecodeParms": params})
        extractor._decode_stream(stream, "attachment")
        return extractor.budget.read

    assert spent(_Deref(_extractor().budget, [{"/Predictor": 1}])) == spent([{"/Predictor": 1}])
