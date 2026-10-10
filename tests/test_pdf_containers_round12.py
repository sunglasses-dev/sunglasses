"""Twelfth round on the PDF containers: the decoder has one ledger.

Review of the eleventh round of the sibling image check found that the decoder was handed the
budget left when it was called and its setup (the filter list and the decode parameters, charged
entry by entry) then spent part of it, so the stages were sized against space that was already
gone. The decoder takes every setup charge off the allowance it sizes the stages against.
"""
import zlib

import pytest

from sunglasses.extractors import pdf as pdf_module
from sunglasses.extractors.pdf import PDFExtractor

VISIT = PDFExtractor.VISIT_COST


class _Stream(dict):
    def __init__(self, data=b"", **entries):
        super().__init__(entries)
        self._data = data


def _charging(cost):
    return lambda: cost


def test_a_stage_is_sized_against_what_is_left_after_the_setup_charges():
    stream = _Stream(zlib.compress(bytes(100)), **{"/Filter": ["/FlateDecode"]})
    assert pdf_module._decode_bounded(stream, 100 + VISIT - 1, _charging(VISIT)).state == "big"
    ok = pdf_module._decode_bounded(stream, 100 + VISIT, _charging(VISIT))
    assert ok.state == "ok" and ok.spent == 100


def test_the_predictor_does_not_run_on_space_the_setup_already_spent(monkeypatch):
    from PyPDF2 import filters as pdf_filters

    ran = []
    real = pdf_filters.FlateDecode._decode_png_prediction
    monkeypatch.setattr(pdf_filters.FlateDecode, "_decode_png_prediction",
                        staticmethod(lambda *a: ran.append(1) or real(*a)))
    stream = _Stream(zlib.compress(bytes(22)),
                     **{"/Filter": ["/FlateDecode"],
                        "/DecodeParms": [{"/Predictor": 12, "/Columns": 10}]})
    assert pdf_module._decode_bounded(stream, 2 * VISIT + 44 - 1, _charging(VISIT)).state == "big"
    assert ran == []
    assert pdf_module._decode_bounded(stream, 2 * VISIT + 44, _charging(VISIT)).state == "ok"
    assert ran == [1]


def test_a_decoder_with_no_setup_charge_sizes_stages_as_before():
    stream = _Stream(zlib.compress(bytes(100)), **{"/Filter": "/FlateDecode"})
    assert pdf_module._decode_bounded(stream, 99).state == "big"
    assert pdf_module._decode_bounded(stream, 100).state == "ok"


def test_the_extractor_hands_the_decoder_what_is_left_after_its_own_setup(monkeypatch):
    asked = []
    real = pdf_module._inflate
    monkeypatch.setattr(pdf_module, "_inflate", lambda data, room: asked.append(room) or real(data, room))
    extractor = PDFExtractor()
    extractor.failures = []
    extractor.budget.read = extractor.budget.MAX_BYTES - (2 * VISIT + 150)   # two charges of setup, then the stage
    stream = _Stream(zlib.compress(bytes(100)), **{"/Filter": ["/FlateDecode"]})
    assert extractor._decode_stream(stream, "attachment") == bytes(100)
    assert asked == [150], asked


# --- work that sizes a stream is paid for before it is done ---------------------------------

def _lzw_stream(n):
    # 9-bit codes that are not a valid LZW stream: no end code, so the sizing pass reads it all
    # and gives up ("unsized").
    return _Stream(b"\xff" * n, **{"/Filter": ["/LZWDecode"]})


def test_a_refused_lzw_sizing_pass_is_charged_for_the_input_it_read():
    result = pdf_module._decode_bounded(_lzw_stream(4096), 1 << 20)
    assert result.state == "unsized"
    assert result.spent >= 4096


def test_lzw_sizing_does_not_start_when_the_input_alone_passes_the_allowance(monkeypatch):
    ran = []
    real = pdf_module._lzw_length
    monkeypatch.setattr(pdf_module, "_lzw_length", lambda *a: ran.append(1) or real(*a))
    assert pdf_module._decode_bounded(_lzw_stream(4096), 64).state == "big"
    assert ran == []


def test_ascii85_sizing_does_not_start_when_the_input_alone_passes_the_allowance(monkeypatch):
    ran = []
    real = pdf_module._ascii85_length
    monkeypatch.setattr(pdf_module, "_ascii85_length", lambda *a: ran.append(1) or real(*a))
    stream = _Stream(b"9" * 4096, **{"/Filter": ["/ASCII85Decode"]})
    assert pdf_module._decode_bounded(stream, 64).state == "big"
    assert ran == []


def test_repeated_refused_lzw_streams_spend_the_document_budget():
    extractor = PDFExtractor()
    extractor.failures = []
    before = extractor.budget.remaining()
    for _ in range(20):
        extractor._decode_stream(_lzw_stream(4096), "attachment")
    assert before - extractor.budget.remaining() >= 20 * 4096


# --- name-tree pairs ------------------------------------------------------------------------

def _tree_extractor(room):
    extractor = PDFExtractor()
    extractor.failures = []
    extractor.budget.read = extractor.budget.MAX_BYTES - room
    return extractor


def test_a_name_tree_pair_is_charged_before_its_key_is_touched(monkeypatch):
    touched = []
    real = PDFExtractor._as_text
    monkeypatch.setattr(PDFExtractor, "_as_text", lambda self, v: touched.append(1) or real(self, v))
    names = []
    for i in range(50):
        names += [b"k" * 1000, {"/S": "/JavaScript"}]
    extractor = _tree_extractor(0)
    assert extractor._name_tree({"/Names": names}, "document scripts", 256) == []
    assert touched == []


def test_a_name_tree_stops_at_the_pair_that_exhausts_the_budget(monkeypatch):
    touched = []
    real = PDFExtractor._as_text
    monkeypatch.setattr(PDFExtractor, "_as_text", lambda self, v: touched.append(1) or real(self, v))
    names = []
    for i in range(50):
        names += ["k%d" % i, {"/S": "/JavaScript"}]
    extractor = _tree_extractor(3 * VISIT + 10)
    extractor._name_tree({"/Names": names}, "document scripts", 256)
    assert len(touched) <= 3, touched
    assert any("rest was not inspected" in f for f in extractor.failures), extractor.failures


def test_a_byte_string_is_charged_for_its_bytes_before_it_is_converted(monkeypatch):
    converted = []
    real = PDFExtractor._bytes_text
    monkeypatch.setattr(PDFExtractor, "_bytes_text", lambda self, v: converted.append(len(v)) or real(self, v))
    extractor = _tree_extractor(100)
    assert extractor._as_text(b"x" * 100000) == ""
    assert converted == []


# --- a charge that comes after a stage can overdraw the allowance; the next stage must see it ---

def test_a_late_setup_charge_cannot_leave_the_next_stage_without_a_limit(monkeypatch):
    """The decode parameters are charged after each Flate stage. When that charge took more than was
    left, the next stage was inflated with a limit of zero or less, and zlib reads a zero limit as
    "no limit"."""
    inner = zlib.compress(bytes(100000))
    stream = _Stream(zlib.compress(inner),
                     **{"/Filter": ["/FlateDecode", "/FlateDecode"], "/DecodeParms": [{}]})
    asked = []
    real = pdf_module._inflate

    def spy(data, room):
        asked.append(room)
        return real(data, room)

    monkeypatch.setattr(pdf_module, "_inflate", spy)
    overdrawn = 0
    for cap in range(2 * VISIT, 6 * VISIT + 2 * len(inner)):
        asked.clear()
        result = pdf_module._decode_bounded(stream, cap, _charging(VISIT))
        assert all(room > 0 for room in asked), (cap, asked)
        assert result.state != "ok" or result.spent <= cap, (cap, result.spent)
        overdrawn += result.state == "big"
    assert overdrawn > 0


def test_a_stage_that_starts_with_nothing_left_is_refused_not_run(monkeypatch):
    ran = []
    real = pdf_module._inflate
    monkeypatch.setattr(pdf_module, "_inflate", lambda *a: ran.append(1) or real(*a))
    stream = _Stream(zlib.compress(bytes(100)), **{"/Filter": ["/FlateDecode"]})
    for room in (0, -1, -VISIT):
        result = pdf_module._decode_bounded(stream, room)
        assert result.state == "big" and result.spent >= 1
    assert ran == []
