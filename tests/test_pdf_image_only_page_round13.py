"""Fourteenth round on the image only page check: three places where the shared decoder still touched
something before it was paid for (the same three as the thirteenth round on the PDF containers).

* A filter name was turned into text whatever its length. A name longer than any real one is
  now not converted, and the chain it belongs to is refused as a filter that is not sized.
* The stream's own Flate input was never on the ledger, only its output. The input is now
  charged before the first inflate, as it already is for ASCII85 and LZW.
* The decoder subtracts only what its charge callback returns from the allowance it sizes the
  stages against. A dereference of a decode parameter can spend more than that (it can inflate
  an object stream, which spends the document budget directly), and the allowance did not fall.
  The decoder now also asks what the budget has left, before each stage and after the decode
  parameters are read.
"""
import base64
import zlib

from PyPDF2 import filters as pdf_filters

from sunglasses.extractors import pdf as pdf_module

VISIT = pdf_module._ImageWalk.VISIT_COST


class _Stream(dict):
    def __init__(self, data=b"", **entries):
        super().__init__(entries)
        self._data = data

    def get_data(self):
        return self._data


class _Loud(str):
    """A name that records every time it is turned into text."""
    converted = 0

    def __str__(self):
        type(self).converted += 1
        return str.__str__(self)


# --- a filter name is not converted at any length -------------------------------------------

def test_a_filter_name_longer_than_any_real_one_is_not_converted():
    _Loud.converted = 0
    stream = _Stream(b"x", **{"/Filter": [_Loud("/" + "A" * 10_000)]})
    result = pdf_module._decode_bounded(stream, 1 << 20, lambda: VISIT)
    assert _Loud.converted == 0, _Loud.converted
    assert result.state == "unsized"


def test_a_single_long_filter_name_is_not_converted_either():
    _Loud.converted = 0
    stream = _Stream(b"x", **{"/Filter": _Loud("/" + "A" * 10_000)})
    result = pdf_module._decode_bounded(stream, 1 << 20, lambda: VISIT)
    assert _Loud.converted == 0, _Loud.converted
    assert result.state == "unsized"


def test_a_filter_name_of_a_real_length_is_read_as_before():
    stream = _Stream(zlib.compress(bytes(10)), **{"/Filter": ["/FlateDecode"]})
    result = pdf_module._decode_bounded(stream, 1 << 20, lambda: VISIT)
    assert result.state == "ok" and result.data == bytes(10)


# --- the stream's own Flate input is charged ------------------------------------------------

def test_the_flate_input_is_on_the_ledger_before_it_is_inflated(monkeypatch):
    raw = zlib.compress(bytes(10))
    stream = _Stream(raw, **{"/Filter": ["/FlateDecode"]})
    asked = []
    real = pdf_module._inflate
    monkeypatch.setattr(pdf_module, "_inflate", lambda data, room: asked.append(room) or real(data, room))
    result = pdf_module._decode_bounded(stream, 1000)
    assert result.state == "ok"
    assert result.spent == 10 + len(raw)
    assert asked == [1000 - len(raw)], asked


def test_a_flate_input_larger_than_the_allowance_is_refused_without_inflating(monkeypatch):
    raw = zlib.compress(bytes(10))
    stream = _Stream(raw, **{"/Filter": ["/FlateDecode"]})
    ran = []
    real = pdf_module._inflate
    monkeypatch.setattr(pdf_module, "_inflate", lambda data, room: ran.append(1) or real(data, room))
    assert pdf_module._decode_bounded(stream, len(raw) - 1).state == "big"
    assert ran == []


def test_a_later_stage_is_not_charged_its_input_a_second_time():
    # ASCII85 first, then Flate: the Flate input is the first stage's output, already charged.
    raw = base64.a85encode(zlib.compress(bytes(10))) + b"~>"
    stream = _Stream(raw, **{"/Filter": ["/ASCII85Decode", "/FlateDecode"]})
    result = pdf_module._decode_bounded(stream, 1000)
    assert result.state == "ok" and result.data == bytes(10)
    compressed = len(zlib.compress(bytes(10)))
    assert result.spent == len(raw) + compressed + 10, result.spent


# --- a spend made inside a dereference lowers the allowance ---------------------------------

class _Deref:
    """Resolving this spends part of the document budget directly, the way a dereference does
    when it inflates an object stream, and returns the decode parameters."""
    def __init__(self, budget, size, target):
        self._budget, self._size, self._target = budget, size, target

    def get_object(self):
        self._budget.spend(self._size)
        return self._target


def test_a_spend_inside_the_decode_parameter_dereference_lowers_the_allowance(monkeypatch):
    budget = pdf_module._ReadBudget()
    left = 400
    budget.read = budget.MAX_BYTES - left
    charge = lambda: (budget.spend(VISIT), VISIT)[1]
    ran = []
    real = pdf_filters.FlateDecode._decode_png_prediction
    monkeypatch.setattr(pdf_filters.FlateDecode, "_decode_png_prediction",
                        staticmethod(lambda *a: ran.append(1) or real(*a)))
    params = {"/Predictor": 12, "/Columns": 10}
    stream = _Stream(zlib.compress(bytes(22)),
                     **{"/Filter": ["/FlateDecode"],
                        "/DecodeParms": _Deref(budget, left - 80, [params])})
    result = pdf_module._decode_bounded(stream, left, charge, budget.remaining)
    assert result.state == "big", result.state
    assert ran == []


def test_the_walk_gives_the_decoder_the_budget(monkeypatch):
    seen = {}
    real = pdf_module._decode_bounded

    def spy(stream, room, charge=lambda: 0, left=None):
        seen["left"] = left
        return real(stream, room, charge, left)

    monkeypatch.setattr(pdf_module, "_decode_bounded", spy)
    walk = pdf_module._ImageWalk(pdf_module._ReadBudget())
    stream = _Stream(zlib.compress(bytes(10)), **{"/Filter": ["/FlateDecode"]})
    walk._content(stream)
    assert seen["left"] == walk.budget.remaining


def test_a_decoder_given_no_budget_sizes_stages_as_before():
    stream = _Stream(zlib.compress(bytes(100)), **{"/Filter": "/FlateDecode"})
    assert pdf_module._decode_bounded(stream, 120).state == "ok"


def test_a_flate_input_that_is_all_of_the_allowance_leaves_nothing_to_inflate_into(monkeypatch):
    # A zero limit means "no limit" to zlib, so a stage is never started on nothing.
    raw = zlib.compress(bytes(10))
    stream = _Stream(raw, **{"/Filter": ["/FlateDecode"]})
    ran = []
    real = pdf_module._inflate
    monkeypatch.setattr(pdf_module, "_inflate", lambda data, room: ran.append(room) or real(data, room))
    assert pdf_module._decode_bounded(stream, len(raw)).state == "big"
    assert ran == []
