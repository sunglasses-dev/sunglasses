"""Twelfth round on the image only page check: one ledger, and every resolution is paid for first.

Review of the eleventh round found two faults of the same kind as the tenth:

* the decoder was handed the budget left when it was called, and its setup (the filter list and the
  decode parameters, charged entry by entry) then spent part of it, so the stages were sized against
  space that was already gone. A Flate stage made more than was left and a predictor ran on input
  that did not fit. The decoder now takes every setup charge off the allowance it sizes the stages
  against, so there is one ledger;
* the objects the walk reached by name (an XObject, a font, a graphics state, a glyph procedure, a
  soft-mask group) and the resources of a page were resolved before anything was charged for them,
  including the glyph procedures of a Type3 font, up to 512 of them, after the allowance was gone.
  Every such resolution now goes through one method that charges first.
"""
import zlib

import pytest

from sunglasses.extractors import pdf as pdf_module

VISIT = pdf_module._ImageWalk.VISIT_COST


class _Counted:
    """An object that counts how often it is resolved, and when, in the order of the budget's charges."""
    log = None

    def __init__(self, target):
        self._target = target

    def get_object(self):
        type(self).log.append(("resolve", None))
        return self._target


class _Dict(dict):
    def raw_get(self, key):
        return dict.__getitem__(self, key)


class _Stream(_Dict):
    def __init__(self, data=b"", **entries):
        super().__init__(entries)
        self._data = data

    def get_data(self):
        return self._data


class _Ledger(pdf_module._ReadBudget):
    """The document budget, writing every charge to the same log as the resolutions."""

    def spend(self, size):
        _Counted.log.append(("spend", size))
        super().spend(size)


@pytest.fixture(autouse=True)
def _log():
    _Counted.log = []


def _walk(left=None):
    walk = pdf_module._ImageWalk(_Ledger())
    if left is not None:
        walk.budget.read = walk.budget.MAX_BYTES - left
    return walk


def _resolutions():
    return sum(1 for kind, _ in _Counted.log if kind == "resolve")


def _each_resolution_has_its_own_visit(visits_before=0):
    """At every resolution the visits charged so far exceed the resolutions made so far."""
    visits = resolutions = 0
    for kind, size in _Counted.log:
        if kind == "spend" and size == VISIT:
            visits += 1
        elif kind == "resolve":
            resolutions += 1
            assert visits - visits_before >= resolutions, (visits, resolutions, _Counted.log)


# 1. One ledger: the setup charges come off the allowance the stages are sized against.
def _charging(cost):
    return lambda: cost


def test_a_stage_is_sized_against_what_is_left_after_the_setup_charges():
    data = zlib.compress(bytes(100))
    stream = _Stream(data, **{"/Filter": ["/FlateDecode"]})
    n = len(stream._data)   # the stream's own input is on the ledger too
    assert pdf_module._decode_bounded(stream, 100 + n + VISIT - 1, _charging(VISIT)).state == "big"
    ok = pdf_module._decode_bounded(stream, 100 + n + VISIT, _charging(VISIT))
    assert ok.state == "ok" and ok.spent == 100 + n


def test_the_predictor_does_not_run_on_space_the_setup_already_spent(monkeypatch):
    from PyPDF2 import filters as pdf_filters

    ran = []
    real = pdf_filters.FlateDecode._decode_png_prediction
    monkeypatch.setattr(pdf_filters.FlateDecode, "_decode_png_prediction",
                        staticmethod(lambda *a: ran.append(1) or real(*a)))
    stream = _Stream(zlib.compress(bytes(22)),
                     **{"/Filter": ["/FlateDecode"],
                        "/DecodeParms": [{"/Predictor": 12, "/Columns": 10}]})
    # 22 bytes inflated, 22 more reserved for the predictor, and two entries of setup at VISIT each
    n = len(stream._data)
    assert pdf_module._decode_bounded(stream, 2 * VISIT + 44 + n - 1, _charging(VISIT)).state == "big"
    assert ran == []
    assert pdf_module._decode_bounded(stream, 2 * VISIT + 44 + n, _charging(VISIT)).state == "ok"
    assert ran == [1]


def test_a_decoder_with_no_setup_charge_sizes_stages_as_before():
    stream = _Stream(zlib.compress(bytes(100)), **{"/Filter": "/FlateDecode"})
    n = len(stream._data)
    assert pdf_module._decode_bounded(stream, 99 + n).state == "big"
    assert pdf_module._decode_bounded(stream, 100 + n).state == "ok"


def test_the_walk_hands_the_decoder_what_is_left_after_its_own_setup(monkeypatch):
    asked = []
    real = pdf_module._inflate
    monkeypatch.setattr(pdf_module, "_inflate", lambda data, room: asked.append(room) or real(data, room))
    walk = _walk(left=VISIT + 150)
    stream = _Stream(zlib.compress(bytes(100)), **{"/Filter": ["/FlateDecode"]})
    walk._content(stream)
    assert asked == [150 - len(stream._data)], asked   # the input came off first


# 2. Every resolution is paid for before it is made.
def test_a_page_is_charged_before_its_resources_are_resolved():
    page = _Dict({"/Resources": _Counted(_Dict())})
    with pytest.raises(pdf_module._WalkBudget):
        _walk(left=0).painted_images(page, 0)
    assert _resolutions() == 0


@pytest.mark.parametrize("method,make", [
    ("_font", lambda: _Dict({"/Subtype": "/Type3"})),
    ("_state", lambda: _Dict({"/SMask": "/None"})),
])
def test_a_font_or_graphics_state_is_charged_before_it_is_resolved(method, make):
    with pytest.raises(pdf_module._WalkBudget):
        getattr(_walk(left=0), method)(_Counted(make()), (), 0)
    assert _resolutions() == 0


def test_a_soft_mask_group_is_charged_before_it_is_resolved():
    group = _Counted(_Stream(b"", **{"/Subtype": "/Form"}))
    state = _Dict({"/SMask": _Dict({"/G": group})})
    with pytest.raises(pdf_module._WalkBudget):
        _walk(left=0)._state(state, (), 0)
    assert _resolutions() == 0


GLYPHS = pdf_module._ImageWalk.MAX_GLYPHS


def test_a_glyph_procedure_is_charged_before_it_is_resolved():
    procs = _Dict({"/G%d" % i: _Counted("not a stream") for i in range(GLYPHS)})
    font = _Dict({"/CharProcs": procs, "/Subtype": "/Type3"})
    with pytest.raises(pdf_module._WalkBudget):
        _walk(left=3 * VISIT)._type3(font, None, (), 0)
    assert _resolutions() == 3, _resolutions()


def test_a_glyph_procedure_that_is_not_a_stream_is_charged_too():
    procs = _Dict({"/G%d" % i: _Counted(_Dict()) for i in range(GLYPHS)})
    font = _Dict({"/CharProcs": procs, "/Subtype": "/Type3"})
    with pytest.raises(pdf_module._WalkBudget):
        _walk(left=0)._type3(font, None, (), 0)
    assert _resolutions() == 0


def _page_drawing(content, resources):
    return _Dict({"/Contents": _Stream(content), "/Resources": resources})


@pytest.mark.parametrize("operator,table,make", [
    (b"/%s Do", "/XObject", lambda: _Stream(b"", **{"/Subtype": "/Image"})),
    (b"/%s 12 Tf", "/Font", lambda: _Dict({"/Subtype": "/Type1"})),
    (b"/%s gs", "/ExtGState", lambda: _Dict({})),
])
def test_each_name_a_page_draws_is_charged_before_it_is_resolved(operator, table, make):
    names = [b"A", b"B", b"C", b"D"]
    resources = _Dict({table: _Dict({"/" + n.decode(): _Counted(make()) for n in names})})
    content = b" ".join(operator % n for n in names)
    walk = _walk()
    walk.painted_images(_page_drawing(content, resources), 0)
    assert _resolutions() == len(names)
    _each_resolution_has_its_own_visit()


# The inventory of every dereference, decode and size step is tests/test_pdf_charge_inventory_round12.py.


# --- work that sizes a stream is paid for before it is done -------------------------------

def _sized(filter_name, n, byte):
    return _Stream(byte * n, **{"/Filter": [filter_name]})


def test_a_refused_lzw_sizing_pass_is_charged_for_the_input_it_read():
    result = pdf_module._decode_bounded(_sized("/LZWDecode", 4096, b"\xff"), 1 << 20)
    assert result.state == "unsized"
    assert result.spent >= 4096


def test_sizing_does_not_start_when_the_input_alone_passes_the_allowance(monkeypatch):
    ran = []
    for attr in ("_lzw_length", "_ascii85_length"):
        real = getattr(pdf_module, attr)
        monkeypatch.setattr(pdf_module, attr, lambda *a, real=real: ran.append(1) or real(*a))
    assert pdf_module._decode_bounded(_sized("/LZWDecode", 4096, b"\xff"), 64).state == "big"
    assert pdf_module._decode_bounded(_sized("/ASCII85Decode", 4096, b"9"), 64).state == "big"
    assert ran == []


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
