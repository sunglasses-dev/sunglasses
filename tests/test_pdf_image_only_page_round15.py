"""Fifteenth round on the image-only page walk, at the caller: the walk's budget holds a content
stream's decode spend before a decode parameter is resolved, and the whole is charged once.
"""
import zlib

from sunglasses.extractors import pdf as pdf_module


class _Stream(dict):
    def __init__(self, data=b"", **entries):
        super().__init__(entries)
        self._data = data

    def get_data(self):
        raise AssertionError("the reader's own decode must not run")


class _Deref:
    def __init__(self, budget, target):
        self.budget, self.target, self.seen = budget, target, None

    def get_object(self):
        self.seen = self.budget.read
        return self.target


def _walk():
    return pdf_module._ImageWalk(pdf_module._ReadBudget())


def test_the_walk_budget_holds_the_decoder_spend_when_a_decode_parameter_is_resolved():
    walk = _walk()
    raw = zlib.compress(bytes(300))
    deref = _Deref(walk.budget, [{"/Predictor": 1}])
    stream = _Stream(raw, **{"/Filter": ["/FlateDecode"], "/DecodeParms": deref})
    assert walk._content(stream) == bytes(300)
    assert deref.seen >= len(raw) + 300, deref.seen


def test_a_content_stream_is_charged_once_whether_or_not_its_parameters_are_resolved():
    def spent(make_params):
        walk = _walk()
        stream = _Stream(zlib.compress(bytes(300)),
                         **{"/Filter": ["/FlateDecode"], "/DecodeParms": make_params(walk.budget)})
        walk._content(stream)
        return walk.budget.read

    assert spent(lambda b: _Deref(b, [{"/Predictor": 1}])) == spent(lambda b: [{"/Predictor": 1}])
