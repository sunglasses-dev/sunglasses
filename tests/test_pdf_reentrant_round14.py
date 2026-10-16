"""Fourteenth round on the shared decoder: the document ledger sees a decoder's own spend before
anything it resolves can start another decode, and an attachment's size cap is a cap on what is
decoded, not on what is read.

* A decode parameter can be an object that has to be resolved, and resolving it can decode again
  (an object stream). The outer decode kept what it had read and produced in a local counter and
  charged it when it returned, so the nested decode was sized against a ledger that left it out.
  The outer spend is now put on the ledger before the parameters are resolved, and what the
  decoder returns is only what is still unpaid, so a caller that charges the result does not
  charge it twice.
* The attachment cap counted the encoded input together with the decoded output, so an attachment
  whose input and output each fit the cap could stop early. The cap now counts what the stages
  produce, as it did before the input was put on the ledger; the input is still paid for from the
  document budget.
"""
import base64
import os
import zlib

import pytest

from sunglasses.extractors import pdf as pdf_module
from sunglasses.extractors.pdf import _ReadBudget, _WalkBudget

VISIT = 32


class _Stream(dict):
    def __init__(self, data=b"", **entries):
        super().__init__(entries)
        self._data = data


class _Deref:
    """Resolving this reads the ledger, and may do work that spends on it, as a dereference that
    inflates an object stream does."""
    def __init__(self, budget, target, act=None):
        self.budget, self.target, self.act, self.seen = budget, target, act, None

    def get_object(self):
        self.seen = self.budget.read
        if self.act:
            self.act()
        return self.target


def _charge(budget):
    def charge():
        budget.spend(VISIT)
        return VISIT
    return charge


def _decode(budget, stream, commit=True, **kw):
    return pdf_module._decode_bounded(stream, budget.remaining(), _charge(budget), budget.remaining,
                                      budget.spend if commit else None, **kw)


def test_the_outer_spend_is_on_the_ledger_before_a_parameter_is_resolved():
    budget = _ReadBudget()
    raw = zlib.compress(bytes(300))
    deref = _Deref(budget, [{"/Predictor": 1}])
    stream = _Stream(raw, **{"/Filter": ["/FlateDecode"], "/DecodeParms": deref})
    result = _decode(budget, stream)
    assert result.state == "ok" and len(result.data) == 300
    assert deref.seen is not None
    assert deref.seen >= len(raw) + 300, deref.seen


def test_a_nested_decode_is_sized_against_a_ledger_that_holds_the_outer_spend():
    budget = _ReadBudget()
    budget.MAX_BYTES = 400
    inner_raw = zlib.compress(bytes(250))
    nested = {}

    def nested_decode():
        inner = _Stream(inner_raw, **{"/Filter": ["/FlateDecode"]})
        nested["result"] = _decode(budget, inner)

    outer_raw = zlib.compress(bytes(150))
    deref = _Deref(budget, [{"/Predictor": 1}], nested_decode)
    stream = _Stream(outer_raw, **{"/Filter": ["/FlateDecode"], "/DecodeParms": deref})
    try:
        outer = _decode(budget, stream)
        budget.spend(outer.spent)
    except _WalkBudget:
        pass
    assert nested["result"].state == "big", nested["result"].state


def _streams():
    flate = zlib.compress(bytes(100))
    yield "ok", _Stream(flate, **{"/Filter": ["/FlateDecode"], "/DecodeParms": [{"/Predictor": 1}]})
    yield "ok chain", _Stream(base64.a85encode(flate) + b"~>", **{"/Filter": ["/ASCII85Decode", "/FlateDecode"]})
    yield "big", _Stream(zlib.compress(bytes(5000)), **{"/Filter": ["/FlateDecode"]})
    yield "unsized", _Stream(b"abc", **{"/Filter": ["/RunLengthDecode"]})
    yield "error", _Stream(flate, **{"/Filter": ["/FlateDecode"], "/DecodeParms": [{"/Predictor": 99}]})
    yield "unfiltered", _Stream(b"plain text")


@pytest.mark.parametrize("label,stream", list(_streams()), ids=[s[0] for s in _streams()])
def test_committing_early_does_not_charge_the_result_twice(label, stream):
    totals = []
    for commit in (False, True):
        budget = _ReadBudget()
        budget.MAX_BYTES = 2000
        try:
            result = _decode(budget, stream, commit=commit)
            budget.spend(result.spent)
        except _WalkBudget:
            pass
        totals.append(budget.read)
    assert totals[0] == totals[1], totals


# --- the cap on what is decoded -------------------------------------------------------------

def test_an_attachment_whose_input_and_output_each_fit_the_cap_is_decoded():
    random = os.urandom(600)
    raw = zlib.compress(random, 0)
    assert len(raw) < 1000 and len(random) < 1000 and len(raw) + len(random) > 1000
    budget = _ReadBudget()
    result = _decode(budget, _Stream(raw, **{"/Filter": ["/FlateDecode"]}), cap=1000)
    assert result.state == "ok" and result.data == random


def test_output_past_the_cap_is_refused_and_says_it_was_the_cap():
    raw = zlib.compress(bytes(1500))
    budget = _ReadBudget()
    result = _decode(budget, _Stream(raw, **{"/Filter": ["/FlateDecode"]}), cap=1000)
    assert result.state == "big" and result.detail == "cap"
    assert result.spent > 0


def test_every_stage_of_a_chain_counts_toward_the_cap():
    flate = zlib.compress(os.urandom(300), 0)
    raw = base64.a85encode(flate) + b"~>"
    budget = _ReadBudget()
    chain = _Stream(raw, **{"/Filter": ["/ASCII85Decode", "/FlateDecode"]})
    assert _decode(budget, chain, cap=400).state == "big"
    assert _decode(_ReadBudget(), chain, cap=1000).state == "ok"


def test_the_document_budget_still_refuses_without_naming_the_cap():
    budget = _ReadBudget()
    budget.MAX_BYTES = 300
    raw = zlib.compress(bytes(5000))
    result = _decode(budget, _Stream(raw, **{"/Filter": ["/FlateDecode"]}), cap=1 << 20)
    assert result.state == "big" and result.detail != "cap"


def test_no_cap_means_the_allowance_alone():
    budget = _ReadBudget()
    raw = zlib.compress(bytes(5000))
    assert _decode(budget, _Stream(raw, **{"/Filter": ["/FlateDecode"]})).state == "ok"
