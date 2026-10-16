"""Tenth round on the image only page check: appearance states are paid for before they are read.

Review of the ninth round found that the normal appearance of an annotation was resolved state by
state into a list before the first state was charged. The list is capped at 64 states, but each
reference in it was followed once the allowance was already gone.
"""
import pytest

from sunglasses.extractors import pdf as pdf_module


class _State:
    """An appearance state reference that counts how often it is resolved."""
    resolutions = 0

    def get_object(self):
        type(self).resolutions += 1
        return _Form()


class _Form(dict):
    def get_data(self):
        return b""


class _Table(dict):
    """A dictionary the way PyPDF2 hands one over: raw_get gives the reference unresolved."""

    def raw_get(self, key):
        return dict.__getitem__(self, key)


def _page(states):
    normal = _Table({f"/S{i}": _State() for i in range(states)})
    appearance = _Table({"/N": normal})
    return {"/Annots": [{"/AP": appearance}]}


def _walk(left):
    walk = pdf_module._ImageWalk(pdf_module._ReadBudget())
    walk.budget.read = walk.budget.MAX_BYTES - left
    return walk


@pytest.mark.parametrize("states", [1, 8, 64])
def test_no_state_is_resolved_once_the_allowance_is_gone(states):
    _State.resolutions = 0
    walk = _walk(pdf_module._ImageWalk.VISIT_COST)
    with pytest.raises(pdf_module._WalkBudget):
        walk._appearances(_page(states), ())
    assert _State.resolutions == 0, _State.resolutions


def test_a_page_of_many_states_resolves_only_the_state_it_paid_for():
    _State.resolutions = 0
    cost = pdf_module._ImageWalk.VISIT_COST
    walk = _walk(2 * cost)
    with pytest.raises(pdf_module._WalkBudget):
        walk._appearances(_page(64), ())
    # One visit for the annotation, one charge for the first state, which is then read; the
    # visit that reads its content is the charge that fails. The other 63 are never resolved.
    assert _State.resolutions == 1, _State.resolutions


def test_every_state_is_still_read_when_the_allowance_holds(monkeypatch):
    _State.resolutions = 0
    walk = _walk(1 << 20)
    seen = []
    monkeypatch.setattr(walk, "_form", lambda stream, ident, scope, depth: seen.append(stream) or (0, 0, 0))
    assert walk._appearances(_page(5), ()) == (0, 0, 0)
    assert _State.resolutions == 5 and len(seen) == 5

