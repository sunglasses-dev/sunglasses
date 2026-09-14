"""T4.R7: the one thing the client is ever told, and everything it must not say.

Specified from the row before the implementation exists.

    {"jsonrpc":"2.0","id":<actual correlated id, same JSON type>,
     "error":{"code":-32070,"message":"SUNGLASSES_WITHHELD",
              "data":{"reason_code","rule","budget","accepted","status",
                      "inspection_complete","inspected_utf8_bytes",
                      "observed_content_bytes","elapsed_ms",
                      "rule_ids":[catalog-only, bounded 32, deduplicated]}}}

    Never payload, secret, descriptor text, exception/worker/stderr text,
    arbitrary ids.

That last sentence is the reason this is its own module and its own test file.
Everything else in the proxy decides WHETHER to withhold; this decides what
leaves the boundary when we do, and it is the one structure an attacker reads.
Three times already in this package a field built out of situational text has
carried peer material into evidence. The envelope is built from an allowlist,
and the tests are written to fail if it is ever built the other way round.
"""
import json

import pytest

envelope = pytest.importorskip(
    "sunglasses.proxy.envelope",
    reason="the envelope is the slice being specified here")

CATALOG = {"GLS-SD-001", "GLS-SD-003", "GLS-PI-016-API", "GLS-FW-SEC-001"}


def _built(**over):
    fields = {"request_id": 41, "reason_code": "PROHIBITED_SECRET", "rule": "S2",
              "accepted": True, "status": "complete", "inspection_complete": True,
              "inspected_utf8_bytes": 21, "observed_content_bytes": 21,
              "elapsed_ms": 3.5, "rule_ids": ["GLS-SD-001"], "catalog": CATALOG}
    fields.update(over)
    return envelope.withheld(**fields)


# ── the shape the row fixes ────────────────────────────────────────────────

def test_the_envelope_is_exactly_the_shape_the_row_names():
    built = _built()
    assert built["jsonrpc"] == "2.0"
    assert built["error"]["code"] == -32070
    assert built["error"]["message"] == "SUNGLASSES_WITHHELD"
    assert set(built) == {"jsonrpc", "id", "error"}
    assert set(built["error"]) == {"code", "message", "data"}
    assert set(built["error"]["data"]) == {
        "reason_code", "rule", "budget", "accepted", "status",
        "inspection_complete", "inspected_utf8_bytes",
        "observed_content_bytes", "elapsed_ms", "rule_ids"}


@pytest.mark.parametrize("request_id", [41, "41", 2.5, None])
def test_the_correlated_id_keeps_its_json_type(request_id):
    """T4.R7: the ACTUAL correlated id, same JSON type. `"41"` answered with 41
    is a reply to a request the client did not make."""
    built = _built(request_id=request_id)
    assert built["id"] == request_id
    assert type(built["id"]) is type(request_id)


# ── v5.1: budget is declared, and null unless it is a budget breach ────────

def test_budget_is_null_unless_the_reason_is_over_budget():
    assert _built(reason_code="PROHIBITED_SECRET")["error"]["data"]["budget"] is None
    assert _built(reason_code="SCAN_DEADLINE")["error"]["data"]["budget"] is None


@pytest.mark.parametrize("which", ["content", "frame", "depth", "nodes"])
def test_an_over_budget_reason_names_which_budget(which):
    built = _built(reason_code="OVER_BUDGET", budget=which)
    assert built["error"]["data"]["budget"] == which


def test_over_budget_without_a_named_budget_is_refused():
    """A receipt saying OVER_BUDGET with no budget cannot be graded against the
    fixtures, which is the whole reason v5.1 declared the field."""
    with pytest.raises(ValueError):
        _built(reason_code="OVER_BUDGET", budget=None)


def test_a_budget_on_a_reason_that_is_not_over_budget_is_refused():
    with pytest.raises(ValueError):
        _built(reason_code="SCAN_DEADLINE", budget="content")


# ── rule_ids: catalog only, bounded, deduplicated ─────────────────────────

def test_a_rule_id_outside_the_catalog_never_reaches_the_client():
    """T4.R6 and T4.R7 together. An id we cannot vouch for is not evidence, and
    echoing one lets anything that can reach the worker choose what we say."""
    built = _built(rule_ids=["GLS-SD-001", "GLS-INVENTED-999"])
    assert built["error"]["data"]["rule_ids"] == ["GLS-SD-001"]


def test_rule_ids_are_deduplicated():
    built = _built(rule_ids=["GLS-SD-001", "GLS-SD-001", "GLS-SD-003"])
    assert built["error"]["data"]["rule_ids"] == ["GLS-SD-001", "GLS-SD-003"]


def test_rule_ids_are_bounded_at_thirty_two():
    many = [f"GLS-SD-{n:03d}" for n in range(100)]
    built = _built(rule_ids=many, catalog=set(many))
    assert len(built["error"]["data"]["rule_ids"]) == 32


def test_rule_ids_are_ordered_so_the_bound_is_not_arbitrary():
    """Truncating an unordered set gives a different 32 each run, and a receipt
    that differs between two identical runs cannot be compared."""
    many = [f"GLS-SD-{n:03d}" for n in range(100)]
    first = _built(rule_ids=list(reversed(many)), catalog=set(many))
    second = _built(rule_ids=many, catalog=set(many))
    assert first["error"]["data"]["rule_ids"] == second["error"]["data"]["rule_ids"]


# ── the sentence that matters: never ───────────────────────────────────────

FORBIDDEN = "AKIAGATE2SYNTHETIC001"


@pytest.mark.parametrize("field,value", [
    ("detail", f"the payload was {FORBIDDEN}"),
    ("worker_stderr", f"Traceback: secret={FORBIDDEN}"),
    ("descriptor", f"Read a file. {FORBIDDEN}"),
    ("exception", RuntimeError(FORBIDDEN)),
])
def test_no_extra_field_can_smuggle_text_into_the_envelope(field, value):
    """An allowlist, proved by trying to push things through it.

    Whatever a caller passes that the row does not name must not appear. Three
    times in this package a field built from situational text has carried peer
    material into evidence, every time through a caller who had a good reason.
    """
    built = _built(**{field: value})
    assert FORBIDDEN not in json.dumps(built, default=str)


def test_the_reason_code_itself_must_be_from_the_catalog():
    """Otherwise the reason is a free text field with a respectable name."""
    with pytest.raises(ValueError):
        _built(reason_code="BECAUSE_" + FORBIDDEN)


def test_counters_that_are_not_numbers_are_refused():
    with pytest.raises(ValueError):
        _built(inspected_utf8_bytes=f"lots, like {FORBIDDEN}")


def test_the_envelope_is_json_serialisable_as_built():
    """It goes on the wire. A structure that cannot be serialised is discovered
    at the worst possible moment."""
    json.dumps(_built())


@pytest.mark.xfail(strict=True, reason="T409: the frozen status set is the "
                                       "slice being specified here")
def test_the_status_field_is_frozen_not_free_text():
    """T409. Every other field here is an allowlist and this one is a string.

    `status` arrives from the worker result, so leaving it open lets a worker
    choose text that lands in the one structure an attacker is guaranteed to
    read. An allowlist with one open field is not an allowlist; it is an
    allowlist with a door in it.
    """
    with pytest.raises(ValueError):
        _built(status="review-status-marker")


@pytest.mark.parametrize("status", ["complete", "incomplete", "exception",
                                    "deadline", "cancelled", "not_run"])
def test_every_worker_status_still_passes(status):
    """The positive half. Freezing the field must not reject the real statuses,
    or T409 is satisfied by an envelope that can no longer be built."""
    assert _built(status=status)["error"]["data"]["status"] == status
