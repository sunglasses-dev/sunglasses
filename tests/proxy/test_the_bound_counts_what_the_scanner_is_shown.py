"""The content bound counts the bytes the scanner is shown, not only the plain text values.

`selector.content_bytes` leaves out object keys, and the string values under a
protocol-scalar name (`nextCursor`, `progress`, `id`, ...) or a discriminant name
(`type`, `role`), at any depth outside the opaque containers. That number is the one
the receipts and the worker contract use, and it does not move.

The bound compares `selector.bound_bytes`: `content_bytes` plus the scanner input
bytes it leaves out (keys, protocol-scalar and discriminant strings, numbers, and one
byte for every leaf the scanner is shown, which stands for its joining newline), once
those pass 16,384 bytes. The standard envelope costs a few dozen bytes, so a message
exactly on the cap is admitted (the inclusive edge in `test_proxy_bounds.py` and the
pr164 fixtures). The allowance is written as the literal 16,384 in these tests on
purpose: a test built from `UNCOUNTED_ALLOWANCE` moves with the constant and cannot
notice it being changed.

The cases put a large part of a message at each place the scanner reads and
`content_bytes` does not count: an object key, a key inside the text block, a
`nextCursor` string, a `progress` string, a nested `type` and a nested `role`. They run
on the number, on the result path (the pump), on the client request path and on the
client notification path (the route). The controls are the same messages with the
filler moved to a counted place or made small.
"""
import json
import random

import pytest

from sunglasses.proxy import bounds, inspection, pump, selector

from _proxy_inspect_harness import frame, make_route
from test_round4 import reply, wire

CAP = bounds.CONTENT_BYTES
# Past the cap by more than the allowance, one byte a character: the allowance is the
# one place the shown-but-uncounted bytes are free, so a vector must clear it to count.
# The 16,384 is a literal, not the constant (see the module note).
ALLOWANCE = 16_384
PAD = "A" * (CAP + ALLOWANCE + 1)


def _result_with(vector):
    """A tools/call result whose only large part sits at the named place."""
    message = reply(1)
    result = message["result"]
    block = result["content"][0]
    if vector == "object key":
        result[PAD] = "v"
    elif vector == "key in the text block":
        block[PAD] = "v"
    elif vector == "nextCursor string":
        result["nextCursor"] = PAD
    elif vector == "progress string":
        result["progress"] = PAD
    elif vector == "nested type":
        block["meta"] = {"type": PAD}
    elif vector == "nested role":
        block["meta"] = {"role": PAD}
    else:
        raise AssertionError(vector)
    return message


VECTORS = ["object key", "key in the text block", "nextCursor string",
           "progress string", "nested type", "nested role"]


# ── the number itself ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("vector", VECTORS)
def test_the_shown_bytes_are_charged_to_the_bound(vector):
    result = _result_with(vector)["result"]
    assert selector.bound_bytes(result) > CAP, selector.bound_bytes(result)


# content_bytes of each vector, measured on the base 23ef858f where the bound used it
# alone. The receipts and the worker contract keep these exact numbers.
RECEIPT_BYTES = {"object key": 13, "key in the text block": 13,
                 "nextCursor string": 12, "progress string": 12,
                 "nested type": 12, "nested role": 12}


@pytest.mark.parametrize("vector", VECTORS)
def test_content_bytes_is_unchanged_for_the_receipts(vector):
    """The receipts keep counting content only (row 3.1)."""
    result = _result_with(vector)["result"]
    assert selector.content_bytes(result) == RECEIPT_BYTES[vector]


def test_a_message_exactly_on_the_cap_is_still_admitted():
    """The pr164 fixtures sit exactly on the cap with the standard envelope."""
    result = reply(1)["result"]
    result["content"][0]["text"] = "x" * CAP
    assert selector.content_bytes(result) == CAP
    assert not bounds.check_content(selector.bound_bytes(result))
    result["content"][0]["text"] = "x" * (CAP + 1)
    assert bounds.check_content(selector.bound_bytes(result))


def test_small_keys_and_scalars_within_the_allowance_add_nothing():
    result = reply(1)["result"]
    result["content"][0]["text"] = "x" * CAP
    result["nextCursor"] = "c" * 200
    result["progress"] = "7"
    result["content"][0]["meta"] = {"type": "text", "role": "user"}
    assert selector.bound_bytes(result) == CAP


def test_many_small_keys_cannot_stay_free_past_the_allowance():
    """Five thousand 101-byte keys are each small; together they are about thirty
    times the allowance. The total is what is charged, not each one. The counted
    values alone (the text and the 5,000 one-byte values) stay under the cap, so
    only the key bytes can carry the bound over it."""
    result = reply(1)["result"]
    result["content"][0]["text"] = "x" * (CAP - 6000)
    for index in range(5000):
        result["k%05d" % index + "k" * 95] = "v"
    assert selector.content_bytes(result) < CAP, selector.content_bytes(result)
    assert selector.bound_bytes(result) > CAP


def test_the_allowance_is_the_only_slack():
    """Inside it the bound is the content count; past it, every byte is charged."""
    inside = reply(1)["result"]
    inside["content"][0]["text"] = "x" * CAP
    inside["nextCursor"] = "c" * (ALLOWANCE - 200)
    assert selector.bound_bytes(inside) == CAP

    past = reply(1)["result"]
    past["content"][0]["text"] = "x" * CAP
    past["nextCursor"] = "c" * (ALLOWANCE + 1000)
    extra = selector.bound_bytes(past) - CAP
    assert 1000 <= extra <= 1050, extra


def test_the_allowance_edge_is_16384_and_16385():
    """Literal boundary. The envelope shows 24 bytes of its own; a nextCursor of n
    characters adds n + 1 (its value and the joining newline). So 16,359 characters
    make the shown-but-uncounted total exactly 16,384 and the bound the cap itself,
    and 16,360 make it 16,385 and the bound one byte over. Changing the allowance to
    0, or to 32,768, breaks one of the two lines."""
    result = reply(1)["result"]
    result["content"][0]["text"] = "x" * CAP
    result["nextCursor"] = "c" * 16_359
    assert selector._walk_uncounted(result, None, False) == 16_384
    assert selector.bound_bytes(result) == CAP
    assert not bounds.check_content(selector.bound_bytes(result))
    result["nextCursor"] = "c" * 16_360
    assert selector._walk_uncounted(result, None, False) == 16_385
    assert selector.bound_bytes(result) == CAP + 1
    assert bounds.check_content(selector.bound_bytes(result))


# ── the bound against the real scanner input ─────────────────────────────────────

_KEYS = ["a", "text", "type", "role", "id", "nextCursor", "progress", "total",
         "code", "isError", "jsonrpc", "protocolVersion", "structuredContent",
         "_meta", "arguments", "params", "content", "", "k" * 300, "\u00e9\u4e2d"]
_STRINGS = ["", "x", "hello world", "\u00e9", "\u4e2d\u6587", "\U0001f600", "a\nb",
            "s" * 500]


def _random_value(rng, depth):
    pick = rng.random()
    if depth >= 6 or pick < 0.35:
        kind = rng.choice(["str", "str", "int", "float", "bool", "none"])
        if kind == "str":
            return rng.choice(_STRINGS)
        return {"int": rng.randint(-10 ** 6, 10 ** 6), "float": rng.random() * 1e3,
                "bool": rng.random() < 0.5, "none": None}[kind]
    if pick < 0.65:
        return [_random_value(rng, depth + 1) for _ in range(rng.randint(0, 4))]
    return {rng.choice(_KEYS): _random_value(rng, depth + 1)
            for _ in range(rng.randint(0, 4))}


def _scanner_bytes(value):
    return len(inspection.scanner_input(value).encode("utf-8", "surrogatepass"))


def _identity_holds(value):
    leaves = selector.coverage_leaves(value)
    if not leaves:
        return True, None
    expected = (selector.content_bytes(value)
                + selector._walk_uncounted(value, None, False) - 1)
    return _scanner_bytes(value) == expected, (_scanner_bytes(value), expected)


def _hostile_shapes():
    deep = "end"
    for _ in range(200):
        deep = {"n": deep}
    return {
        "many empty leaves": ["" for _ in range(5000)],
        "many empty keys": {str(i): "" for i in range(3000)},
        "deep nesting": deep,
        "deep nesting in lists": [[[[[[["z"]]]]]]],
        "long keys": {"k" * 50_000: "v", "j" * 50_000: ["w", 1, None, True]},
        "top level extras holding params": {
            "params": {"name": "echo", "arguments": {"text": "hi"}},
            "note": "n", "extra": {"nextCursor": "c", "type": "t"}},
        "opaque containers": {
            "structuredContent": {"type": "t", "id": "i", "nextCursor": "c",
                                  "nested": {"role": "r", "progress": "p"}},
            "_meta": {"jsonrpc": "j", "total": 9, "x": ["", {"": ""}]},
            "arguments": {"code": 1, "isError": False, "text": ""}},
        "protocol scalars as strings": {"id": "1", "nextCursor": "", "progress": "9",
                                       "content": [{"type": "text", "text": ""}]},
        "multibyte everywhere": {"\u4e2d": "\u00e9", "\U0001f600": ["\u4e2d\u6587"]},
        "numbers only": {"a": 1, "b": [2.5, True, None, False]},
    }


@pytest.mark.parametrize("name", sorted(_hostile_shapes()))
def test_the_bound_is_the_real_scanner_input_on_hostile_shapes(name):
    """An identity, not a claim: the byte length of what `scanner_input` hands the
    scanner equals content_bytes + the shown-but-uncounted total - 1."""
    ok, seen = _identity_holds(_hostile_shapes()[name])
    assert ok, seen


def test_the_bound_is_the_real_scanner_input_on_seeded_random_shapes():
    checked = 0
    for seed in range(400):
        rng = random.Random(seed)
        value = {rng.choice(_KEYS): _random_value(rng, 0)
                 for _ in range(rng.randint(1, 5))}
        ok, seen = _identity_holds(value)
        assert ok, (seed, seen)
        checked += bool(selector.coverage_leaves(value))
    assert checked > 300, checked


def test_the_bound_surface_of_a_client_frame_is_the_real_scanner_input():
    message = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
               "params": {"name": "echo", "arguments": {"text": "hi"}},
               "note": "n", "x": {"type": "t", "": ""}}
    surface = selector.bound_surface("tools/call", message)
    ok, seen = _identity_holds(surface)
    assert ok, seen
    assert selector.bound_bytes(surface) == selector.content_bytes(surface)


# ── the result path (the pump) ───────────────────────────────────────────────────

@pytest.mark.parametrize("vector", VECTORS)
def test_an_oversized_result_does_not_cross_to_the_client(vector):
    session = pump.Session()
    session.admit_request(1, method="tools/call", origin="client")
    out = list(session.read_upstream(wire(_result_with(vector))))
    assert not any("result" in json.loads(line) for line in out), vector
    assert session.answer_for(1, origin="client").reason == "OVER_BUDGET"


def test_the_same_result_with_the_filler_in_the_text_is_refused():
    session = pump.Session()
    session.admit_request(1, method="tools/call", origin="client")
    message = reply(1)
    message["result"]["content"][0]["text"] = "x" * (CAP + 1)
    out = list(session.read_upstream(wire(message)))
    assert not any("result" in json.loads(line) for line in out)
    assert session.answer_for(1, origin="client").reason == "OVER_BUDGET"


def test_a_normal_result_still_crosses():
    session = pump.Session()
    session.admit_request(1, method="tools/call", origin="client")
    out = list(session.read_upstream(wire(reply(1))))
    assert any("result" in json.loads(line) for line in out)


# ── the client notification path (the route) ─────────────────────────────────────

def _settled(tmp_path):
    rows = []
    for path in (tmp_path / "receipts").glob("*.jsonl"):
        rows += [json.loads(line) for line in path.read_text().splitlines()]
    return [row for row in rows if row["kind"] == "SETTLED"]


def test_an_oversized_key_in_a_client_notification_is_dropped_before_any_scan(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path)
    engine.client_frame(frame(method="notifications/message",
                              params={"data": "hello", PAD: "v"}))
    assert upstream.bytes == b"", "the oversized frame reached the server"
    assert scans == [], "the worker was asked to scan more than the bound"
    settled = _settled(tmp_path)
    assert len(settled) == 1, settled
    assert settled[0]["reason_code"] == "OVER_BUDGET"
    assert settled[0]["budget"] == "content"


def test_a_small_client_notification_is_still_scanned_and_forwarded(tmp_path):
    engine, upstream, _client, scans = make_route(tmp_path)
    raw = frame(method="notifications/message", params={"data": "hello", "k": "v"})
    engine.client_frame(raw)
    assert len(scans) == 1
    assert json.loads(upstream.bytes) == json.loads(raw)


# ── the client request path (the route's request gate) ───────────────────────────

def _answers(client):
    return client.messages()


@pytest.mark.parametrize("filler", ["key", "nextCursor", "nested type"])
def test_an_oversized_client_request_is_refused_before_any_scan(tmp_path, filler):
    """A client REQUEST (it has an id) through the route's request gate, with the
    filler where `content_bytes` does not see it. Refused, no scan, no forward, and
    the client is answered OVER_BUDGET. Reverting that gate alone to `content_bytes`
    makes this fail."""
    params = {"name": "echo", "arguments": {"text": "hi"}}
    if filler == "key":
        params[PAD] = "v"
    elif filler == "nextCursor":
        params["nextCursor"] = PAD
    else:
        params["meta"] = {"type": PAD}
    engine, upstream, client, scans = make_route(tmp_path)
    engine.client_frame(frame(id=2, method="tools/call", params=params))
    assert upstream.bytes == b"", "the oversized request reached the server"
    assert scans == [], "the worker was asked to scan more than the bound"
    answers = _answers(client)
    assert len(answers) == 1, answers
    assert answers[0]["error"]["data"]["reason_code"] == "OVER_BUDGET"


def test_a_small_client_request_is_still_scanned_and_forwarded(tmp_path):
    engine, upstream, _client, scans = make_route(tmp_path)
    raw = frame(id=2, method="tools/call",
                params={"name": "echo", "arguments": {"text": "hi"}, "k": "v"})
    engine.client_frame(raw)
    assert len(scans) == 1
    assert json.loads(upstream.bytes) == json.loads(raw)


# ── the one byte a leaf costs, at the allowance ─────────────────────────────────
# Every leaf the scanner is shown costs one byte in the bound (its joining newline).
# A frame of plain counted values sits at the cap in `content_bytes`; the first
# 16,384 leaves are inside the allowance and the 16,385th is the first one charged.

def _plain_values(count):
    """`count` string values whose `content_bytes` is exactly the cap: count - 1
    one-byte values and one filler holding the rest."""
    return ["x" * (CAP - (count - 1))] + ["v"] * (count - 1)


def test_sixteen_thousand_plain_values_at_the_cap_are_inside_the_allowance():
    at_edge = _plain_values(16_384)
    assert selector.content_bytes(at_edge) == CAP
    assert selector._walk_uncounted(at_edge, None, False) == 16_384
    assert selector.bound_bytes(at_edge) == CAP
    assert not bounds.check_content(selector.bound_bytes(at_edge))
    past_edge = _plain_values(16_385)
    assert selector.content_bytes(past_edge) == CAP
    assert selector._walk_uncounted(past_edge, None, False) == 16_385
    assert selector.bound_bytes(past_edge) == CAP + 1
    assert bounds.check_content(selector.bound_bytes(past_edge))


def test_a_notification_of_16384_values_at_the_cap_is_scanned_and_forwarded(tmp_path):
    engine, upstream, _client, scans = make_route(tmp_path)
    raw = frame(method="notifications/message", params=_plain_values(16_384))
    engine.client_frame(raw)
    assert len(scans) == 1
    assert json.loads(upstream.bytes) == json.loads(raw)
    assert not [row for row in _settled(tmp_path) if row["reason_code"] == "OVER_BUDGET"]


def test_a_notification_of_16385_values_at_the_cap_is_refused_before_any_scan(tmp_path):
    engine, upstream, _client, scans = make_route(tmp_path)
    engine.client_frame(frame(method="notifications/message",
                              params=_plain_values(16_385)))
    assert upstream.bytes == b"", "the frame reached the server"
    assert scans == [], "the worker was asked to scan more than the bound"
    settled = _settled(tmp_path)
    assert len(settled) == 1, settled
    assert settled[0]["reason_code"] == "OVER_BUDGET"
    assert settled[0]["budget"] == "content"


def _request_params(uncounted):
    """tools/call params whose `content_bytes` is exactly the cap and whose
    shown-but-uncounted total is `uncounted`: one filler, then one-byte values."""
    def build(filler, extra):
        return {"name": "echo", "arguments": {"v": [filler] + ["v"] * extra}}
    extra = uncounted - selector._walk_uncounted(build("x", 0), None, False)
    params = build("", extra)
    params = build("x" * (CAP - selector.content_bytes(params)), extra)
    assert selector.content_bytes(params) == CAP
    assert selector._walk_uncounted(params, None, False) == uncounted
    return params


def test_a_request_at_the_cap_with_16384_shown_bytes_is_scanned_and_forwarded(tmp_path):
    engine, upstream, _client, scans = make_route(tmp_path)
    raw = frame(id=2, method="tools/call", params=_request_params(16_384))
    engine.client_frame(raw)
    assert len(scans) == 1
    assert json.loads(upstream.bytes) == json.loads(raw)


def test_a_request_at_the_cap_with_16385_shown_bytes_is_refused_before_any_scan(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path)
    engine.client_frame(frame(id=2, method="tools/call", params=_request_params(16_385)))
    assert upstream.bytes == b"", "the request reached the server"
    assert scans == [], "the worker was asked to scan more than the bound"
    answers = _answers(client)
    assert len(answers) == 1, answers
    assert answers[0]["error"]["data"]["reason_code"] == "OVER_BUDGET"
