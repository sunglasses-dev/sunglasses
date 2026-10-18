"""A number that overflows is refused, never carried through as `Infinity`.

`framing.parse_frame` refused the literals NaN and Infinity but accepted the
numeric literal `1e400`, which `json.loads` turns into `float("inf")`. Every
`json.dumps` on the way out then wrote it back as the bare token `Infinity`,
which is not JSON and which the proxy's own parser refuses. The value reaches
the output through a withheld envelope for a float id, through the rebuilt
initialize result (which carries upstream capability values), and through the
frames passed on to the client.
"""
import io
import json

from sunglasses.proxy import framing

from route_harness import frame, init_request, make_route


def test_parse_frame_refuses_a_numeric_literal_that_is_not_finite():
    parsed = framing.parse_frame(b'{"jsonrpc":"2.0","id":1e400,"method":"ping"}\n',
                                 origin="client")
    assert not parsed.ok, (
        f"accepted id={parsed.message['id']!r}; NaN/Infinity literals are "
        "refused but an overflowing literal is let through")


def test_withheld_envelope_for_a_float_id_is_valid_json(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path)
    engine.client_frame(b'{"jsonrpc":"2.0","id":1e400,"method":"x/unknown"}\n')
    assert client.writes, "no refusal reached the client"
    out = client.writes[0]
    reparsed = framing.parse_frame(out, origin="upstream")
    assert reparsed.ok, (
        f"the proxy wrote non-JSON to the client: {out[:120]!r} -> "
        f"{reparsed.kind}")


def test_rebuilt_initialize_result_is_valid_json(tmp_path):
    engine, upstream, client, scans = make_route(tmp_path)
    engine.client_frame(init_request(1))
    engine.pump_upstream(io.BytesIO(
        b'{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18",'
        b'"capabilities":{"tools":{"listChanged":1e400}},'
        b'"serverInfo":{"name":"s","version":"1"}}}\n'))
    assert client.writes, "no initialize answer reached the client"
    out = client.writes[0]
    reparsed = framing.parse_frame(out, origin="upstream")
    assert reparsed.ok, (
        f"the proxy wrote non-JSON to the client: {out[:160]!r} -> "
        f"{reparsed.kind}")


def test_a_non_finite_number_is_never_written_to_the_client(tmp_path):
    """The parser is the gate; this is the second one, on the way out."""
    engine, upstream, client, scans = make_route(tmp_path)
    body = {"jsonrpc": "2.0", "id": 1, "result": {"value": float("inf")}}
    try:
        engine._to_client(body)
    except ValueError:
        pass
    assert client.writes == []
