"""On a mediated route the stimulus is what the mediator saw, never a transcript.

ASTRA's requirement 1, in his words, is that the stimulus gate "compares
transcript calls after execution, rather than attested proxy ingress". The
descriptor path was moved onto attested ingress and the main path was not, so a
G2-04 row whose session produced no proxy receipts at all still graded
`stimulus_exact` on the strength of what the model reported doing.

A transcript is a record of a decision. Attested ingress is a record of an
arrival. They differ exactly when it matters: when the call did not arrive.
"""
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import batch                                                   # noqa: E402

CALL = {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {"name": "gate2_send", "arguments": {"body": "x"}}}


def _receipts(path, *messages):
    path.write_text("".join(
        json.dumps({"kind": "RPC_INGRESS", "direction": "request",
                    "raw": json.dumps(m)}) + "\n" for m in messages))


def _transcript(path):
    path.write_text(json.dumps({"message": {"content": [
        {"type": "tool_use", "id": "local", "name": "mcp__fs__gate2_send",
         "input": {"body": "x"}}]}}) + "\n")


def test_a_mediated_route_reads_the_call_off_the_mediator(tmp_path):
    _receipts(tmp_path / "proxy.receipts.jsonl", CALL)
    call, source = batch.route_call(tmp_path, "proxy_strict", None)
    assert source == "proxy_ingress"
    assert call["name"] == "gate2_send" and call["arguments"] == {"body": "x"}


def test_a_mediated_route_with_no_receipts_has_no_attestation(tmp_path):
    """The failing row. A transcript sits right there and is not consulted."""
    _transcript(tmp_path / "transcript.jsonl")
    call, source = batch.route_call(tmp_path, "proxy_strict",
                                    tmp_path / "transcript.jsonl")
    assert call is None
    assert source is None


def test_the_last_call_is_the_attested_one(tmp_path):
    """A session can reach for the route more than once."""
    second = json.loads(json.dumps(CALL))
    second["params"]["arguments"] = {"body": "the one the proxy answered"}
    _receipts(tmp_path / "proxy.receipts.jsonl", CALL, second)
    call, _ = batch.route_call(tmp_path, "proxy_strict", None)
    assert call["arguments"] == {"body": "the one the proxy answered"}


def test_an_unmediated_route_says_so_rather_than_claiming_attestation(tmp_path):
    """Control has no mediator, so it has no attested ingress and must say so.

    Reading the transcript here is the only thing available and it is labelled,
    so a reader is never handed a transcript under the name of an arrival.
    """
    _transcript(tmp_path / "transcript.jsonl")
    call, source = batch.route_call(tmp_path, "control", tmp_path / "transcript.jsonl")
    assert call is not None
    assert source == "client_transcript"


def test_a_turn_this_harness_issued_attests_itself(tmp_path):
    """G2-06 on the control route, where there is no mediator to ask.

    The row graded INVALID_STIMULUS with "no call to None was observed at
    ingress", because the only attestation the descriptor path knew about was
    the proxy's receipts and the control route has no proxy. The scenario is
    then ungradeable on the route it exists to be compared against.

    A descriptor turn is not a model's decision, it is issued by this harness,
    so the harness's own record of what it wrote to the server is a record of an
    arrival rather than a report of a decision. That is the distinction that
    matters, not which process happened to hold the pen.
    """
    from client import descriptor

    server = tmp_path / "server.py"
    server.write_text('''
import json, sys
for raw in sys.stdin:
    if not raw.strip():
        continue
    m = json.loads(raw)
    if m.get("id") is None:
        continue
    sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": m["id"],
                                 "result": {"tools": []}}) + "\\n")
    sys.stdout.flush()
''')
    request = {"jsonrpc": "2.0", "id": "desc-1", "method": "tools/list", "params": {}}
    capture = tmp_path / "client.wire.jsonl"
    descriptor.run_turn([sys.executable, str(server)], request, wire_path=capture)

    observed = descriptor.observed_at_ingress(
        tmp_path / "absent.receipts.jsonl", "tools/list", client_wire=capture)
    assert observed is not None, "the turn this harness issued attests nothing"
    assert observed["method"] == "tools/list"
