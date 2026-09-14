"""Evidence of what crossed the wire has to be the bytes that crossed it.

ASTRA's round 2 item 4, in his words: LF inclusive wire captures recorded one
byte short, worker output still clipped at 4,109 of 5,094 bytes.

Both are the same failure at different scales. A receipt that is nearly the
evidence cannot be compared against the evidence, and a grader holding a capture
that is one byte short of the stream has to decide whether that byte is a defect
in the instrument or in the thing measured. It is always the instrument, and the
only way to stop asking is to record the frame as it arrived.
"""
import io
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from proxy import passthrough as proxy                        # noqa: E402


def test_a_frame_is_yielded_with_the_terminator_it_arrived_with():
    """`split` drops the newline, and the newline is on the wire.

    Every complete frame was therefore recorded one byte short, and so was every
    byte counter fed from it.
    """
    stream = io.BytesIO(b'{"a":1}\n{"b":2}\n')
    assert list(proxy.bounded_lines(stream, 65536)) == [b'{"a":1}\n', b'{"b":2}\n']


def test_a_final_frame_with_no_terminator_is_yielded_as_it_arrived():
    """No newline on the wire, none invented. The capture is the stream."""
    stream = io.BytesIO(b'{"a":1}\n{"b":2}')
    assert list(proxy.bounded_lines(stream, 65536)) == [b'{"a":1}\n', b'{"b":2}']


def test_an_over_long_frame_still_yields_its_refusable_prefix():
    """The bound is applied before the allocation, and that has not changed."""
    stream = io.BytesIO(b"x" * 40)
    assert list(proxy.bounded_lines(stream, 8)) == [b"x" * 9]


def test_the_capture_reassembles_into_the_exact_stream():
    """The property the grader actually uses: joined frames are the wire."""
    wire = b'{"jsonrpc":"2.0","id":1}\n{"jsonrpc":"2.0","id":2}\n'
    assert b"".join(proxy.bounded_lines(io.BytesIO(wire), 65536)) == wire


WORKER = '''
import json, sys
sys.stdin.buffer.read()
sys.stdout.buffer.write(open(sys.argv[1], "rb").read())
'''


def test_worker_output_is_retained_whole(tmp_path):
    """5,094 bytes in, 5,094 bytes recorded, not 4,109.

    The clip was there so a chatty scanner could not turn the receipt into the
    thing it was describing, which is a real concern and the wrong instrument
    for it. Worker stdout is the scanner's verdict, and a verdict that has been
    cut in half is not evidence of anything. The bound is still there, far above
    any verdict, and when it is crossed the receipt says so and names the file
    holding the whole of it, so evidence is never silently short.
    """
    raw = json.dumps({"result": {"decision": "allow", "inspection_complete": True,
                                 "findings": []}, "padding": "x" * 5000}).encode() + b"\n"
    body = tmp_path / "worker.json"
    body.write_bytes(raw)
    script = tmp_path / "worker.py"
    script.write_text(WORKER)

    p = proxy.Passthrough(receipts_path=tmp_path / "receipts.jsonl")
    p.submit("request", 601, "ok", [sys.executable, str(script), str(body)]).result()
    event = next(e for e in p.events if e["kind"] == "WORKER_OUTPUT")

    assert event["stdout_bytes"] == len(raw)
    assert event["stdout"].encode() == raw
    assert event.get("stdout_truncated") is not True


def test_an_unreasonable_worker_is_bounded_and_the_receipt_says_where(tmp_path):
    """The chatty scanner the clip existed for, handled without losing evidence."""
    raw = b"z" * (proxy.WORKER_OUTPUT_LIMIT + 4096)
    body = tmp_path / "flood.bin"
    body.write_bytes(raw)
    script = tmp_path / "worker.py"
    script.write_text(WORKER)

    p = proxy.Passthrough(receipts_path=tmp_path / "receipts.jsonl")
    p.submit("request", 602, "ok", [sys.executable, str(script), str(body)]).result()
    event = next(e for e in p.events if e["kind"] == "WORKER_OUTPUT")

    assert event["stdout_bytes"] == len(raw)
    assert event["stdout_truncated"] is True
    complete = pathlib.Path(event["stdout_path"])
    assert complete.read_bytes() == raw, "the whole output must survive somewhere"
