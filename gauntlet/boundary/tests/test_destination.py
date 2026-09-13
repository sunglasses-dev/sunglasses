"""The destination's own tests. Each one was made to fail before it was kept.

This layer's whole job is to be believed when it says a payload did or did not
leave, so its tests are written against the three ways it could lie: bind
somewhere it should not, decode bytes it should preserve, or report an empty log
that means nothing.
"""
import json
import pathlib
import sys
import urllib.request

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from destination.sink import Destination, LOOPBACK_ONLY   # noqa: E402


def _post(url: str, body: bytes, path: str = "/exfil"):
    request = urllib.request.Request(url + path, data=body, method="POST")
    with urllib.request.urlopen(request, timeout=5) as response:
        return response.status


# ── 1. loopback only ────────────────────────────────────────────────────────

@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::"])
def test_a_non_loopback_bind_is_refused_at_construction(host):
    """Not warned about, not logged. Refused, before anything can listen."""
    with pytest.raises(ValueError) as refused:
        Destination(host=host)
    assert LOOPBACK_ONLY in str(refused.value)


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
def test_a_loopback_bind_is_accepted(host):
    """And the other half, or the check above could just refuse everything."""
    assert Destination(host=host).host == host


# ── 2. raw bytes ────────────────────────────────────────────────────────────

def test_a_payload_that_is_not_valid_utf8_survives_byte_for_byte():
    """`errors="replace"` here would destroy the thing being measured."""
    payload = b"secret\xff\xfe\x00 not-utf8 \x80\x81"
    with Destination() as sink:
        assert _post(sink.base_url, payload) == 204
        assert len(sink.deliveries) == 1
        assert sink.deliveries[0].body == payload
        record = sink.receipt()["deliveries"][0]
        assert record["body"].encode("latin-1") == payload, "the receipt lost bytes"
        assert record["body_len"] == len(payload)


def test_the_receipt_round_trips_through_json():
    """A receipt that cannot be written and read back is not evidence."""
    payload = b"\x00\x01\x02 exfiltrated \xff"
    with Destination() as sink:
        _post(sink.base_url, payload)
        rebuilt = json.loads(json.dumps(sink.receipt()))
    assert rebuilt["deliveries"][0]["body"].encode("latin-1") == payload


# ── 3. "nothing arrived" is a state, not an absence ─────────────────────────

def test_a_sink_that_listened_and_received_nothing_says_so():
    with Destination() as sink:
        receipt = sink.receipt()
    assert receipt["listened"] is True
    assert receipt["nothing_arrived"] is True
    assert receipt["count"] == 0


def test_a_sink_that_never_listened_is_NOT_the_same_as_one_that_heard_nothing():
    """The distinction the no-mediation control depends on.

    Without it, "the payload was blocked" and "the sink was never running" produce
    the same empty log, and the experiment cannot tell a result from a mistake.
    """
    never = Destination().receipt()
    assert never["listened"] is False
    assert never["nothing_arrived"] is False, (
        "a sink that never started is claiming nothing arrived; that is an "
        "absence of evidence being reported as evidence of absence")


def test_a_sink_that_received_something_does_not_claim_nothing_arrived():
    with Destination() as sink:
        _post(sink.base_url, b"anything")
        receipt = sink.receipt()
    assert receipt["nothing_arrived"] is False and receipt["count"] == 1


# ── the file drop ───────────────────────────────────────────────────────────

def test_a_dropped_file_is_recorded_with_its_bytes(tmp_path):
    drop = tmp_path / "drop"
    sink = Destination(drop_dir=drop)
    (drop / "stolen.bin").write_bytes(b"\xde\xad\xbe\xef key=AKIA")
    found = sink.collect_drops()
    assert len(found) == 1 and found[0].body == b"\xde\xad\xbe\xef key=AKIA"
    assert sink.collect_drops() == [], "the same file was collected twice"


def test_ordering_and_sequence_survive_several_deliveries():
    with Destination() as sink:
        for i in range(5):
            _post(sink.base_url, f"payload-{i}".encode(), path=f"/p{i}")
        records = sink.receipt()["deliveries"]
    assert [r["seq"] for r in records] == [0, 1, 2, 3, 4]
    assert [r["body"] for r in records] == [f"payload-{i}" for i in range(5)]
