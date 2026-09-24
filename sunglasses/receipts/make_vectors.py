#!/usr/bin/env python3
"""Produce the published byte vectors two independent implementations agree on.

ASTRA: "Publish exact byte vectors for hashes, signatures and fingerprint
derivation before implementing both writer and verifier." This generates them
from `wire.py` itself, so the specification and the code cannot drift: if
someone changes a domain prefix, the vectors change in the same commit and the
diff says so out loud.

The signing key here is a FIXED, PUBLISHED test seed. It is a test vector, not
a secret, and it is written down precisely so an independent implementation can
reproduce every signature below byte for byte. No real key is ever used to
generate documentation.

Run:  python3 make_vectors.py > VECTORS.json
"""
from __future__ import annotations

import json
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

import codes
import wire

# A published test seed. Never a real key: this one exists to be copied.
TEST_SEED = bytes(range(32))
# A second published seed, for "signed by a key that is not this one".
OTHER_SEED = bytes(range(1, 33))

GENESIS = {
    "chain_id": "chain-test-0001",
    "event": "genesis",
    "key_id": "key-test-0001",
    "prev_hash": None,
    "seq": 0,
    "wire": wire.WIRE_VERSION,
}

EVENT = {
    "chain_id": "chain-test-0001",
    "event": "decision",
    "key_id": "key-test-0001",
    "prev_hash": None,          # filled from the genesis hash below
    "seq": 1,
    "wire": wire.WIRE_VERSION,
}

CHECKPOINT = {
    "chain_id": "chain-test-0001",
    "covered_head": None,       # filled from the event hash below
    "covered_seq": 1,
    "event": "checkpoint",
    "interval": 100,
    "key_id": "key-test-0001",
    "prev_hash": None,          # filled from the event hash below
    "purpose": "interval",
    "seq": 2,
    "wire": wire.WIRE_VERSION,
}


def public_bytes(seed: bytes) -> bytes:
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key() \
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


class WireChain:
    """Lines built from the wire alone, never by the writer. `seal()` appends
    a signed checkpoint covering everything before it. The verifier's tests
    and the exported verifier vectors are both built with this, so the bytes
    an outside implementation copies are the bytes our tests ran on."""

    def __init__(self, seed=TEST_SEED, chain_id="chain-verify-0001", interval=100):
        self.key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        self.fp = wire.key_fingerprint(public_bytes(seed))
        self.chain_id = chain_id
        self.interval = interval
        self.lines = []
        self._add({"event": "genesis", "prev_hash": None})

    def _head(self):
        return wire.record_hash(self.lines[-1]) if self.lines else None

    def _add(self, fields):
        record = {"chain_id": self.chain_id, "key_id": self.fp,
                  "seq": len(self.lines), "wire": wire.WIRE_VERSION,
                  "prev_hash": self._head(), **fields}
        self.lines.append(wire.encode(record))
        return record

    def event(self, event, **body):
        return self._add({"event": event, "body": body})

    def seal(self, purpose="interval"):
        record = {"chain_id": self.chain_id, "covered_head": self._head(),
                  "covered_seq": len(self.lines) - 1, "event": "checkpoint",
                  "interval": self.interval, "key_id": self.fp,
                  "prev_hash": self._head(), "purpose": purpose,
                  "seq": len(self.lines), "wire": wire.WIRE_VERSION}
        signature = self.key.sign(wire.checkpoint_signing_bytes(record))
        self.lines.append(wire.encode(dict(record, signature=signature.hex())))
        return len(self.lines) - 1

    def call(self, eval_id):
        self.event("in_flight", eval_id=eval_id)
        self.event("decision", eval_id=eval_id)

    def data(self):
        return b"".join(self.lines)

    def endpoint(self, index):
        return {"seq": index, "hash": wire.record_hash(self.lines[index])}


def sealed_chain():
    """Vector 1: genesis, a creation seal, one hook call, a seal."""
    c = WireChain()
    c.seal("genesis")
    c.call("e1")
    c.seal()
    return c


def segment(chain_id, previous=None, observed_unsigned=0, **kw):
    """A segment's opening, as the writer frames it: genesis (naming its
    predecessor, if any) and the genesis checkpoint."""
    c = WireChain(chain_id=chain_id, **kw)
    c.lines = []
    body = {}
    if previous is not None:
        body = {"previous": previous, "observed_unsigned": observed_unsigned}
    c._add({"event": "genesis", "prev_hash": None, "body": body})
    c.seal("genesis")
    return c


def names(c):
    """What a successor's genesis names: this segment's last checkpoint."""
    index = max(i for i, line in enumerate(c.lines)
                if wire.decode_strict(line)["event"] == "checkpoint")
    return {"chain_id": c.chain_id, "seq": index,
            "hash": wire.record_hash(c.lines[index])}


# --- the verifier's vectors (spec freeze section 6) --------------------------
# Every expected value below is stated by hand from the construction, never
# read back from the verifier. The replay test runs verify.py over these bytes
# and compares; a verifier and an expectation that disagree fail the suite.

UNTRUSTED, TRUSTED = "KEY_UNTRUSTED", "KEY_TRUSTED"
OK, UNKNOWN_EXTENT = "CHAIN_OK", "HISTORY_EXTENT_UNKNOWN"
NO_TAIL, TAIL, COMPLETE = "NO_VISIBLE_TAIL", "UNVERIFIED_TAIL", "LIFECYCLE_COMPLETE"
NOT_EXPORTED = {
    "12": "rotation is specified, not built and not claimed (T9 ruling 40). "
          "The verifier prints ROTATION_UNSUPPORTED for a segment signed by "
          "another key; the SUCCESSOR_ASSERTED row is a strict xfail in "
          "tests/test_verify_log.py until rotation is built.",
    "16": "the positive control is vector 1: every mutation starts from bytes "
          "this verifier accepts, so a verifier that refuses everything fails "
          "vector 1.",
}


def _results(key=UNTRUSTED, integrity=OK, tail=NO_TAIL, endpoint=UNKNOWN_EXTENT,
             lifecycle=COMPLETE):
    return {"key_trust": key, "chain_integrity": integrity,
            "unsigned_tail": tail, "expected_endpoint": endpoint,
            "lifecycle": lifecycle}


def _tail(count=0, first=None, last=None):
    return {"count": count, "first_line": first, "last_line": last}


def _through(c, seq):
    """The verified prefix ends at this checkpoint (seq == its 0 based index,
    line == seq + 1)."""
    return {"seq": seq, "hash": wire.record_hash(c.lines[seq]), "line": seq + 1}


def _vector(vid, title, data, c=None, *, fingerprint=None, endpoint=None,
            results, first_failure_line=None, tail=None, through=None,
            meaning=None):
    expect = {"results": results, "first_failure_line": first_failure_line,
              "tail": tail or _tail(),
              "verified_through": _through(c, through) if through is not None else None}
    if meaning is not None:
        expect["meaning"] = meaning
    return {"id": vid, "title": title,
            "input": {"data_hex": data.hex(),
                      "public_hex": public_bytes(TEST_SEED).hex(),
                      "expected_fingerprint": fingerprint,
                      "expected_endpoint": endpoint},
            "expect": expect}


def verifier_vectors() -> list:
    fp = wire.key_fingerprint(public_bytes(TEST_SEED))
    other_fp = wire.key_fingerprint(public_bytes(OTHER_SEED))
    out = []
    # Lines of the sealed chain: 1 genesis, 2 genesis seal, 3 in_flight e1,
    # 4 decision e1, 5 interval seal.
    c = sealed_chain()
    out.append(_vector("1", "a valid chain, fingerprint and endpoint supplied",
                       c.data(), c, fingerprint=fp, endpoint=c.endpoint(4),
                       results=_results(TRUSTED, endpoint="ENDPOINT_CONFIRMED"),
                       through=4))
    out.append(_vector("2", "no fingerprint supplied: untrusted, integrity holds",
                       c.data(), c, results=_results(), through=4))
    out.append(_vector("2b", "a pinned fingerprint that is not this key",
                       c.data(), c, fingerprint=other_fp,
                       results=_results("EXPECTED_KEY_MISMATCH"), through=4))

    o = WireChain(seed=OTHER_SEED)
    o.seal("genesis")
    out.append(_vector("2c", "a chain signed by another key", o.data(),
                       results=_results(integrity="CONTEXT_MISMATCH"),
                       first_failure_line=1))

    c = sealed_chain()
    c.lines[2] = c.lines[2].replace(b'"e1"', b'"e2"')
    out.append(_vector("3", "an edited data row, still canonical: the NEXT link breaks",
                       c.data(), c,
                       results=_results(integrity="HASH_LINK_MISMATCH", tail=TAIL),
                       first_failure_line=4, tail=_tail(1, 3, 3), through=1))

    c = sealed_chain()
    c.lines[2] = c.lines[2].replace(b'","', b'", "', 1)
    out.append(_vector("3b", "a noncanonical line is refused, never normalized",
                       c.data(), c,
                       results=_results(integrity="NONCANONICAL_BYTES"),
                       first_failure_line=3, through=1))

    c = sealed_chain()
    del c.lines[3]
    out.append(_vector("4", "a deleted middle row", c.data(), c,
                       results=_results(integrity="SEQUENCE_GAP", tail=TAIL),
                       first_failure_line=4, tail=_tail(1, 3, 3), through=1))

    c = sealed_chain()
    c.lines[2], c.lines[3] = c.lines[3], c.lines[2]
    out.append(_vector("5", "two rows swapped", c.data(), c,
                       results=_results(integrity="SEQUENCE_GAP"),
                       first_failure_line=3, through=1))

    c = sealed_chain()
    last = wire.decode_strict(c.lines[-1])
    sig = bytearray.fromhex(last["signature"])
    sig[0] ^= 1
    c.lines[-1] = wire.encode(dict(last, signature=bytes(sig).hex()))
    out.append(_vector("5b", "a forged checkpoint signature", c.data(), c,
                       results=_results(integrity="SIGNATURE_INVALID", tail=TAIL),
                       first_failure_line=5, tail=_tail(2, 3, 4), through=1))

    c = sealed_chain()
    out.append(_vector("5c", "no genesis: a suffix, not a history",
                       b"".join(c.lines[2:]),
                       results=_results(integrity="MISSING_GENESIS"),
                       first_failure_line=1))

    c = sealed_chain()
    out.append(_vector("6", "truncated at a valid checkpoint is never complete (LC02)",
                       b"".join(c.lines[:2]), c, fingerprint=fp,
                       results=_results(TRUSTED), through=1))
    out.append(_vector("7", "a retained endpoint beyond the log",
                       b"".join(c.lines[:2]), c, endpoint=c.endpoint(4),
                       results=_results(endpoint="EXPECTED_CHECKPOINT_MISSING"),
                       through=1))
    out.append(_vector("7b", "a retained endpoint that disagrees", c.data(), c,
                       endpoint=dict(c.endpoint(4), hash="0" * 64),
                       results=_results(endpoint="CHECKPOINT_MISMATCH"), through=4))
    out.append(_vector("7c", "an endpoint must be a verified checkpoint, not a data row",
                       c.data(), c, endpoint=c.endpoint(2),
                       results=_results(endpoint="CHECKPOINT_MISMATCH"), through=4))

    c = sealed_chain()
    c.call("e2")
    c.event("in_flight", eval_id="e3")
    out.append(_vector("8", "an unsigned tail of 3, counted with its line bounds; "
                       "the orphan inside it is not judged", c.data(), c,
                       results=_results(tail=TAIL), tail=_tail(3, 6, 8), through=4))

    c = WireChain()
    c.call("e1")
    out.append(_vector("8b", "no checkpoint at all: everything is tail, nothing "
                       "is verified, so there is no meaning line", c.data(),
                       results=_results(tail=TAIL), tail=_tail(3, 1, 3)))

    c = sealed_chain()
    c.event("in_flight", eval_id="e2")
    out.append(_vector("9", "a torn last line is TRUNCATED_RECORD, never repaired",
                       c.data()[:-5], c,
                       results=_results(integrity="TRUNCATED_RECORD"),
                       first_failure_line=6, through=4))

    c = sealed_chain()
    for suffix, bad in zip("abcde", (b'{"a":1,"a":2}\n', b'{"a":1.5}\n',
                                     b'{"a":NaN}\n', b'{"a":"x\\u0001"}\n',
                                     b'{"a": 1}\n')):
        out.append(_vector("10" + suffix, "a refused encoding: " + bad[:-1].decode(),
                           c.data() + bad, c,
                           results=_results(integrity="NONCANONICAL_BYTES"),
                           first_failure_line=6, through=4))

    c = sealed_chain()
    last = wire.decode_strict(c.lines[-1])
    unsigned = {k: v for k, v in last.items() if k != "signature"}
    wrong = c.key.sign(wire.RECORD_DOMAIN + wire.encode(unsigned))
    c.lines[-1] = wire.encode(dict(unsigned, signature=wrong.hex()))
    out.append(_vector("11", "a checkpoint signed under the RECORD domain",
                       c.data(), c,
                       results=_results(integrity="SIGNATURE_INVALID", tail=TAIL),
                       first_failure_line=5, tail=_tail(2, 3, 4), through=1))

    c = sealed_chain()
    last = wire.decode_strict(c.lines[-1])
    unsigned = {k: v for k, v in last.items() if k != "signature"}
    unsigned["covered_head"] = "f" * 64
    sig = c.key.sign(wire.checkpoint_signing_bytes(unsigned))
    c.lines[-1] = wire.encode(dict(unsigned, signature=sig.hex()))
    out.append(_vector("11b", "a validly signed checkpoint covering another head",
                       c.data(), c,
                       results=_results(integrity="HASH_LINK_MISMATCH", tail=TAIL),
                       first_failure_line=5, tail=_tail(2, 3, 4), through=1))

    c = WireChain()
    c.seal("genesis")
    c.event("in_flight", eval_id="e1", note="the scanner ran")   # it did not
    c.event("decision", eval_id="e1", decision="allow")
    end = c.seal()
    out.append(_vector(
        "13", "a valid and false log (LC01): every result green, and the "
        "meaning line says what green does not prove", c.data(), c,
        fingerprint=fp, endpoint=c.endpoint(end),
        results=_results(TRUSTED, endpoint="ENDPOINT_CONFIRMED"), through=end,
        meaning=codes.MEANING_TEMPLATE.format(
            fingerprint=fp, start=0,
            end=f"{end}/{wire.record_hash(c.lines[end])}")))

    c = WireChain()
    c.seal("genesis")
    c.event("from_the_future", eval_id="x")
    c.seal()
    out.append(_vector("14", "an unknown event is meaning, not integrity",
                       c.data(), c, results=_results(lifecycle="UNKNOWN_EVENT"),
                       through=3))

    c = WireChain()
    c.seal("genesis")
    c.event("in_flight", eval_id="e1")
    c.seal()
    out.append(_vector("15", "an opening without its terminal", c.data(), c,
                       results=_results(lifecycle="LIFECYCLE_ORPHAN"), through=3))

    c = WireChain()
    c.seal("genesis")
    c.call("e1")
    c.event("decision", eval_id="e1")
    c.seal()
    out.append(_vector("15b", "two terminals for one opening", c.data(), c,
                       results=_results(lifecycle="LIFECYCLE_DUPLICATE"), through=5))
    return out


def _log(*segments):
    return [{"name": f"segment-{n:06d}.chain", "data_hex": s.data().hex()}
            for n, s in enumerate(segments, 1)]


def log_vectors() -> list:
    """A log is a directory of segments; `name` is the file name inside it."""
    fp = wire.key_fingerprint(public_bytes(TEST_SEED))
    log_ok = _results(TRUSTED)
    out = []

    a = segment("seg-a"); a.call("e1"); a.seal("close")
    b = segment("seg-b", previous=names(a)); b.call("e2"); b.seal("close")
    c = segment("seg-c", previous=names(b)); c.call("e3"); c.seal("close")
    p = segment("proxy-a"); p.call("p1"); p.seal("close")
    out.append({
        "id": "17", "title": "two logs, five results each, verified alone",
        "public_hex": public_bytes(TEST_SEED).hex(), "expected_fingerprint": fp,
        "logs": {"hook": _log(a, b, c), "proxy-srv": _log(p)},
        "expect": {"hook": {"results": log_ok, "first_failure_segment": None},
                   "proxy-srv": {"results": log_ok, "first_failure_segment": None}}})

    a = segment("seg-a"); a.call("e1"); a.seal("close")
    named = names(a)
    a.call("e2")                                       # died: never sealed
    b = segment("seg-b", previous=named, observed_unsigned=2)
    b.call("e3"); b.seal("close")
    out.append({
        "id": "18", "title": "a call that died leaves its own segment's tail "
        "unverified, and the next segment names the last checkpoint that holds",
        "public_hex": public_bytes(TEST_SEED).hex(), "expected_fingerprint": fp,
        "logs": {"hook": _log(a, b)},
        "expect": {"hook": {
            "results": _results(TRUSTED, tail=TAIL), "first_failure_segment": None,
            "segments": {"segment-000001.chain": _results(TRUSTED, tail=TAIL),
                         "segment-000002.chain": _results(TRUSTED)}}}})
    return out


def build() -> dict:
    private = ed25519.Ed25519PrivateKey.from_private_bytes(TEST_SEED)
    public = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)

    genesis_line = wire.encode(GENESIS)
    genesis_hash = wire.record_hash(genesis_line)

    event = dict(EVENT, prev_hash=genesis_hash)
    event_line = wire.encode(event)
    event_hash = wire.record_hash(event_line)

    # The covered head is the PREVIOUS record's hash, and the completed signed
    # checkpoint becomes the next predecessor.
    checkpoint = dict(CHECKPOINT, prev_hash=event_hash, covered_head=event_hash)
    signing_bytes = wire.checkpoint_signing_bytes(checkpoint)
    signature = private.sign(signing_bytes)
    signed = dict(checkpoint, signature=signature.hex())
    signed_line = wire.encode(signed)

    return {
        "note": "Generated by make_vectors.py from wire.py. The seed is a "
                "published test value and never a real key.",
        "wire_version": wire.WIRE_VERSION,
        "hash_algorithm": wire.HASH_ALGORITHM,
        "signature_algorithm": wire.SIGNATURE_ALGORITHM,
        "domains": {
            "record": wire.RECORD_DOMAIN.decode("latin-1"),
            "record_hex": wire.RECORD_DOMAIN.hex(),
            "checkpoint": wire.CHECKPOINT_DOMAIN.decode("latin-1"),
            "checkpoint_hex": wire.CHECKPOINT_DOMAIN.hex(),
            "fingerprint": wire.FINGERPRINT_DOMAIN.decode("latin-1"),
            "fingerprint_hex": wire.FINGERPRINT_DOMAIN.hex(),
        },
        "key": {
            "seed_hex": TEST_SEED.hex(),
            "public_hex": public.hex(),
            "fingerprint": wire.key_fingerprint(public),
        },
        "records": {
            "genesis": {
                "record": GENESIS,
                "line_hex": genesis_line.hex(),
                "line_utf8": genesis_line.decode("utf-8"),
                "chain_hash": genesis_hash,
            },
            "event": {
                "record": event,
                "line_hex": event_line.hex(),
                "line_utf8": event_line.decode("utf-8"),
                "chain_hash": event_hash,
            },
            "checkpoint": {
                "record_unsigned": checkpoint,
                "signing_bytes_hex": signing_bytes.hex(),
                "signature_hex": signature.hex(),
                "record_signed": signed,
                "line_hex": signed_line.hex(),
                "line_utf8": signed_line.decode("utf-8"),
                "chain_hash": wire.record_hash(signed_line),
            },
        },
        "verifier": verifier_vectors(),
        "verifier_logs": log_vectors(),
        "verifier_not_exported": NOT_EXPORTED,
    }


if __name__ == "__main__":
    json.dump(build(), sys.stdout, indent=1, sort_keys=True)
    sys.stdout.write("\n")
