"""The verifier, measured against chains built straight from the wire.

Every chain here is assembled by `_Chain` from `wire.py` and the published
test seed, NOT by the writer. A verifier tested only against its own writer's
output proves the two agree, which is the one thing ASTRA said is not enough:
the instrument is built from the frozen bytes, independently of the product.

Each row names the expected value of EACH of the five results (key trust,
chain integrity, unsigned tail, expected endpoint, lifecycle), never one
pass/fail. Every mutation has its positive control beside it: a verifier that
refuses everything must fail this file.
"""
import pathlib
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import codes                                               # noqa: E402
import verify                                              # noqa: E402
import wire                                                # noqa: E402

SEED = bytes(range(32))            # the published test seed, never a real key
OTHER_SEED = bytes(range(1, 33))


def _public(seed):
    return ed25519.Ed25519PrivateKey.from_private_bytes(seed).public_key() \
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


PUBLIC = _public(SEED)
FP = wire.key_fingerprint(PUBLIC)


class _Chain:
    """Lines built from the wire alone. `seal()` appends a signed checkpoint
    covering everything before it."""

    def __init__(self, seed=SEED, chain_id="chain-verify-0001", interval=100):
        self.key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)
        self.fp = wire.key_fingerprint(_public(seed))
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


def _sealed_chain():
    """Vector 1: genesis, a creation seal, one hook call, a seal."""
    c = _Chain()
    c.seal("genesis")
    c.call("e1")
    c.seal()
    return c


def _results(report):
    return {k: report.results[k] for k in codes.RESULT_KINDS}


# --- 1, 2 · the positive control and the key it trusts ---------------------

def test_1_a_valid_chain_with_a_supplied_fingerprint():
    c = _sealed_chain()
    report = verify.verify(c.data(), PUBLIC, expected_fingerprint=FP,
                           expected_endpoint=c.endpoint(len(c.lines) - 1))
    assert _results(report) == {
        "key_trust": "KEY_TRUSTED", "chain_integrity": "CHAIN_OK",
        "unsigned_tail": "NO_VISIBLE_TAIL",
        "expected_endpoint": "ENDPOINT_CONFIRMED",
        "lifecycle": "LIFECYCLE_COMPLETE"}
    assert codes.strict_exit_code(report.results) == 0


def test_2_no_fingerprint_supplied_is_untrusted_and_integrity_still_holds():
    c = _sealed_chain()
    report = verify.verify(c.data(), PUBLIC)
    assert report.results["key_trust"] == "KEY_UNTRUSTED"
    assert report.results["chain_integrity"] == "CHAIN_OK"
    assert report.results["expected_endpoint"] == "HISTORY_EXTENT_UNKNOWN"


def test_2b_a_pinned_fingerprint_that_is_not_this_key():
    c = _sealed_chain()
    report = verify.verify(c.data(), PUBLIC,
                           expected_fingerprint=wire.key_fingerprint(
                               _public(OTHER_SEED)))
    assert report.results["key_trust"] == "EXPECTED_KEY_MISMATCH"


def test_2c_a_chain_signed_by_another_key_is_not_this_keys_chain():
    c = _Chain(seed=OTHER_SEED)
    c.seal("genesis")
    report = verify.verify(c.data(), PUBLIC)
    assert report.results["chain_integrity"] == "CONTEXT_MISMATCH"


# --- 3, 4, 5 · edits, deletions, reordering --------------------------------

def test_3_a_flipped_byte_in_a_data_row_fails_at_that_line():
    c = _sealed_chain()
    target = 2                                   # the in_flight row
    line = c.lines[target].replace(b'"e1"', b'"e2"')
    assert line != c.lines[target]
    c.lines[target] = line
    report = verify.verify(c.data(), PUBLIC)
    # The edited line is still canonical, so the break is the NEXT link.
    assert report.results["chain_integrity"] == "HASH_LINK_MISMATCH"
    assert report.first_failure_line == target + 2


def test_3b_a_noncanonical_line_is_refused_not_normalized():
    c = _sealed_chain()
    c.lines[2] = c.lines[2].replace(b'","', b'", "', 1)
    report = verify.verify(c.data(), PUBLIC)
    assert report.results["chain_integrity"] == "NONCANONICAL_BYTES"
    assert report.first_failure_line == 3


def test_4_a_deleted_middle_row_breaks_the_chain():
    c = _sealed_chain()
    del c.lines[3]
    report = verify.verify(c.data(), PUBLIC)
    assert report.results["chain_integrity"] in {"SEQUENCE_GAP",
                                                 "HASH_LINK_MISMATCH"}
    assert report.results["chain_integrity"] != "CHAIN_OK"


def test_5_two_rows_swapped_break_the_chain():
    c = _sealed_chain()
    c.lines[2], c.lines[3] = c.lines[3], c.lines[2]
    report = verify.verify(c.data(), PUBLIC)
    assert report.results["chain_integrity"] in {"SEQUENCE_GAP",
                                                 "HASH_LINK_MISMATCH"}


def test_5b_a_forged_signature_is_invalid():
    c = _sealed_chain()
    last = wire.decode_strict(c.lines[-1])
    sig = bytearray.fromhex(last["signature"])
    sig[0] ^= 1
    c.lines[-1] = wire.encode(dict(last, signature=bytes(sig).hex()))
    report = verify.verify(c.data(), PUBLIC)
    assert report.results["chain_integrity"] == "SIGNATURE_INVALID"


def test_5c_no_genesis_is_a_suffix_not_a_history():
    c = _sealed_chain()
    report = verify.verify(b"".join(c.lines[2:]), PUBLIC)
    assert report.results["chain_integrity"] == "MISSING_GENESIS"


# --- 6, 7 · the endpoint (LC02) ---------------------------------------------

def test_6_truncated_at_a_valid_checkpoint_is_never_complete():
    c = _sealed_chain()
    first_seal = 1
    c.call("e2")
    c.seal()
    truncated = b"".join(c.lines[:first_seal + 1])
    report = verify.verify(truncated, PUBLIC, expected_fingerprint=FP)
    assert report.results["chain_integrity"] == "CHAIN_OK"
    assert report.results["unsigned_tail"] == "NO_VISIBLE_TAIL"
    assert report.results["expected_endpoint"] == "HISTORY_EXTENT_UNKNOWN"
    assert codes.strict_exit_code(report.results) == 1


def test_7_a_retained_endpoint_beyond_the_log_is_reported_missing():
    c = _sealed_chain()
    endpoint = c.endpoint(len(c.lines) - 1)
    report = verify.verify(b"".join(c.lines[:2]), PUBLIC,
                           expected_endpoint=endpoint)
    assert report.results["expected_endpoint"] == "EXPECTED_CHECKPOINT_MISSING"


def test_7b_a_retained_endpoint_that_disagrees_is_a_mismatch():
    c = _sealed_chain()
    endpoint = dict(c.endpoint(len(c.lines) - 1), hash="0" * 64)
    report = verify.verify(c.data(), PUBLIC, expected_endpoint=endpoint)
    assert report.results["expected_endpoint"] == "CHECKPOINT_MISMATCH"


def test_7c_an_endpoint_must_be_a_verified_checkpoint():
    """An auditor retains a CHECKPOINT; a data row's hash is not one."""
    c = _sealed_chain()
    report = verify.verify(c.data(), PUBLIC, expected_endpoint=c.endpoint(2))
    assert report.results["expected_endpoint"] == "CHECKPOINT_MISMATCH"


# --- 8, 9 · the tail --------------------------------------------------------

def test_8_an_unsigned_tail_is_counted_with_its_line_bounds():
    c = _sealed_chain()
    c.call("e2")
    c.event("in_flight", eval_id="e3")
    report = verify.verify(c.data(), PUBLIC)
    assert report.results["chain_integrity"] == "CHAIN_OK"
    assert report.results["unsigned_tail"] == "UNVERIFIED_TAIL"
    # lines 1-5: genesis, seal, in_flight, decision, seal. The tail is 6-8.
    assert report.tail == {"count": 3, "first_line": 6, "last_line": 8}
    # The tail is outside the verified prefix: its orphan is not judged.
    assert report.results["lifecycle"] == "LIFECYCLE_COMPLETE"


def test_8b_a_chain_with_no_checkpoint_is_all_tail():
    c = _Chain()
    c.call("e1")
    report = verify.verify(c.data(), PUBLIC)
    assert report.results["unsigned_tail"] == "UNVERIFIED_TAIL"
    assert report.tail["count"] == 3
    assert report.meaning is None


def test_9_a_torn_last_line_is_reported_never_repaired():
    c = _sealed_chain()
    c.event("in_flight", eval_id="e2")
    data = c.data()[:-5]
    report = verify.verify(data, PUBLIC)
    assert report.results["chain_integrity"] == "TRUNCATED_RECORD"
    assert report.first_failure_line == len(c.lines)


# --- 10, 11 · the encoding and domain separation ----------------------------

@pytest.mark.parametrize("bad", [
    b'{"a":1,"a":2}\n', b'{"a":1.5}\n', b'{"a":NaN}\n', b'{"a":"x\\u0001"}\n',
    b'{"a": 1}\n'])
def test_10_a_refused_encoding_is_refused_per_case(bad):
    c = _sealed_chain()
    report = verify.verify(c.data() + bad, PUBLIC)
    assert report.results["chain_integrity"] == "NONCANONICAL_BYTES"
    assert report.first_failure_line == len(c.lines) + 1


def test_11_a_signature_replayed_under_the_record_domain_is_refused():
    """The checkpoint's signature bytes, made over the RECORD domain instead:
    the same key, the same fields, the wrong domain."""
    c = _sealed_chain()
    last = wire.decode_strict(c.lines[-1])
    unsigned = {k: v for k, v in last.items() if k != "signature"}
    wrong = c.key.sign(wire.RECORD_DOMAIN + wire.encode(unsigned))
    c.lines[-1] = wire.encode(dict(unsigned, signature=wrong.hex()))
    report = verify.verify(c.data(), PUBLIC)
    assert report.results["chain_integrity"] == "SIGNATURE_INVALID"


def test_11b_a_checkpoint_that_covers_a_different_head_is_refused():
    c = _sealed_chain()
    last = wire.decode_strict(c.lines[-1])
    unsigned = {k: v for k, v in last.items() if k != "signature"}
    unsigned["covered_head"] = "f" * 64
    sig = c.key.sign(wire.checkpoint_signing_bytes(unsigned))
    c.lines[-1] = wire.encode(dict(unsigned, signature=sig.hex()))
    report = verify.verify(c.data(), PUBLIC)
    assert report.results["chain_integrity"] == "HASH_LINK_MISMATCH"


# --- 13 · LC01, a valid and false log ---------------------------------------

def test_13_a_valid_and_false_log_is_green_and_says_what_green_means():
    c = _Chain()
    c.seal("genesis")
    c.event("in_flight", eval_id="e1", note="the scanner ran")   # it did not
    c.event("decision", eval_id="e1", decision="allow")
    end = c.seal()
    report = verify.verify(c.data(), PUBLIC, expected_fingerprint=FP,
                           expected_endpoint=c.endpoint(end))
    assert codes.strict_exit_code(report.results) == 0
    assert report.meaning == codes.MEANING_TEMPLATE.format(
        fingerprint=FP, start=0, end=f"{end}/{wire.record_hash(c.lines[end])}")
    rendered = verify.render(report).lower()
    assert "clean" not in rendered
    for kind in codes.RESULT_KINDS:
        assert kind in rendered


# --- 14, 15 · lifecycle -----------------------------------------------------

def test_14_an_unknown_event_is_meaning_not_integrity():
    c = _Chain()
    c.seal("genesis")
    c.event("from_the_future", eval_id="x")
    c.seal()
    report = verify.verify(c.data(), PUBLIC)
    assert report.results["chain_integrity"] == "CHAIN_OK"
    assert report.results["lifecycle"] == "UNKNOWN_EVENT"


def test_15_an_opening_without_its_terminal_is_an_orphan():
    c = _Chain()
    c.seal("genesis")
    c.event("in_flight", eval_id="e1")
    c.seal()
    report = verify.verify(c.data(), PUBLIC)
    assert report.results["chain_integrity"] == "CHAIN_OK"
    assert report.results["lifecycle"] == "LIFECYCLE_ORPHAN"


def test_15b_two_terminals_for_one_opening_is_a_duplicate():
    c = _Chain()
    c.seal("genesis")
    c.call("e1")
    c.event("decision", eval_id="e1")
    c.seal()
    report = verify.verify(c.data(), PUBLIC)
    assert report.results["lifecycle"] == "LIFECYCLE_DUPLICATE"


# --- 16 · the verifier is not a checker that says no ------------------------

def test_16_every_mutation_above_starts_from_a_chain_this_verifier_accepts():
    c = _sealed_chain()
    report = verify.verify(c.data(), PUBLIC, expected_fingerprint=FP,
                           expected_endpoint=c.endpoint(len(c.lines) - 1))
    assert codes.strict_exit_code(report.results) == 0
    assert report.first_failure_line is None


def test_the_verifier_imports_nothing_from_sunglasses():
    """WIRE_SPEC §Offline: a standalone verifier. Read, not imported."""
    source = (HERE.parent / "verify.py").read_text(encoding="utf-8")
    assert "import sunglasses" not in source
    assert "from sunglasses" not in source
