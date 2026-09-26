"""Wire level controls. Every one of them is a mutation, not a happy path.

These cover the parts of ASTRA's SR01 to SR09 and SR19 that live in the
encoding and the hashes. The parts that need a writer, a store, concurrency or
an offline bundle are not here and are not claimed: this file proves the bytes,
and nothing about a system that does not exist yet.

A positive control sits beside each refusal, because a checker that refuses
everything passes every negative test ever written.
"""
import json
import pathlib
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

import make_vectors                                        # noqa: E402
import wire                                                # noqa: E402


@pytest.fixture(scope="module")
def vectors():
    return make_vectors.build()


# --- the positive controls -------------------------------------------------

def test_a_canonical_line_round_trips(vectors):
    line = bytes.fromhex(vectors["records"]["genesis"]["line_hex"])
    assert wire.decode_strict(line) == vectors["records"]["genesis"]["record"]


def test_a_real_signature_verifies(vectors):
    """Without this, every rejection below could be a checker that says no."""
    public = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(vectors["key"]["public_hex"]))
    checkpoint = vectors["records"]["checkpoint"]
    public.verify(bytes.fromhex(checkpoint["signature_hex"]),
                  wire.checkpoint_signing_bytes(checkpoint["record_signed"]))


# --- the published vectors must not move silently --------------------------

def test_the_vectors_are_pinned(vectors):
    """A committed vector file that regenerates differently is the whole alarm.

    If a domain prefix or the encoding changes, this fails in the same commit
    rather than six weeks later when an auditor's verifier disagrees with ours.
    """
    committed = json.loads((HERE.parent / "VECTORS.json").read_text())
    assert committed == vectors, (
        "VECTORS.json does not match what wire.py produces today. Regenerate "
        "it in the same commit as the change, and say so in the message.")


def test_the_two_domains_are_different(vectors):
    """Otherwise a record could be presented as a checkpoint, or the reverse."""
    assert wire.RECORD_DOMAIN != wire.CHECKPOINT_DOMAIN
    assert wire.FINGERPRINT_DOMAIN not in (wire.RECORD_DOMAIN,
                                           wire.CHECKPOINT_DOMAIN)


def test_the_four_domains_are_different_and_the_vectors_name_them(vectors):
    """T9 ruling 60 adds the marker's. Each prefix is also no prefix of
    another, so no signed bytes of one kind start like another kind's."""
    domains = [wire.RECORD_DOMAIN, wire.CHECKPOINT_DOMAIN,
               wire.FINGERPRINT_DOMAIN, wire.MARKER_DOMAIN]
    for a in domains:
        assert [b for b in domains if b.startswith(a)] == [a], a
    assert bytes.fromhex(vectors["domains"]["marker_hex"]) == wire.MARKER_DOMAIN


def test_the_marker_vector_replays(vectors):
    """The published marker: its line decodes to its record, its signing bytes
    are the marker domain plus the canonical record, and it verifies."""
    public = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(vectors["key"]["public_hex"]))
    marker = vectors["records"]["marker"]
    line = bytes.fromhex(marker["line_hex"])
    assert line.endswith(b"\n") and wire.decode_strict(line) == marker["record_signed"]
    assert marker["record_signed"]["key_id"] == vectors["key"]["fingerprint"]
    signing = bytes.fromhex(marker["signing_bytes_hex"])
    assert signing == wire.MARKER_DOMAIN + wire.encode(marker["record_unsigned"])
    assert signing == wire.marker_signing_bytes(marker["record_signed"])
    public.verify(bytes.fromhex(marker["signature_hex"]), signing)


@pytest.mark.parametrize("domain", ["record", "checkpoint"])
def test_a_marker_signature_does_not_verify_under_another_domain(vectors, domain):
    from cryptography.exceptions import InvalidSignature
    public = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(vectors["key"]["public_hex"]))
    marker = vectors["records"]["marker"]
    other = bytes.fromhex(vectors["domains"][domain + "_hex"])
    with pytest.raises(InvalidSignature):
        public.verify(bytes.fromhex(marker["signature_hex"]),
                      other + wire.encode(marker["record_unsigned"]))


# --- SR01, a line edited ---------------------------------------------------

def test_editing_a_committed_record_changes_its_chain_hash(vectors):
    record = dict(vectors["records"]["event"]["record"], event="allow")
    assert wire.record_hash(wire.encode(record)) != \
        vectors["records"]["event"]["chain_hash"]


def test_editing_a_signed_checkpoint_breaks_its_signature(vectors):
    public = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(vectors["key"]["public_hex"]))
    tampered = dict(vectors["records"]["checkpoint"]["record_signed"],
                    covered_seq=99)
    with pytest.raises(Exception):
        public.verify(bytes.fromhex(vectors["records"]["checkpoint"]["signature_hex"]),
                      wire.checkpoint_signing_bytes(tampered))


# --- SR04, a correctly encoded signature from the wrong key ----------------

def test_a_valid_signature_from_the_wrong_key_is_rejected(vectors):
    """Not garbage. A real Ed25519 signature, correctly formed, wrong signer."""
    other = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    checkpoint = vectors["records"]["checkpoint"]["record_signed"]
    signing_bytes = wire.checkpoint_signing_bytes(checkpoint)
    forged = other.sign(signing_bytes)
    assert len(forged) == 64, "the forgery must be a well formed signature"
    pinned = ed25519.Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(vectors["key"]["public_hex"]))
    with pytest.raises(Exception):
        pinned.verify(forged, signing_bytes)
    # And it verifies under its own key, so the rejection is about the signer.
    other.public_key().verify(forged, signing_bytes)


def test_two_keys_cannot_share_a_fingerprint(vectors):
    other = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    other_public = other.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)
    assert wire.key_fingerprint(other_public) != vectors["key"]["fingerprint"]


def test_a_fingerprint_needs_a_real_public_key():
    with pytest.raises(wire.NotEncodable, match="32 bytes"):
        wire.key_fingerprint(b"too short")


# --- SR05, truncation ------------------------------------------------------

def test_a_line_without_its_lf_is_truncated_not_shorter(vectors):
    line = bytes.fromhex(vectors["records"]["genesis"]["line_hex"])
    with pytest.raises(wire.NotCanonical, match="terminating LF"):
        wire.decode_strict(line[:-1])


def test_a_record_may_not_span_two_physical_lines(vectors):
    line = bytes.fromhex(vectors["records"]["genesis"]["line_hex"])
    with pytest.raises(wire.NotCanonical, match="more than one LF"):
        wire.decode_strict(line + b"\n")


# --- SR09, schema and encoding --------------------------------------------

def test_duplicate_keys_are_refused():
    """Two parsers can disagree about which value wins, which is the attack."""
    with pytest.raises(wire.NotCanonical, match="duplicate key"):
        wire.decode_strict(b'{"seq":1,"seq":2}\n')


def test_changed_whitespace_is_not_the_same_record():
    with pytest.raises(wire.NotCanonical, match="canonical"):
        wire.decode_strict(b'{"seq": 1}\n')


def test_changed_key_order_is_not_the_same_record():
    with pytest.raises(wire.NotCanonical, match="canonical"):
        wire.decode_strict(b'{"seq":1,"chain_id":"c"}\n')


def test_invalid_utf8_is_located_not_repaired():
    with pytest.raises(wire.NotCanonical, match="UTF-8"):
        wire.decode_strict(b'{"a":"\xff\xfe"}\n')


def test_nan_and_infinity_are_not_values_a_receipt_may_carry():
    for literal in (b'{"a":NaN}\n', b'{"a":Infinity}\n', b'{"a":-Infinity}\n'):
        with pytest.raises(wire.NotCanonical):
            wire.decode_strict(literal)


def test_a_float_cannot_be_encoded():
    """Durations and counts are integers, for a reason that is not fussiness."""
    with pytest.raises(wire.NotEncodable, match="floats"):
        wire.encode({"duration": 1.5})


def test_a_control_character_cannot_be_encoded():
    with pytest.raises(wire.NotEncodable, match="control character"):
        wire.encode({"detail": "line one\nline two"})


def test_an_unknown_type_is_never_converted():
    class Thing:
        pass
    with pytest.raises(wire.NotEncodable, match="no canonical form"):
        wire.encode({"thing": Thing()})


def test_bounds_are_enforced_before_signing():
    with pytest.raises(wire.NotEncodable, match="longer than"):
        wire.encode({"s": "x" * (wire.MAX_STRING + 1)})
    with pytest.raises(wire.NotEncodable, match="64 bit"):
        wire.encode({"n": wire.MAX_INT + 1})
    with pytest.raises(wire.NotEncodable, match="array longer"):
        wire.encode({"a": [0] * (wire.MAX_ARRAY + 1)})


def test_a_record_is_an_object_not_an_array():
    with pytest.raises(wire.NotCanonical, match="an object"):
        wire.decode_strict(b'[1,2]\n')


# --- the signature covers what it should, and no more ----------------------

def test_the_signature_does_not_cover_itself(vectors):
    """Otherwise a checkpoint could never be signed at all."""
    signed = vectors["records"]["checkpoint"]["record_signed"]
    assert wire.SIGNATURE_MEMBER in signed
    assert wire.SIGNATURE_MEMBER.encode() not in \
        wire.checkpoint_signing_bytes(signed)


def test_the_signing_bytes_are_identical_with_and_without_the_member(vectors):
    signed = vectors["records"]["checkpoint"]["record_signed"]
    unsigned = vectors["records"]["checkpoint"]["record_unsigned"]
    assert wire.checkpoint_signing_bytes(signed) == \
        wire.checkpoint_signing_bytes(unsigned)


def test_the_chain_hash_covers_the_framing(vectors):
    """The LF is inside the hash, so a reframed stream cannot hash the same."""
    line = bytes.fromhex(vectors["records"]["genesis"]["line_hex"])
    import hashlib
    assert wire.record_hash(line) == hashlib.sha256(
        wire.RECORD_DOMAIN + line).hexdigest()
    assert wire.record_hash(line) != hashlib.sha256(
        wire.RECORD_DOMAIN + line.rstrip(b"\n")).hexdigest()


# --- the codes are a closed set with no friendly summary -------------------

def test_there_is_no_overall_clean_label():
    """C, overruled: no single word a stranger can quote as 'audit is clean'."""
    import codes
    joined = " ".join(codes.CODES).lower()
    for banned in ("clean", "verified_ok", "all_good", "trusted_log"):
        assert banned not in joined


def test_unknown_extent_is_not_a_pass():
    import codes
    assert codes.strict_exit_code({"expected_endpoint": "HISTORY_EXTENT_UNKNOWN"}) == 1
    assert codes.strict_exit_code({"unsigned_tail": "UNVERIFIED_TAIL"}) == 1
    assert codes.strict_exit_code({"key_trust": "KEY_UNTRUSTED"}) == 1


def test_a_fully_confirmed_log_can_still_pass():
    """The positive control: strict mode is harsh, not impossible."""
    import codes
    assert codes.strict_exit_code({
        "key_trust": "KEY_TRUSTED", "chain_integrity": "CHAIN_OK",
        "unsigned_tail": "NO_VISIBLE_TAIL",
        "expected_endpoint": "ENDPOINT_CONFIRMED",
        "lifecycle": "LIFECYCLE_COMPLETE"}) == 0


def test_the_meaning_sentence_keeps_its_disclaimers():
    import codes
    for phrase in ("does not prove who originally wrote",
                   "that a scanner or tool ran",
                   "does not establish that no later records existed"):
        assert phrase in codes.MEANING_TEMPLATE
