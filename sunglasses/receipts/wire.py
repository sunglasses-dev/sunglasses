"""The exact bytes a receipt chain is made of.

ASTRA's design verdict of 2026-09-14 puts this file before everything else:
"Publish exact byte vectors for hashes, signatures and fingerprint derivation
before implementing both writer and verifier." A writer and a verifier written
against prose agree until the day they disagree, and the disagreement surfaces
as an auditor being told their honest log is broken.

So this module is the wire, and only the wire. It does not write files, hold
keys, decide policy or know what a hook is. It defines:

  the canonical encoding      one byte sequence per record, or a refusal
  the chain hash              domain separated, over the full line including LF
  the checkpoint signature    a DIFFERENT domain, over the record minus its
                              own signature member
  the key fingerprint         from an algorithm identifier and raw public bytes

WHAT THIS BUYS, EXACTLY. The protected object is the recorded prefix and its
order. Not the truth of any event. A valid chain says these records, in this
order, were committed by the holder of this key. It does not say a scanner ran,
that the recorded time is real, that the decision is correct, or that no later
records existed. Those limits are in the verifier's output, not just its docs.

THREE RULES THAT LOOK FUSSY AND ARE NOT.

Reject noncanonical bytes; never normalize them. Normalizing altered evidence
before checking it is checking your own rewrite. So `decode_strict` re-encodes
what it parsed and demands byte equality with what it was given.

No floats. A float has more than one shortest representation across languages
and a NaN is not equal to itself. A chain hashed over one implementation's
float formatting is a chain that verifies only on that implementation.

The signature covers the record minus its signature member, followed by one LF,
under its own domain prefix. Without the separate domain, a record could be
presented as a checkpoint or the reverse; without removing the member, the
signature would have to cover itself.
"""
from __future__ import annotations

import hashlib
import json

# --- frozen identifiers ------------------------------------------------------
# These byte strings are part of the wire. Changing one is a new format version,
# never an edit: every previously signed checkpoint verifies under the domain it
# was signed with, and a silent change would make old history look forged.
WIRE_VERSION = "sg-receipt-chain/1"
RECORD_DOMAIN = b"sunglasses-receipt-chain/1\x00record\x00"
CHECKPOINT_DOMAIN = b"sunglasses-receipt-chain/1\x00checkpoint\x00"
FINGERPRINT_DOMAIN = b"sunglasses-receipt-key/1\x00ed25519\x00"

# Fixed, not negotiated. A file that names its own algorithm lets an attacker
# pick the weakest one the verifier still supports.
HASH_ALGORITHM = "sha256"
SIGNATURE_ALGORITHM = "ed25519"

SIGNATURE_MEMBER = "signature"
GENESIS_SEQ = 0
NULL_PREDECESSOR = None

# Bounds. A record is a fixed-shape structural document, not a place to put a
# payload, and every one of these limits exists so an oversized or exotic value
# is refused before it is signed rather than after it is published.
MAX_STRING = 4096
MAX_INT = 2 ** 63 - 1
MIN_INT = -(2 ** 63)
MAX_DEPTH = 8
MAX_KEYS = 64
MAX_ARRAY = 256


class NotCanonical(ValueError):
    """These bytes are not the one encoding this record is allowed to have."""


class NotEncodable(ValueError):
    """This value has no canonical representation, so it may not be signed."""


def _check_value(value, *, depth: int = 0, path: str = "$") -> None:
    """Refuse anything without exactly one byte representation."""
    if depth > MAX_DEPTH:
        raise NotEncodable(f"{path}: nesting deeper than {MAX_DEPTH}")
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, float):
        # Deliberately before the int check: bool is an int subclass but float
        # is not, and a float is the classic source of two honest programs
        # disagreeing about the same document.
        raise NotEncodable(
            f"{path}: floats have more than one shortest representation across "
            "implementations and NaN is not equal to itself. Durations and "
            "counts are integers.")
    if isinstance(value, int):
        if not MIN_INT <= value <= MAX_INT:
            raise NotEncodable(f"{path}: integer outside the signed 64 bit range")
        return
    if isinstance(value, str):
        if len(value) > MAX_STRING:
            raise NotEncodable(f"{path}: string longer than {MAX_STRING}")
        for char in value:
            if ord(char) < 0x20 or ord(char) == 0x7F:
                raise NotEncodable(
                    f"{path}: control character U+{ord(char):04X}. Diagnostics "
                    "are displayed separately and never inside signed bytes.")
            if 0xD800 <= ord(char) <= 0xDFFF:
                raise NotEncodable(
                    f"{path.encode('utf-8', 'backslashreplace').decode()}: lone "
                    f"surrogate U+{ord(char):04X}. UTF-8 cannot "
                    "carry it, so there are no bytes to sign.")
        return
    if isinstance(value, list):
        if len(value) > MAX_ARRAY:
            raise NotEncodable(f"{path}: array longer than {MAX_ARRAY}")
        for index, item in enumerate(value):
            _check_value(item, depth=depth + 1, path=f"{path}[{index}]")
        return
    if isinstance(value, dict):
        if len(value) > MAX_KEYS:
            raise NotEncodable(f"{path}: object with more than {MAX_KEYS} keys")
        for key, item in value.items():
            if not isinstance(key, str):
                raise NotEncodable(f"{path}: non string key {key!r}")
            _check_value(key, depth=depth + 1, path=f"{path}.{key}")
            _check_value(item, depth=depth + 1, path=f"{path}.{key}")
        return
    raise NotEncodable(
        f"{path}: {type(value).__name__} has no canonical form here. There is "
        "no automatic conversion: a value that needed one was never the value "
        "the producer meant to commit.")


def encode(record: dict) -> bytes:
    """The one canonical line for this record, including its single LF.

    Sorted keys, compact separators, UTF-8, no escaping of non-ASCII beyond
    what JSON requires. One LF, at the end, and nowhere else: a record carrying
    an embedded newline would occupy two physical lines and a line oriented
    reader would split one signed record into two unsigned ones.
    """
    if not isinstance(record, dict):
        raise NotEncodable("a record is an object")
    _check_value(record)
    text = json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)
    return text.encode("utf-8") + b"\n"


def _reject_duplicate_keys(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise NotCanonical(
                f"duplicate key {key!r}. Two parsers can disagree about which "
                "value wins, so a duplicate key is a way to show one reader a "
                "different record than another.")
        seen[key] = value
    return seen


def decode_strict(line: bytes) -> dict:
    """Parse a line, or refuse it. Never repair it.

    The re-encode comparison is the whole check: whatever the producer meant,
    these exact bytes are what was hashed, and a document that would encode to
    something else is not the document that was signed. Normalizing it first
    and then checking would be checking our own rewrite of the evidence.
    """
    if not isinstance(line, (bytes, bytearray)):
        raise NotCanonical("a record line is bytes")
    if not line.endswith(b"\n"):
        raise NotCanonical(
            "no terminating LF. A final record without its LF is a truncated "
            "write, not a shorter record.")
    if line.count(b"\n") != 1:
        raise NotCanonical("more than one LF in a single physical record")
    try:
        text = line[:-1].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise NotCanonical(f"not valid UTF-8: {exc}") from exc
    try:
        record = json.loads(text, object_pairs_hook=_reject_duplicate_keys,
                            parse_constant=_reject_constant)
    except NotCanonical:
        raise
    except ValueError as exc:
        raise NotCanonical(f"not JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise NotCanonical("a record is an object")
    try:
        reencoded = encode(record)
    except NotEncodable as exc:
        raise NotCanonical(f"parsed but not encodable: {exc}") from exc
    if reencoded != bytes(line):
        raise NotCanonical(
            "these bytes are not the canonical encoding of the record they "
            "parse to. Changed whitespace, key order or escaping means the "
            "bytes that were signed are not the bytes supplied.")
    return record


def _reject_constant(name):
    raise NotCanonical(f"{name} is not a value a receipt may carry")


def record_hash(line: bytes) -> str:
    """The chain hash of a record, over its full canonical line including LF.

    Including the LF means the framing is signed too, so a reader cannot be
    shown a differently framed stream that hashes the same.
    """
    return hashlib.sha256(RECORD_DOMAIN + bytes(line)).hexdigest()


def checkpoint_signing_bytes(checkpoint: dict) -> bytes:
    """Exactly what a checkpoint signature covers.

    The checkpoint minus its own signature member, canonically encoded with its
    single LF, under the checkpoint domain. A different domain from
    `record_hash` so the same bytes can never be presented as the other kind.
    """
    if SIGNATURE_MEMBER in checkpoint:
        checkpoint = {k: v for k, v in checkpoint.items() if k != SIGNATURE_MEMBER}
    return CHECKPOINT_DOMAIN + encode(checkpoint)


def key_fingerprint(public_key_bytes: bytes) -> str:
    """The fingerprint an auditor is given out of band.

    Over an explicit algorithm identifier and the raw public bytes, so two keys
    of different algorithms can never share a fingerprint and a fingerprint
    cannot be reinterpreted under a different algorithm later.
    """
    if not isinstance(public_key_bytes, (bytes, bytearray)):
        raise NotEncodable("a public key is raw bytes")
    if len(public_key_bytes) != 32:
        raise NotEncodable(
            f"an ed25519 public key is 32 bytes, got {len(public_key_bytes)}")
    return hashlib.sha256(FINGERPRINT_DOMAIN + bytes(public_key_bytes)).hexdigest()
