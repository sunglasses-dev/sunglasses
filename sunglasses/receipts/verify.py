"""Verify a receipt chain offline, and say exactly what the answer means.

WIRE_SPEC §Offline: a standalone verifier with NO `sunglasses` import. It needs
this directory's `wire.py` and `codes.py` and PyCA's Ed25519, nothing else, so
it can be handed to an auditor who never installs the product.

FIVE RESULTS, NEVER ONE. Key trust, chain integrity, unsigned tail, expected
endpoint and lifecycle are computed and printed separately, and nothing here
combines them. A caller who wants one number asks `codes.strict_exit_code`,
which is deliberately harsh: an unknown is not a pass.

WHAT IS VERIFIED IS A PREFIX. The chain is walked from genesis; the verified
prefix ends at the last checkpoint whose signature holds and whose links all
held before it. Everything after it is the unsigned tail -- counted, bounded by
file line, and not judged for lifecycle, because an unsigned record is a claim
nobody has committed to yet. The first integrity failure stops the walk: past a
broken link there is no chain to talk about, only bytes.

WHAT IS NEVER DONE. Nothing is normalized (`decode_strict` refuses rather than
repairs), a torn last line is reported and never re-framed, and a deleted count
is never invented: with no independently retained endpoint the answer is
HISTORY_EXTENT_UNKNOWN, even at a valid checkpoint with nothing after it.
"""
from __future__ import annotations

import dataclasses

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

try:                                   # inside the package
    from . import codes, wire
except ImportError:                    # the standalone bundle: a flat directory
    import codes                       # type: ignore[no-redef]
    import wire                        # type: ignore[no-redef]

CHECKPOINT = "checkpoint"
GENESIS = "genesis"

# Openings and their one terminal, per producer, paired by a body key. A
# closed vocabulary: an event outside it is UNKNOWN_EVENT under lifecycle and
# never an integrity failure -- integrity is about bytes, vocabulary is about
# meaning, and mixing them makes an old verifier call a new honest log forged.
PAIRS = {"in_flight": ("decision", "eval_id")}
TERMINALS = {terminal: (opening, key) for opening, (terminal, key) in PAIRS.items()}
CHAIN_EVENTS = {GENESIS, CHECKPOINT}


@dataclasses.dataclass
class Report:
    results: dict
    first_failure_line: int | None = None
    failure_detail: str | None = None
    tail: dict | None = None
    verified_through: dict | None = None
    meaning: str | None = None
    fingerprint: str | None = None


def _split(data: bytes):
    """Lines WITH their LF. A final chunk without one is returned separately:
    it is torn, and re-framing it would be verifying our own repair."""
    lines, start = [], 0
    while True:
        end = data.find(b"\n", start)
        if end < 0:
            break
        lines.append(data[start:end + 1])
        start = end + 1
    torn = data[start:] if start < len(data) else None
    return lines, torn


def _signature_holds(public: ed25519.Ed25519PublicKey, record: dict) -> bool:
    try:
        signature = bytes.fromhex(record.get(wire.SIGNATURE_MEMBER) or "")
        public.verify(signature, wire.checkpoint_signing_bytes(record))
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def verify(data: bytes, public_key: bytes, *, expected_fingerprint=None,
           expected_endpoint=None) -> Report:
    """`public_key` is the raw 32 bytes. `expected_fingerprint` is obtained
    out of band; the key beside a log gives portability, not trust.
    `expected_endpoint` is `{"seq": int, "hash": hex}` of a checkpoint an
    auditor retained independently."""
    fingerprint = wire.key_fingerprint(public_key)
    results = {
        "key_trust": ("KEY_UNTRUSTED" if expected_fingerprint is None
                      else "KEY_TRUSTED" if expected_fingerprint == fingerprint
                      else "EXPECTED_KEY_MISMATCH"),
    }
    report = Report(results=results, fingerprint=fingerprint)
    public = ed25519.Ed25519PublicKey.from_public_bytes(bytes(public_key))
    lines, torn = _split(bytes(data))

    def fail(code, line_no, detail):
        results["chain_integrity"] = code
        report.first_failure_line = line_no
        report.failure_detail = detail

    records = []             # (line_no, record, hash) for every linked record
    verified = None          # index into `records` of the last verified checkpoint
    chain_id = None
    for index, line in enumerate(lines):
        line_no = index + 1
        try:
            record = wire.decode_strict(line)
        except (wire.NotCanonical, wire.NotEncodable, ValueError) as exc:
            fail("NONCANONICAL_BYTES", line_no, type(exc).__name__)
            break
        if index == 0:
            if (record.get("event") != GENESIS or record.get("seq") != wire.GENESIS_SEQ
                    or record.get("prev_hash") is not wire.NULL_PREDECESSOR):
                fail("MISSING_GENESIS", line_no, "the first record is not a genesis")
                break
            chain_id = record.get("chain_id")
        if (record.get("wire") != wire.WIRE_VERSION
                or record.get("chain_id") != chain_id
                or record.get("key_id") != fingerprint):
            fail("CONTEXT_MISMATCH", line_no,
                 "wire version, chain id or key id does not fit this chain")
            break
        if record.get("seq") != index:
            fail("SEQUENCE_GAP", line_no, f"expected seq {index}")
            break
        previous = records[-1][2] if records else wire.NULL_PREDECESSOR
        if record.get("prev_hash") != previous:
            fail("HASH_LINK_MISMATCH", line_no, "predecessor hash does not match")
            break
        if record.get("event") == CHECKPOINT:
            if (record.get("covered_head") != previous
                    or record.get("covered_seq") != index - 1):
                fail("HASH_LINK_MISMATCH", line_no,
                     "the checkpoint does not cover the record before it")
                break
            if not _signature_holds(public, record):
                fail("SIGNATURE_INVALID", line_no, "checkpoint signature")
                break
            verified = len(records)
        records.append((line_no, record, wire.record_hash(line)))
    else:
        if torn is not None:
            fail("TRUNCATED_RECORD", len(lines) + 1, "no terminating LF")
        else:
            results["chain_integrity"] = "CHAIN_OK"

    # The tail: linked records after the verified prefix. After a failure the
    # prefix still stands up to its last checkpoint; what follows is unjudged.
    prefix = records[:verified + 1] if verified is not None else []
    tail = records[len(prefix):]
    if tail:
        results["unsigned_tail"] = "UNVERIFIED_TAIL"
        report.tail = {"count": len(tail), "first_line": tail[0][0],
                       "last_line": tail[-1][0]}
    else:
        results["unsigned_tail"] = "NO_VISIBLE_TAIL"
        report.tail = {"count": 0, "first_line": None, "last_line": None}

    if prefix:
        end_line, end_record, end_hash = prefix[-1]
        report.verified_through = {"seq": end_record["seq"], "hash": end_hash,
                                   "line": end_line}
        report.meaning = codes.MEANING_TEMPLATE.format(
            fingerprint=fingerprint, start=0,
            end=f"{end_record['seq']}/{end_hash}")

    results["expected_endpoint"] = _endpoint(prefix, records, expected_endpoint)
    results["lifecycle"] = _lifecycle(prefix)
    return report


def _endpoint(prefix, records, expected):
    if expected is None:
        # Never "complete", even with no visible tail (LC02).
        return "HISTORY_EXTENT_UNKNOWN"
    seq, want = expected.get("seq"), expected.get("hash")
    for _, record, digest in records:
        if record.get("seq") == seq:
            is_verified_checkpoint = any(r is record for _, r, _ in prefix) \
                and record.get("event") == CHECKPOINT
            if is_verified_checkpoint and digest == want:
                return "ENDPOINT_CONFIRMED"
            return "CHECKPOINT_MISMATCH"
    return "EXPECTED_CHECKPOINT_MISSING"


def _lifecycle(prefix):
    """Judged over the VERIFIED prefix only."""
    open_, closed, unknown = {}, set(), False
    for _, record, _ in prefix:
        event = record.get("event")
        body = record.get("body") or {}
        if event in CHAIN_EVENTS:
            continue
        if event in PAIRS:
            open_[(event, body.get(PAIRS[event][1]))] = True
        elif event in TERMINALS:
            opening, key = TERMINALS[event]
            ident = (opening, body.get(key))
            if ident in closed:
                return "LIFECYCLE_DUPLICATE"
            if ident not in open_:
                return "LIFECYCLE_ORPHAN"
            closed.add(ident)
        else:
            unknown = True
    if any(ident not in closed for ident in open_):
        return "LIFECYCLE_ORPHAN"
    return "UNKNOWN_EVENT" if unknown else "LIFECYCLE_COMPLETE"


def render(report: Report) -> str:
    """Five lines, then the bounds, then what a valid signature means. There
    is no summary line, by design."""
    out = [f"key: {report.fingerprint}"]
    for kind in codes.RESULT_KINDS:
        code = report.results[kind]
        out.append(f"{kind}: {code} -- {codes.CODES.get(code, '')}")
    if report.first_failure_line is not None:
        out.append(f"first failure: line {report.first_failure_line} "
                   f"({report.failure_detail})")
    if report.tail and report.tail["count"]:
        out.append(f"unsigned tail: {report.tail['count']} records, lines "
                   f"{report.tail['first_line']}-{report.tail['last_line']}")
    if report.meaning:
        out.append(report.meaning)
    for code, text in codes.LIMITATIONS.items():
        out.append(f"{code}: {text}")
    return "\n".join(out)
