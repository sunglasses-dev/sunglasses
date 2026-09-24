"""The machine reason codes a verifier prints, and the five results it separates.

ASTRA's ruling C, overruling the brief: a key commits to a PREFIX. It does not
prove who wrote each line. So there is no overall "clean audit trail" label
anywhere in this package, and there is no single boolean a caller can read to
get one. A verifier prints five independent results, and a reader who wants a
summary has to look at all five.

That is deliberate friction. A single green word is what a stranger quotes, and
the single green word would be wrong.
"""
from __future__ import annotations

# The five results, always printed separately, never combined.
RESULT_KINDS = (
    "key_trust",             # do we have independent reason to expect this key
    "chain_integrity",       # do the hashes and signatures hold over the prefix
    "unsigned_tail",         # what is visible after the last verified checkpoint
    "expected_endpoint",     # does an independently retained boundary match
    "lifecycle",             # are openings and terminals paired
)

CODES = {
    # key trust
    "KEY_TRUSTED": "the supplied key matches an independently obtained fingerprint",
    "KEY_UNTRUSTED": "valid under this supplied key; ownership unknown",
    "EXPECTED_KEY_MISMATCH": "the key does not match the pinned fingerprint",
    "KEY_UNUSABLE": ("signing is on and the key cannot sign, so nothing new is "
                     "signed; the cause and the command that clears it are "
                     "printed with it (T9 ruling R21)"),

    # chain integrity
    "CHAIN_OK": "hashes and signatures hold across the verified prefix",
    "HASH_LINK_MISMATCH": "a record's predecessor hash does not match",
    "SEQUENCE_GAP": "sequence numbers do not increment by exactly one",
    "SIGNATURE_INVALID": "a checkpoint signature does not verify under the key",
    "TRUNCATED_RECORD": "a final record has no terminating LF",
    "NONCANONICAL_BYTES": "bytes are not the canonical encoding of their record",
    "CONTEXT_MISMATCH": "a record's bound chain, session or segment does not fit here",

    # the tail
    "UNVERIFIED_TAIL": "records visible after the last verified checkpoint",
    "NO_VISIBLE_TAIL": "no records after the last verified checkpoint",

    # the endpoint. The one most likely to be quoted wrongly.
    "HISTORY_EXTENT_UNKNOWN":
        "no independently retained endpoint, so how far the history once "
        "extended is unknown. This is reported even at a valid checkpoint with "
        "no visible tail: an attacker who removed whole intervals leaves "
        "exactly that picture.",
    "EXPECTED_CHECKPOINT_MISSING": "the retained endpoint is absent from this log",
    "CHECKPOINT_MISMATCH": "the retained endpoint disagrees with this log",
    "ENDPOINT_CONFIRMED": "the independently retained endpoint is present and matches",

    # boundaries and epochs
    "MISSING_GENESIS": "no authenticated start, and a suffix is not a history",
    "SEGMENT_MISSING": "a rotated segment referenced by its successor is absent",
    "PREDECESSOR_UNAVAILABLE": "the named earlier chain material is not present",
    "SUCCESSOR_ASSERTED":
        "this signer points at that older history. Not authorisation by the "
        "old key, and not proof of the same owner.",
    "SUCCESSOR_ENDORSED": "the old key signed this successor binding",
    "LEGACY_UNSIGNED": "predates signing; integrity status unknown, not clean",

    # lifecycle
    "LIFECYCLE_COMPLETE": "every opening has its terminal",
    "LIFECYCLE_ORPHAN": "an opening with no terminal, or a terminal with no opening",
    "LIFECYCLE_DUPLICATE": "more than one settlement for one invocation",
    "PAIRING_UNKEYED":
        "the session opened and ended; the items inside it carry no key to "
        "pair them by, so whether each one settled is not judged (T9 ruling "
        "R24, WIRE_SPEC section 4). Not a pass and not a failure.",
    "UNKNOWN_EVENT":
        "an event outside this verifier's vocabulary; its meaning is not "
        "judged, and chain integrity is unaffected",
}

# Exactly what a verifier prints about what a valid signature means. ASTRA's
# replacement sentence, with the boundaries filled in from the actual log. It is
# a constant so it cannot drift into something friendlier over time.
MEANING_TEMPLATE = (
    "The checkpoint signature is valid under key {fingerprint}. The supplied "
    "records from {start} through {end}, including their order, match the "
    "prefix committed by that signature. This does not prove who originally "
    "wrote the records, that a scanner or tool ran, that the recorded time or "
    "decision is true, or that the hook was installed. It does not establish "
    "that no later records existed."
)

# The three limitations that are NOT defects and must never be "fixed" by
# rejecting valid logs. A verifier states them; it cannot detect them.
LIMITATIONS = {
    "LC01": "a key holder can fabricate and correctly sign false events. "
            "Cryptography accepts the commitment; it does not audit the claim.",
    "LC02": "an earlier valid checkpoint with no independently retained later "
            "endpoint is indistinguishable from a history that genuinely "
            "stopped there.",
    "LC03": "an action taken outside logging is not observed at all.",
}


def strict_exit_code(results: dict) -> int:
    """Nonzero for invalid integrity, unknown key or extent, tail, or incomplete.

    A caller that wants one number gets this, and it is deliberately harsh: an
    unknown is not a pass. The five results stay visible either way.
    """
    failing = {
        "KEY_UNTRUSTED", "EXPECTED_KEY_MISMATCH", "HASH_LINK_MISMATCH",
        "SEQUENCE_GAP", "SIGNATURE_INVALID", "TRUNCATED_RECORD",
        "NONCANONICAL_BYTES", "CONTEXT_MISMATCH", "UNVERIFIED_TAIL",
        "HISTORY_EXTENT_UNKNOWN", "EXPECTED_CHECKPOINT_MISSING",
        "CHECKPOINT_MISMATCH", "MISSING_GENESIS", "SEGMENT_MISSING",
        "LIFECYCLE_ORPHAN", "LIFECYCLE_DUPLICATE", "LEGACY_UNSIGNED",
        "UNKNOWN_EVENT",
    }
    for kind in RESULT_KINDS:
        if results.get(kind) in failing:
            return 1
    return 0
