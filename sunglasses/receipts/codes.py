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
    "ROTATION_UNSUPPORTED":
        "a later segment is signed by another key: a key transition. Rotation "
        "is specified (WIRE_SPEC, key loss and rotation) and not built, so "
        "that segment and everything after it is not judged (T9 ruling R40). "
        "Not a pass.",

    # lifecycle
    "EMPTY_CHAIN":
        "no record was verified, so there is no lifecycle to judge (T9 ruling "
        "R41). Not a pass and not a failure; the integrity result says why "
        "nothing verified.",
    "NO_SESSION":
        "a proxy segment with its genesis and no HEADER: no session was "
        "opened, so there is none to judge (T9 ruling R43). Not an orphan, "
        "since nothing opened, and not complete. Not a pass and not a failure.",
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
    "UNKNOWN_FIELD":
        "a signed record carries a key outside the closed schema for its "
        "record kind (T9 ruling R44). A signed row's keys are the writer's, "
        "fixed by the schema, so an extra one is a failure, never a limit; "
        "chain integrity is unaffected.",
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


# Every code is exactly one of three classes, and the exit code comes from the
# class (T9 rulings R46, R48). OK is a result that holds. LIMIT is a verifier
# that could not conclude because the caller did not supply something
# (fingerprint, endpoint, key, session) or the feature is specified and not
# built (R40), with log bytes consistent with clean. FAIL is a log whose bytes
# contradict or lack what they must carry. Every limit exits non-zero.
OK, FAIL, LIMIT = "ok", "fail", "limit"

# 2 is the CLI's usage exit (argparse and a malformed argument), so a limit is 3.
EXIT_OK, EXIT_FAIL, EXIT_USAGE, EXIT_LIMIT = 0, 1, 2, 3

_OK_CODES = {"KEY_TRUSTED", "CHAIN_OK", "NO_VISIBLE_TAIL", "ENDPOINT_CONFIRMED",
             "LIFECYCLE_COMPLETE"}
_LIMIT_CODES = {"PAIRING_UNKEYED", "EMPTY_CHAIN", "NO_SESSION",
                "ROTATION_UNSUPPORTED", "KEY_UNTRUSTED", "HISTORY_EXTENT_UNKNOWN"}
_FAIL_CODES = {"CHECKPOINT_MISMATCH", "CONTEXT_MISMATCH",
               "EXPECTED_CHECKPOINT_MISSING", "EXPECTED_KEY_MISMATCH",
               "HASH_LINK_MISMATCH", "KEY_UNUSABLE", "LEGACY_UNSIGNED",
               "LIFECYCLE_DUPLICATE", "LIFECYCLE_ORPHAN", "MISSING_GENESIS",
               "NONCANONICAL_BYTES", "PREDECESSOR_UNAVAILABLE", "SEGMENT_MISSING",
               "SEQUENCE_GAP", "SIGNATURE_INVALID", "SUCCESSOR_ASSERTED",
               "SUCCESSOR_ENDORSED", "TRUNCATED_RECORD", "UNKNOWN_EVENT",
               "UNKNOWN_FIELD", "UNVERIFIED_TAIL"}


def _tag(**groups) -> dict:
    """The class table from the three named sets and nothing else. A code named
    in two sets gets both tags joined ("ok+fail"), which is no class at all, so
    untagged() reports it rather than one set silently winning."""
    table = {}
    for tag, members in groups.items():
        for code in members:
            table[code] = tag if code not in table else f"{table[code]}+{tag}"
    return table


# Built from the three sets only, never from CODES with a default: a code added
# to CODES and to no set has no class, and untagged() names it (T11 on R46).
CLASS = _tag(ok=_OK_CODES, limit=_LIMIT_CODES, fail=_FAIL_CODES)


def untagged(codes_map=None, class_map=None) -> list:
    """Every code whose class is missing or not one of the three, and every
    class entry for a code that does not exist. Empty means the table holds."""
    codes_map = CODES if codes_map is None else codes_map
    class_map = CLASS if class_map is None else class_map
    bad = [code for code in codes_map if class_map.get(code) not in (OK, FAIL, LIMIT)]
    return bad + [code for code in class_map if code not in codes_map]


def exit_code(results: dict, strict: bool = False) -> int:
    """0 when every result is ok, 1 when any is a failure, 3 when none fails
    and at least one is a limit. `strict` makes a limit exit 1.

    A result that is not a known code exits 1: a code nobody classed is a code
    nobody decided, so it cannot pass. The five results stay visible either
    way."""
    classes = [CLASS.get(results.get(kind), FAIL) for kind in RESULT_KINDS]
    if FAIL in classes:
        return EXIT_FAIL
    if LIMIT in classes:
        return EXIT_FAIL if strict else EXIT_LIMIT
    return EXIT_OK


def strict_exit_code(results: dict) -> int:
    """exit_code with every limit counted as a failure."""
    return exit_code(results, strict=True)


def combine_exits(exits) -> int:
    """One exit for several logs: any failure wins, then any limit. Not max(),
    which would let a limit (3) outrank a failure (1)."""
    exits = list(exits)
    if EXIT_FAIL in exits or any(e not in (EXIT_OK, EXIT_LIMIT) for e in exits):
        return EXIT_FAIL
    return EXIT_LIMIT if EXIT_LIMIT in exits else EXIT_OK
