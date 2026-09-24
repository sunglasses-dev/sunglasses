# Signed receipts, wire specification `sg-receipt-chain/1`

Frozen bytes for the receipt chain. Written against ASTRA's design verdict of
2026-09-14, which is a **DESIGN GO WITH EDITS** and certifies no implementation
and approves no release.

ASTRA's ordering rule is why this document exists before any writer:

> Publish exact byte vectors for hashes, signatures and fingerprint derivation
> before implementing both writer and verifier.

A writer and a verifier built from prose agree until the day they disagree, and
that day arrives as an auditor being told their honest log is broken.

## What a valid chain proves, and what it does not

The protected object is **the recorded prefix and its order**. Not the truth of
any event.

A verifier prints this sentence with real boundaries substituted, and it is a
frozen constant in `codes.py` so it cannot soften over time:

> The checkpoint signature is valid under key [fingerprint]. The supplied
> records from [start] through [checkpoint sequence/hash], including their
> order, match the prefix committed by that signature. This does not prove who
> originally wrote the records, that a scanner or tool ran, that the recorded
> time or decision is true, or that the hook was installed. It does not
> establish that no later records existed.

There is **no overall "clean audit trail" label** anywhere in this package, and
no single boolean that yields one. Five results print separately: key trust,
chain integrity, unsigned tail, expected endpoint, lifecycle. That friction is
the point, because a single green word is what a stranger quotes.

Three limitations are stated, never "fixed" by rejecting valid logs:

- **LC01** a key holder can fabricate and correctly sign false events.
- **LC02** an earlier valid checkpoint with no independently retained later
  endpoint is indistinguishable from a history that genuinely stopped there.
- **LC03** an action taken outside logging is not observed at all.

Claims that may **not** be made: chain-only integrity, execution, trusted time,
or that the latest visible history is automatically the whole history.

## The canonical encoding

One record has exactly one byte sequence. `decode_strict` parses, re-encodes
and demands byte equality; it never normalizes. Normalizing altered evidence
before checking it is checking your own rewrite.

- sorted keys, compact separators `,` and `:`, UTF-8, no `NaN` or `Infinity`
- exactly **one LF**, at the end of the record and nowhere else
- **no floats.** A float has more than one shortest representation across
  implementations and a NaN is not equal to itself. Durations and counts are
  integers
- no duplicate keys; two parsers can disagree about which value wins, which is
  the whole attack
- no control characters in strings; diagnostics are displayed separately and
  never inside signed bytes
- bounded: strings 4096, integers signed 64 bit, arrays 256, object keys 64,
  nesting 8
- unknown types are **refused, never converted**. A value needing a conversion
  was never the value the producer meant to commit

## The three domain prefixes

Frozen. Changing one is a new format version, never an edit: every previously
signed checkpoint verifies under the domain it was signed with, and a silent
change makes old history look forged.

| purpose | bytes |
|---|---|
| record chain hash | `sunglasses-receipt-chain/1\x00record\x00` |
| checkpoint signature | `sunglasses-receipt-chain/1\x00checkpoint\x00` |
| key fingerprint | `sunglasses-receipt-key/1\x00ed25519\x00` |

Separate domains mean the same bytes can never be presented as the other kind.

## Hashing and signing

- **chain hash** = SHA-256 of the record domain prefix plus the full canonical
  line **including its LF**. The framing is inside the hash, so a reframed
  stream cannot hash the same.
- **checkpoint signature** = Ed25519 over the checkpoint domain prefix plus the
  checkpoint's canonical record with **only its `signature` member omitted**,
  followed by one LF. Without omitting it the signature would cover itself.
- **predecessor** covers checkpoint signatures too. The completed signed
  checkpoint becomes the next predecessor.
- **covered head** is the previous record's hash.
- genesis is sequence 0 and holds the sole null predecessor. Every later
  record, checkpoints included, increments by exactly 1.
- algorithms are **fixed, not negotiated**. A file that names its own algorithm
  lets an attacker pick the weakest one a verifier still supports.

## Key fingerprint

SHA-256 over the fingerprint domain and the **raw 32 public key bytes**. The
algorithm identifier is inside the domain, so two keys of different algorithms
can never share a fingerprint and a fingerprint cannot be reinterpreted under a
different algorithm later.

The adjacent public key gives **portability, not trust**. A stranger obtains
the expected fingerprint independently, or verification reports `KEY_UNTRUSTED`:
valid under this supplied key, ownership unknown.

## Checkpoint cadence, and the honest bound

Sign at creation, every **100 non-checkpoint records** by default, each observed
session close, segment closure, export and key transition. The configured
positive interval is bound **in the signed header**. Under the append lock, the
checkpoint at 100 is required before record 101 is admitted.

A crash can leave up to 100 pending records under this healthy-writer policy.
That is **neither a time bound nor an adversarial rollback bound**, and the
documentation may not present it as either.

Records visible after the last verified checkpoint report `UNVERIFIED_TAIL`
with counts and file:line boundaries. An existing unsigned suffix is **never
automatically signed on restart** merely because its hashes are consistent; it
could have been rewritten while the writer was down.

## The endpoint, and the code most likely to be quoted wrongly

Without an independently retained expected endpoint, verification reports
`HISTORY_EXTENT_UNKNOWN` — **even at a valid checkpoint with no visible tail.**

That is not pedantry. An attacker without the key who deletes the newest
checkpoint and everything after an earlier valid one leaves exactly the picture
of a log that genuinely stopped earlier. Deleting every unsigned tail record
leaves **zero** visible tail records, not evidence of how many were removed. A
verifier must never invent a deleted count.

A reference supplied alongside an attacker-controlled log establishes nothing.
A previously retained auditor copy, transferred independently, establishes a
known boundary while verification stays offline. Activity after that boundary is
outside the completeness claim.

## Key loss and rotation

Loss of the **private** key does not invalidate old signatures. Preserve public
keys, exact log bytes, format and algorithm information, and the verifier.

A new key starts a new epoch whose signed genesis checkpoint names the old
fingerprint, chain ID and last verified checkpoint. That cross-reference means
"this signer points at that old history": `SUCCESSOR_ASSERTED`, not
authorisation by the old key and not proof of the same owner. For planned
rotation with the old key available, the old key also signs the successor
binding, which loss cannot manufacture: `SUCCESSOR_ENDORSED`.

Old public keys are never overwritten. This is **not** forward-secure signing.

## Offline verification

Independent offline verification is mandatory; "stdlib only" was not achievable
and is not claimed. Python's standard library exposes hashing, HMAC and
randomness, not an Ed25519 verification API, and HMAC would let an auditor
forge. So: a standalone verifier with **no `sunglasses` import**, a maintained
Ed25519 implementation (PyCA), pinned and installable from a supplied local
bundle, running with networking disabled.

**Offline does not mean dependency-free**, and the prerequisites are stated
rather than implied. RFC 8032's sample implementation is illustrative and is
not copied into production to satisfy a slogan.

The offline claim is withheld until the standalone bundle is demonstrated
offline.

## The vectors

`VECTORS.json` is generated by `make_vectors.py` from `wire.py`, never typed, so
the specification and the code cannot drift. The signing seed in it is a
**published test value**, never a real key, and exists precisely to be copied by
an independent implementation.

    python3 make_vectors.py > VECTORS.json
    python3 -m pytest tests -q

A committed vector file that regenerates differently fails `test_the_vectors_
are_pinned` in the same commit, rather than six weeks later when an auditor's
verifier disagrees with ours.

## Chains and writers: one chain per log (T9 ruling 15)

Amended 2026-09-24, before any receipt byte exists, so no epoch is needed.

- **One chain per LOG.** The hook and each proxy log write separate chains, each
  in its own directory with its own append lock and its own sequence. There is
  no global sequence. A single chain shared by a per-call hook process and a
  long-lived proxy would share one unsigned suffix, and a writer may never sign
  a suffix it did not write.
- **The hook seals each call.** Each hook invocation writes its rows, then a
  `close` checkpoint over them, signed before the process exits. A call that
  finds the tail sealed continues the segment; one that finds an unsigned tail
  (a call that died) opens a new segment whose genesis names it.
- **Sealed means verified (ruling 15b).** A tail counts as sealed only when its
  last checkpoint is this segment's, names this writer's key, and its signature
  verifies under that key. A forged, garbled or foreign seal is just bytes: it
  is counted as unsigned, the segment is closed untouched, and the new genesis
  names the last checkpoint that does verify. Cost: one signature verification
  per write.
- **Durability** is `os.fsync` of the file and the directory for both producers,
  one statement for both. `F_FULLFSYNC` is not used.
- **The verifier reports per chain**: five results for each chain. Matching a
  hook call to a proxy item across chains is a **lifecycle** result only. A
  partner missing from another chain never changes either chain's integrity.

## What is built here, and what is not

Built: the encoding, the hashes, the signature construction, the fingerprint,
the reason codes, the vectors, and 24 controls, every one a mutation with a
positive control beside it so a checker that refuses everything cannot pass.

**Not built and not claimed:** the writer, the store, the per-chain append lock and
sequence, rotation, epochs, the CLI, the offline bundle, concurrency between
hook and proxy, and the durable release gate. ASTRA's 20 acceptance groups and 3
limitation controls are future requirements, not results. This file proves the
bytes and nothing about a system that does not exist yet.

## Not in the released artifact

`sunglasses/receipts/` deliberately has **no `__init__.py`**, so `find_packages()`
does not collect it and none of this reaches the wheel. Verified, not assumed:

    python3 -c "from setuptools import find_packages; \
      print(any('receipts' in p for p in find_packages()))"   # False

Adding an `__init__.py` ships it. That should happen in the commit that also
ships the writer, the verifier and their acceptance evidence, never before.
