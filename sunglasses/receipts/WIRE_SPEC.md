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
- no lone surrogates (U+D800 to U+DFFF) in strings or keys; UTF-8 cannot
  carry one, so a record holding one has no bytes to sign and is refused
- bounded: strings 4096, integers signed 64 bit, arrays 256, object keys 64,
  nesting 8, and one whole line at most 16 KiB (16384 bytes) with its LF
  (`wire.MAX_LINE`). Values inside every other bound can still add up past
  it, and the writer refuses such a line before anything is written
- unknown types are **refused, never converted**. A value needing a conversion
  was never the value the producer meant to commit
- **text a peer chose is replaced before the wire, never refused (T9 ruling
  43).** The refusals above stay the wire's own rule. A producer writing a
  string it did not choose (the proxy writes a server's name, the methods it
  advertises, a reason it gave) replaces first, so a refusal is never a
  switch a peer can flip. Each control character (U+0000 to U+001F and
  U+007F) becomes its JSON escape as six characters of text, `\u` and four
  lowercase hex digits, so a newline can never split a record in two. Each
  lone surrogate becomes U+FFFD. The same input always gives the same
  output, and the record says how many were replaced in `sanitized`, keyed
  by field (proxy/receipts.py:103-126)
- **a peer's object is one string, never an object in the row (T9 ruling
  44).** Replacing inside an object's keys could make two keys one: `"a\u0000"`
  (a real NUL) escapes to exactly the six characters of the key
  `"a\\u0000"`. So a value that is an object, or a list holding one at any
  depth, is written as ONE string, its canonical JSON: keys sorted, every
  character outside printable ASCII as a `\u` escape, no spaces. That is
  lossless, so two keys stay two, and nothing is replaced or counted in
  `sanitized`. Over the field's 72 bytes it is written as the sha256 of that
  string, 64 lowercase hex, and `digested` maps the field to the string's
  length (proxy/receipts.py:128-146, 407-419)

## The four domain prefixes

Frozen. Changing one is a new format version, never an edit: every previously
signed checkpoint verifies under the domain it was signed with, and a silent
change makes old history look forged.

| purpose | bytes |
|---|---|
| record chain hash | `sunglasses-receipt-chain/1\x00record\x00` |
| checkpoint signature | `sunglasses-receipt-chain/1\x00checkpoint\x00` |
| key fingerprint | `sunglasses-receipt-key/1\x00ed25519\x00` |
| hook log marker signature (T9 ruling 60) | `sunglasses-receipt-chain/1\x00marker\x00` |

Separate domains mean the same bytes can never be presented as the other kind.

## Hashing and signing

- **chain hash** = SHA-256 of the record domain prefix plus the full canonical
  line **including its LF**. The framing is inside the hash, so a reframed
  stream cannot hash the same.
- **checkpoint signature** = Ed25519 over the checkpoint domain prefix plus the
  checkpoint's canonical record with **only its `signature` member omitted**,
  followed by one LF. Without omitting it the signature would cover itself.
- **marker signature** = Ed25519 over the marker domain prefix plus the hook
  log marker's canonical record with **only its `signature` member omitted**,
  followed by one LF (T9 ruling 60).
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
positive interval, an integer of at least 1, is bound **in the signed
header**. Under the append lock, the
checkpoint at 100 is required before record 101 is admitted.

A crash can leave up to 100 pending records under this healthy-writer policy.
That is **neither a time bound nor an adversarial rollback bound**, and the
documentation may not present it as either.

Records visible after the last verified checkpoint report `UNVERIFIED_TAIL`
with counts and file:line boundaries. An existing unsigned suffix is **never
automatically signed on restart** merely because its hashes are consistent; it
could have been rewritten while the writer was down.

A last line without its terminating LF is a torn write, reported as
`TRUNCATED_RECORD` (`verify.py:225`), never read as a shorter record.

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

None of this section is built yet. Today the verifier knows one key per log;
a segment whose genesis names another key reports `ROTATION_UNSUPPORTED`
instead of guessing whether a successor was meant.

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

## Exit codes (T9 rulings 46 and 48)

Every reason code is exactly one of three classes, and a verifier's exit code
comes from the class, never from a list kept somewhere else.

LIMIT = verifier could not conclude because the CALLER did not supply something (fingerprint, endpoint, key, session, log) or the feature is specified-not-built (R40), log bytes consistent with clean. FAIL = the log's bytes contradict or lack what they must carry. Every limit exits non-zero.

- **ok**: the result holds. `KEY_TRUSTED`, `CHAIN_OK`, `NO_VISIBLE_TAIL`,
  `ENDPOINT_CONFIRMED` and `LIFECYCLE_COMPLETE`.
- **limit**: `KEY_UNTRUSTED`, `HISTORY_EXTENT_UNKNOWN`, `PAIRING_UNKEYED`,
  `EMPTY_CHAIN`, `NO_SESSION`, `ROTATION_UNSUPPORTED`, `NO_LOG` and
  `LOG_UNCHAINED` (T9 ruling 60). A limit is neither a pass nor a failure, and
  it is never a pass.
- **fail**: every other code, including `UNKNOWN_FIELD` (T9 ruling 44),
  `KEY_UNUSABLE`, `LEGACY_UNSIGNED`, `PATH_UNREADABLE` (T9 ruling 57),
  `LOG_MISSING` (T9 ruling 60) and the rotation codes a verifier does not emit
  yet.

The exit, over every result of every log verified:

| exit | when |
|---|---|
| 0 | every result is ok |
| 1 | at least one result is a failure |
| 2 | a usage error: the command line itself was wrong |
| 3 | no failure, and at least one limit |

`--strict` counts a limit as a failure, so a strict run exits 0 or 1 only. A
failure in one log is never hidden by a limit in another: across logs, 1 wins
over 3. A result that is not a known code exits 1, and a new code with no
class fails the enumeration test in CI before it can ship.

`--verify` with nothing on disk to verify prints `NO_LOG` and exits 3 (1 under
`--strict`), with the hint to run `sunglasses init` (T9 ruling 53). Without
`--verify` the same empty listing exits 0, because a listing is not a verdict.

A path the verifier must list that is there and cannot be listed (a directory
it may not read, or a file or symlink where a directory should be) prints
`PATH_UNREADABLE` with the path and the OS cause and exits 1, with or without
`--strict` (T9 ruling 57). It is never `NO_LOG`: something is on disk, so
"nothing to verify" would be false. Only a path with no directory entry at all
is absent.

Which entries are logs: under the home's `receipts/` the hook's log is `hook`,
and under the proxy's default `receipts/` a run's log is its run id, 32
lowercase hex (`[0-9a-f]{32}`, the whole name), the rule the writer names it
with (T9 ruling 58). A run written by a proxy started with `--state-root PATH`
is not read by `--verify` unless it is named with `--log PATH`.
An entry with a known name that the verifier cannot
list (a file, a dangling symlink, a symlink to a file, a directory it may not
read) is `PATH_UNREADABLE`, never passed over. Any other directory is read as a
log when it holds segments, and one the verifier cannot list is
`PATH_UNREADABLE` too. A known name that is a listable directory with no
segments is passed over without a warning, as before. A `--log PATH` the
verifier cannot list is `PATH_UNREADABLE`; no name rule applies to it. Any
other entry that is not a directory is not a log and is passed over.

A log with no chain (T9 ruling 60). A proxy run in a home with no key writes
its rows to `<run id>.jsonl` under the proxy's `receipts/`, and a hook that
predates signing writes day files under the home's `receipts/`. `--verify`
names each one `LOG_UNCHAINED`, a limit, so exit 3 and 1 under `--strict`,
joined to the day files' lifecycle verdict. The walk found these logs and
nothing says they should have been signed. The claim decides the exit, so a
log the caller supplies with `--log` that carries no chain is a failure. Plain
`receipts` names a run's `.jsonl` too, and stays exit 0.

The hook log's marker (T9 ruling 60). At the hook chain's first genesis the
writer creates `keys/log-hook.genesis` with `O_EXCL`. It holds one canonical
line with exactly the members `chain_id`, `event` (`log_genesis`), `key_id`,
`log` (`hook`), `signature`, `t_wall_ns` and `wire`, naming that chain and the
time its genesis carries, signed under the marker domain. `receipts init`
never writes it. A marker already there is never replaced and never deleted,
and it is never an error for the writer. Under `--verify` a marker whose chain
opens no segment of `receipts/hook` is `LOG_MISSING`, a failure in both modes,
because the log was begun and is gone or was wiped and begun again. A marker
that cannot be read is `PATH_UNREADABLE`. One that is not canonical, carries
another member, names another log or does not verify under its key is a
failure naming why, and never `LOG_MISSING`. With no marker, a hook log with
no segments stays `NO_LOG`. The marker belongs to its chain, and rotation,
when built, retires it with the chain. Proxy runs carry no marker until
0.6.2, so an emptied run directory is passed over as stated above.

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

The file carries one signed marker (`records.marker`) beside the genesis, the
event and the checkpoint. Its line verifies under the marker domain and under
no other, and a home holding only that line and the vector key reads
`LOG_MISSING` under `--verify`, because the chain it names is not there.

## Record fields

Read from the writer at this head, not designed here. Every row cites the
lines that write it, relative to `sunglasses/receipts/`, and
`test_the_spec_names_every_field_the_writer_writes` parses the three tables
below, compares them with every record a real writer produced, and checks that
each cited line names its field. A table that drifts from the writer fails in
the commit that moved it.

A segment is one file, `segment-NNNNNN.chain` (six digits, from 000001),
created 0600 with `O_EXCL` in a 0700 directory beside a `LOCK` file that every
write holds with `flock(LOCK_EX)` (chain.py:187, :210, :283-286). Its first
line is a genesis and its second a checkpoint with purpose `genesis`
(chain.py:209).

### genesis

| field | value | where |
|---|---|---|
| `wire` | `sg-receipt-chain/1` | chain.py:201 |
| `chain_id` | 32 lowercase hex, fresh per segment (`secrets.token_hex(16)`) | chain.py:188, :201 |
| `key_id` | the signing key's fingerprint | chain.py:202 |
| `seq` | `0` | chain.py:202 |
| `prev_hash` | `null`, the only null predecessor in a segment | chain.py:203 |
| `event` | `genesis` | chain.py:203 |
| `producer` | the writer's producer name; the callers pass `hook` or `proxy`, and a writer refuses a directory whose genesis names another (R15) | chain.py:204, :91-96 |
| `t_wall_ns` | integer, the writer's wall clock, not trusted time | chain.py:204 |
| `body` | `{}` for a log's first segment, else the predecessor object below | chain.py:189-205 |

A successor's genesis `body` carries `previous`, the `{chain_id, seq, hash}`
of the last checkpoint that verifies in the segment before it (`seq` and
`hash` are `null` when none does), and `observed_unsigned`, the count of
complete records seen after that checkpoint. When they apply it also carries
`observed_torn_bytes` (bytes after the last LF) and `observed_undecodable:
true` (chain.py:190-198). These are observations and never a vouch: the
successor signs nothing that came after that checkpoint.

### event

| field | value | where |
|---|---|---|
| `wire` | `sg-receipt-chain/1` | chain.py:255 |
| `chain_id` | the segment's | chain.py:255 |
| `key_id` | the signing key's fingerprint | chain.py:256 |
| `seq` | previous `seq` + 1 | chain.py:256 |
| `prev_hash` | the chain hash of the previous line | chain.py:257 |
| `event` | the producer's event name, never `genesis` or `checkpoint` | chain.py:257, :223 |
| `producer` | as in the genesis | chain.py:258 |
| `t_wall_ns` | integer, the writer's wall clock | chain.py:258 |
| `body` | an object: the producer's allowed fields (see Redaction) | chain.py:259 |
| `t_mono_ns` | integer, optional: the producer's monotonic clock (the proxy sets it) | chain.py:260-261 |

A producer supplies only `event`, `body` and `t_mono_ns`. Any other field is
refused before anything is written, so the envelope is always the writer's
(chain.py:43, :219-222).

### checkpoint

| field | value | where |
|---|---|---|
| `chain_id` | the segment's | chain.py:246 |
| `covered_head` | equal to `prev_hash`: the head this signature commits to | chain.py:246 |
| `covered_seq` | `seq` - 1 | chain.py:247 |
| `event` | `checkpoint` | chain.py:247 |
| `interval` | the writer's interval, an integer of at least 1, so the cadence is inside the signed bytes | chain.py:248, :67 |
| `key_id` | the signing key's fingerprint | chain.py:248 |
| `prev_hash` | the chain hash of the previous line | chain.py:249 |
| `purpose` | `genesis`, `interval`, `close`, or a producer's seal name | chain.py:249, :263-266 |
| `seq` | previous `seq` + 1 | chain.py:249 |
| `wire` | `sg-receipt-chain/1` | chain.py:250 |
| `signature` | 128 lowercase hex: Ed25519 as in Hashing and signing | chain.py:251-252 |

A checkpoint has no `producer`, `t_wall_ns` or `body`. An `interval`
checkpoint is written once `interval` records are unsigned (chain.py:263-264).
A `genesis` or `close` seal is written even over nothing, and any other
purpose only over at least one unsigned record (chain.py:265-266).

### The vocabulary a verifier judges

Lifecycle is judged over the verified prefix by the producer's vocabulary,
frozen in verify.py:44-64 because the verifier imports nothing from the
product.

- hook: `in_flight` opens and `decision` closes, paired by `body.eval_id`;
  `receipts_off` is known and pairs with nothing (verify.py:44-49).
- proxy: the session, `HEADER` then `SESSION_TORN_DOWN` or `TEARDOWN`; items
  are not paired (see A proxy chain's lifecycle, R24) (verify.py:56-64).
- anything else is `UNKNOWN_EVENT` under lifecycle and never an integrity
  failure.
- nothing verified at all (no genesis, the wrong key, no checkpoint) is
  `EMPTY_CHAIN` (T9 ruling 41): printed by name, never `LIFECYCLE_COMPLETE`
  and never a lifecycle failure, since the integrity result already says why
  nothing verified. A genesis and its checkpoint alone are verified, so a
  chain that started and recorded nothing stays `LIFECYCLE_COMPLETE`
  (vectors 2c, 5c and 8b against 6, 6b and the hook's 6c).
- a proxy genesis with no `HEADER` is `NO_SESSION` (T9 ruling 43): the proxy
  opens a session with `HEADER`, so none was opened. Not `LIFECYCLE_ORPHAN`,
  since nothing opened, and not `LIFECYCLE_COMPLETE`; neither a pass nor a
  failure (vector 6d).
- a key outside the closed schema for its record kind is `UNKNOWN_FIELD`
  (T9 ruling 44), a failure and never a limit: a signed row's keys are the
  writer's, so an extra one says something no honest writer can say. The
  kinds are the checkpoint, the envelope of every other record, the genesis
  body, and the body of a proxy or a hook record, each held in verify.py
  as a copy of its writer's set (verify.py:66-111, 280-281, 307-328).
  Inside a proxy body no field holds an object; `leaf_provenance` entries
  and the markers have their own keys. A body whose chain names no producer
  is a test vector's and is not judged, though its envelope is. Judged over
  the verified prefix like the rest, and before the producer's own rules
  (vectors 19 and 19b).

## Redaction: what is never signed

What the code does at this head, not a design. A signed byte is permanent: there
is no redaction after signing, because an edited record breaks the hash link
after it and a re-signed one is a different history. The one way to erase is
to delete a whole segment, and the verifier then reports the gap (a successor
names a checkpoint that is not there). So everything below happens BEFORE the
writer sees a body. Paths are relative to `sunglasses/`.

Each producer builds its own body from an allowlist. The writer adds only the
envelope (see Record fields) and refuses any other top level field.

**The hook** (`receipts/hook_rows.py`, called from firewall.py:1742 and :1749)

- An allowlist with a grammar per field (hook_rows.py:64-83). `in_flight`
  carries `eval_id` (16 hex), `tool_name`, `session_id` (printable, at most 256
  characters) and `input_sha256` (64 hex or null). `decision` adds `decision`,
  `lane`, `rule_id` (`GLS-` grammar), the flags `degraded`, `fuzzy_lane` and
  `pin_state_stale` (carried only when true), and `policy_state`, `pin_source`,
  `pin_reach` and `pin_checked_at` as fixed tokens.
- Converted once, here: `elapsed_ms` becomes the integer `elapsed_us` and
  `pin_state_age_s` is floored to an integer (hook_rows.py:96, :104);
  `cleared_canaries` keeps only each entry's `rule_id` and `fingerprint`
  (hook_rows.py:153).
- The error's CLASS NAME only. `error` never reaches a body, because an
  exception message may quote the value that raised it; the caller passes
  `error_types`, class names of at most 64 characters, at most 64 of them
  (hook_rows.py:40, :118). Measured by
  `test_a_chained_error_carries_its_class_name_never_its_message` in
  tests/test_receipts_hook_chain.py.
- A field that is not named, or whose value fails its grammar, is withheld and
  its name listed sorted in `withheld`; a name that is not a plain field name
  is only counted in `withheld_unnamed` (hook_rows.py:123, :147-149). Less
  evidence, said out loud.
- An input that has no digest carries `input_sha256` null and `input_digest`
  set to `"UNENCODABLE"` (hook_rows.py:145).
- Before any of this, `tool_name`, `session_id`, `error` and `rule_id` pass
  through `sanitize_receipt_field`: control, DEL, C1 and bidi characters are
  stripped and the value is cut to 128 characters (firewall.py:1597-1636).

With a key the chain is the hook's log and no unsigned JSONL line is written.
Without a key the unsigned JSONL receipt keeps its sanitized error message; it
is not a chain and this spec does not cover it.

**The proxy** (`proxy/receipts.py`)

- The never list, as field names: `payload`, `matched_text`, `stderr`,
  `stdout`, `exception`, `detail`, `pointer`, `raw_id`, `key`, `text`,
  `content`, `body` (proxy/receipts.py:59-62). Any field outside
  `PERMITTED_FIELDS` (proxy/receipts.py:64-82) is dropped without a note.
- The values of `reason_code`, `status`, `method`, `rule_ids`, `id_token` and
  `rule` are checked against the proxy's own catalog or grammar, and a value
  outside is refused, never trimmed (proxy/receipts.py:191-241). The whole
  value is checked before any cut, so a bad entry cannot hide past a bound.
- `leaf_provenance` keeps index, depth, byte count and the value's digest; the
  JSON pointer is hashed to `pointer_sha256`, never carried (proxy/receipts.py:
  438-453). No caller writes it at this head.
- **A row fits its line by construction (T9 ruling 41).** A long value is cut
  and the cut is counted, never refused, because the values come from matches
  on what a peer sent and a refusal would stop the audit for the rest of the
  session (proxy/receipts.py:84-188, 387-436):
  - `rule_ids` keeps the first 256 in the order the engine gave, and the
    kept ids, each encoded with its quotes, total at most 6 KiB; whichever
    cuts first (T9 ruling 43). `rule_ids_omitted` counts every id left out,
    for either reason, in one number. Real catalog ids are at most 21
    characters, so 256 of them are kept whole.
  - `leaf_provenance` keeps the first 8 entries; the rest are counted in
    `leaf_provenance_omitted`.
  - a field holding an object is its canonical JSON or that string's
    digest, as the canonicalisation section says, counted in `digested`.
  - every other field is first replaced as the canonicalisation section
    says, counted in `sanitized`, and then keeps at most 72 bytes once
    encoded. Text keeps its longest prefix that fits; a longer list is
    written as `null`. Either way `truncated` maps the field to the length
    it had when it was cut.
  - the five markers are derived by the writer and are not permitted input,
    so a caller cannot claim a cut or a repair that did not happen.
- The chained body is the same cleaned fields, plus the proxy's `t_mono_ns`
  (proxy/receipts.py:363-385). The 16 KiB line check stays as the invariant,
  and a test feeds every permitted field at its worst to show nothing reaches
  it. If it ever fires, the bounds above are wrong: like any other failure to
  append, it stops the session as a receipt failure (R4), the refusal is kept
  so every later row is refused too, and the message names the cause.

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

## A proxy chain's lifecycle is the session (T9 ruling 24)

Stated 2026-09-24 for this round, in its own commit, so the limit is on the
record before a verifier prints it.

- **The lifecycle checked is the session.** A proxy chain opens with `HEADER`
  and ends with `SESSION_TORN_DOWN` or `TEARDOWN`. A chain with no terminal is
  `LIFECYCLE_ORPHAN`. That is all this round judges.
- **Items are recorded, not paired.** `ADMITTED`, `SETTLED` and
  `FORWARD_SUPPRESSED` rows are written and signed like any other, but most
  `SETTLED` rows carry no key to pair an `ADMITTED` by, and pairing them
  anyway would let one keyless `SETTLED` settle every keyless `ADMITTED`. So
  the verifier pairs nothing and says so: a session that ended prints
  **`PAIRING_UNKEYED`**, which is neither a pass nor a failure (a limit:
  exit 3, and 1 under `--strict`), and never `LIFECYCLE_COMPLETE`, because that code says every opening
  has its terminal and nobody checked.
- **The target is unchanged, and not yet judged.** Freeze vector 15, "proxy
  `ADMITTED` without `SETTLED` → lifecycle failure; `FORWARD_SUPPRESSED` +
  `SETTLED REQUEST_CANCELLED` → lifecycle ok", stays the requirement. It is
  **not judged until R24-A lands**: its own change after this round, where
  each obligation carries one key (`record_key` + direction, T9 ruling 25,
  never the raw JSON-RPC id) and the verifier pairs by it.

## What is built here, and what is not

Built in this directory: the encoding, the hashes, the signature construction
and the fingerprint (`wire.py`); the reason codes (`codes.py`); the signing key,
created only by `sunglasses receipts init` (`keys.py`); the writer with its
per-chain lock, sequence, checkpoint cadence and segment rotation by size
(`chain.py`); opting in and out (`optin.py`); the verifier for one segment and
for a whole log, with its rendering (`verify.py`); the hook's row allowlist
(`hook_rows.py`); and the vectors (`make_vectors.py`, `VECTORS.json`). Outside
it, the firewall hook and the proxy each write a chain signed with the home's
key, and `sunglasses receipts --verify` checks both.

**Specified and not built, so not claimed:**

- Key rotation and epochs. `SUCCESSOR_ASSERTED` and `SUCCESSOR_ENDORSED` are
  defined above and nothing emits them. A segment signed by a key other than
  the one being verified reports `ROTATION_UNSUPPORTED`, the way an unkeyed
  proxy pair reports `PAIRING_UNKEYED`. Freeze vector 12 is a strict expected
  failure until rotation is built.
- The standalone offline bundle. The verifier is the one in this package.
- A streaming verifier. The verifier reads one whole segment into memory, and
  a segment is at most 256 MiB (`chain.py:63`).
- An upper bound on the checkpoint interval. The writer refuses an interval
  that is not a positive integer (`chain.py:67`) and accepts any larger one.
- Concurrency between hook and proxy beyond their separate chains, and the
  durable release gate. ASTRA's acceptance groups remain requirements until a
  review says otherwise.

## Not in the released artifact

`sunglasses/receipts/` deliberately has **no `__init__.py`**, so `find_packages()`
does not collect it and none of this reaches the wheel. Verified, not assumed:

    python3 -c "from setuptools import find_packages; \
      print(any('receipts' in p for p in find_packages()))"   # False

Adding an `__init__.py` ships it. That should happen in the commit that also
ships the writer, the verifier and their acceptance evidence, never before.
