# Gauntlet corpus

`pool/` grows continuously. Every case is provenance-stamped **at capture**, not at
scoring — the stamp records where it came from and, once a pattern is authored from
it, which pattern. A case whose stamp is missing `tuned_from_pattern_ids` is REFUSED
by `freeze`, never defaulted to "not tuned-from": defaulting the permissive way is
how a held-out set quietly turns back into an answer key.

`frozen/<release>/` is the scoring set for that release. Immutable once written.

`tuned_from/` holds cases a pattern was authored FROM. They are never scored — a
number measured against the cases your rules were written from measures your memory,
not your defenses.
