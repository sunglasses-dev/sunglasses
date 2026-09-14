"""Which generation a variant belongs to.

The package holds two deliveries with genuinely different shapes: only 7 of
about 45 variant keys are shared. The second generation carries `routes`
plural including `no_mediation`, a `schedule_file` of operations rather than an
inline schedule, and a `payload_ref` into another seed's payload by hash.
`batch.run_one` can drive the first generation and nothing else.

So something has to decide which driver a variant goes to, and the one thing it
must not do is decide from the id. G2-01..G2-12 are first generation and
G2-13.. are second today, but that is a fact about one delivery; the next seed
can arrive numbered anywhere. It is decided from the keys the variant actually
carries, and a variant that does not clearly belong to either shape is refused
rather than defaulted, because defaulting it to the first generation would send
the whole second delivery to a driver that cannot express it and every row
would come back reading as a failure of the candidate.

Resolving `payload_ref` lives in `runner.resolve_payload_ref`, not here. One
resolver, one digest check.
"""
from __future__ import annotations

# The keys that only the second generation has. `routes` is the load-bearing
# one: the first generation has no route field at all and the harness derives
# proxy_strict and control from CONTROL_SEEDS.
GEN2_KEYS = frozenset({"routes", "schedule_file", "payload_ref", "profile",
                       "sequence", "observe_until", "calibration",
                       "actual_id_source", "mutation_must_reject"})

# The keys that only the first generation has. An inline `payload` is the
# opposite of a `payload_ref`, and an inline `schedule` the opposite of a
# `schedule_file`.
GEN1_KEYS = frozenset({"payload", "schedule", "route"})


class AmbiguousGeneration(Exception):
    """A variant carries the marks of both shapes, or of neither."""


def generation_of(variant: dict) -> int:
    """1 or 2, or a refusal naming what made it undecidable."""
    present = frozenset(variant)
    second = present & GEN2_KEYS
    first = present & GEN1_KEYS

    if second and first:
        raise AmbiguousGeneration(
            f"variant {variant.get('name')!r} carries second generation keys "
            f"{sorted(second)} and first generation keys {sorted(first)}. A "
            "half migrated variant would be driven by the second generation "
            "adapter, which resolves payload_ref, and would silently ignore "
            "what is written beside it."
        )
    if second:
        return 2
    return 1
