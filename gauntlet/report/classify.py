"""Whether a blocked variant could be unblocked by adapter work alone.

The question the ceiling answers, stated exactly (S7, E4): adapter-only
eligibility requires EVERY remaining capability a variant still needs to be
available on the identified real route, with no unresolved classification and
no invalid schedule. Anything short of that is not a `false`, it is a refusal.

Two failures this module exists to prevent, both of them already made once:

THE SHORT CIRCUIT. The first version checked classification inside the loop
that decides a variant's blocker, and that loop returned on the first blocker it
met, so an unclassified op sitting later in the same variant was never reached.
The refusal read green and the run exited 0. A validation pass that can be
skipped by the order of its inputs is not a validation pass. So classification
of EVERY op across EVERY blocked variant happens here, before any ceiling,
subtotal or category count exists, and the E10 control inserts an unknown op
both before and after a known blocker to prove the order does not matter.

THE UNFALSIFIABLE DERIVATION. The first ceiling was computed as "every blocked
variant needs a mediator capability OR names an unimplemented op", which every
blocked variant satisfies by definition. It was true by construction and could
never go false, which is worse than the stored boolean it replaced because it
looks measured. The split below can flip, and a test flips it.

CAPABILITY IS NOT THE OPCODE. `arm_fault` is decided by its kind against an
enumerated constant, `await_event` by event and actor. An entry says which
tuple decides it; an op whose deciding tuple is not evidenced is unclassified,
never bucketed to whichever answer keeps the run green.
"""
from __future__ import annotations

import dataclasses
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "boundary"))

from gen2 import adapter                                   # noqa: E402

MAP_PATH = pathlib.Path(__file__).with_name("capability_map.json")

ROUTE = "route_capability"
REVIEWED = "reviewed"          # the only review_state `load_map` accepts

# HOW AN ENTRY CAME TO BE BELIEVED. `basis` was free text, so a typo produced a
# bucket nobody could audit and nothing refused it.
#
# `executed_witness` was added by ruling (T9, 2026-09-22) as SCHEMA ONLY, on the
# grounds that nothing in `gauntlet/` executed a step. THAT IS NO LONGER TRUE
# and the comment outlived it by hours: `gen2/execute.py` has a `run()` that
# drives a variant through real pipes, and the first witness was taken the same
# day. There is one entry under this basis now.
#
# The comment is corrected rather than deleted because the reason it gave is the
# reason the fields below exist: a claim of a run that carries no record of one
# is refused rather than believed. Note what the first witness needed before it
# could be taken — the step it exercised could not hold on ANY run until the day
# it was recorded, because it compared a file against itself.
REVIEWED_RULING = "reviewed_ruling"
INSPECTED_SOURCE = "inspected_source"
EXECUTED_WITNESS = "executed_witness"
BASES = frozenset({REVIEWED_RULING, INSPECTED_SOURCE, EXECUTED_WITNESS})

# An executed witness must say WHICH run, WHERE the record is, and WHAT TREE it
# was driven against. The last one is not bookkeeping: a witness driven against
# `gauntlet/boundary/proxy` is adapter-against-harness evidence and is NOT proof
# about the real route, and an entry that does not say so will be read as the
# stronger claim by the next person.
WITNESS_FIELDS = ("run_id", "step_record", "driven_against")
ADAPTER_ONLY = "adapter_implementable"
BUCKETS = frozenset({ROUTE, ADAPTER_ONLY})


class MapInvalid(Exception):
    """The capability map is not usable as an input. Distinct from a refusal."""


@dataclasses.dataclass(frozen=True)
class Need:
    """One capability a variant STILL needs, at the granularity that decides it.

    "Still" is load-bearing. A blocked variant is full of operations the adapter
    drives perfectly well; they are not needs, and counting them as unclassified
    put `send_file` on a list of open route questions in the first run of this
    module. A need is what this adapter cannot do today.
    """
    op: str
    tuple_key: str          # what actually decided it, rendered for the reader
    value: str | None       # the kind or event that decided it, when one did
    variant: str


@dataclasses.dataclass(frozen=True)
class Classification:
    """The whole answer, including the part that says there is no answer."""
    buckets: dict           # tuple_key -> ROUTE | ADAPTER_ONLY
    unknown: dict           # tuple_key -> reason string
    uncovered: dict         # tuple_key -> ops the map does not mention at all

    @property
    def complete(self) -> bool:
        return not self.unknown and not self.uncovered


def load_map(path: pathlib.Path | None = None) -> dict:
    """The reviewed map, refused rather than defaulted if it is not one.

    A missing or malformed map is NOT an empty map. An empty map would classify
    nothing and, under a naive reading, leave no unknowns to refuse on.
    """
    path = path or MAP_PATH
    try:
        data = json.loads(path.read_text())
    except FileNotFoundError as exc:
        raise MapInvalid(f"no capability map at {path}") from exc
    except ValueError as exc:
        raise MapInvalid(f"capability map is not JSON: {exc}") from exc

    for key in ("map_version", "revision", "classified", "unclassified",
                "enumerated_values", "units"):
        if key not in data:
            raise MapInvalid(f"capability map is missing {key!r}")
    for op, entry in data["classified"].items():
        if entry.get("bucket") not in BUCKETS:
            raise MapInvalid(
                f"{op!r} carries bucket {entry.get('bucket')!r}; the only "
                f"buckets are {sorted(BUCKETS)}. An unrecognised bucket is not "
                "a third answer, it is a map defect.")
        basis = entry.get("basis")
        if basis not in BASES:
            raise MapInvalid(
                f"{op!r} carries basis {basis!r}; the only bases are "
                f"{sorted(BASES)}. A basis outside the enumeration is not a new "
                "kind of knowing, it is a typo nobody can audit.")
        if basis == EXECUTED_WITNESS:
            missing = [f for f in WITNESS_FIELDS if not entry.get(f)]
            if missing:
                raise MapInvalid(
                    f"{op!r} claims basis {EXECUTED_WITNESS!r} without "
                    f"{missing}. Claiming a run happened is not recording one: "
                    "say which run, where its step record is, and which tree it "
                    "was driven against.")
        if not entry.get("evidence"):
            raise MapInvalid(
                f"{op!r} is classified with no evidence. A bucket without a "
                "citation is an assertion, and this map exists to stop those.")
    # THE DOCSTRING'S PROMISE, NOW KEPT. This said "the reviewed map, refused
    # rather than defaulted if it is not one" and never read `review_state`.
    #
    # Measured 2026-09-22 before this existed: moving all six unclassified ops
    # into `classified`, with evidence text reading "PROBE ONLY -- deliberately
    # fabricated", flipped the report from REFUSED / exit 3 to COMPLETE /
    # exit 0 and computed a ceiling, while the page went on rendering
    # `capability_map_review_state: unreviewed` in a field nobody had to act on.
    # This report's whole subject is a true number under a false label, and its
    # own gate was doing it.
    #
    # The map is `authored_by: T10`. Without this, the author's own unreviewed
    # assertions publish a ceiling, which is self-review with a citation.
    # ABSENT IS NOT REVIEWED: a missing field must not read as consent.
    if data.get("review_state") != REVIEWED:
        raise MapInvalid(
            f"capability map review_state is {data.get('review_state')!r}, not "
            f"{REVIEWED!r}. A well-formed map that nobody reviewed is not a "
            "reviewed map, and every ceiling computed from one is an assertion "
            "wearing a citation.")

    overlap = set(data["classified"]) & set(data["unclassified"])
    if overlap:
        raise MapInvalid(
            f"{sorted(overlap)} are both classified and unclassified. One "
            "primary state per op; a duplicate lets a reader pick the kinder one.")
    return data


def needs_of(variant_id: str, steps: list[dict], capmap: dict,
             implemented: frozenset[str] | None = None) -> list[Need]:
    """Every capability this variant STILL needs, at deciding granularity.

    No short circuit and no early return: the whole step list is walked and the
    whole list of needs comes back, because the caller must classify all of them
    before it is allowed to conclude anything.

    `implemented` is injected rather than read, so a test can ask what the map
    would say about an adapter other than today's without editing the adapter.
    """
    if implemented is None:
        implemented = adapter.IMPLEMENTED
    units = capmap["units"]
    enumerated = capmap["enumerated_values"]
    needs: list[Need] = []
    for step in steps:
        op = step.get("op")
        unit = units.get(op, units.get("default", "opcode"))

        if unit == "opcode+event+actor":
            # The opcode IS implemented and the capability is still finer than
            # the opcode. Recognising the name is not recognising the call.
            event, actor = step.get("event"), step.get("actor", "proxy")
            available = enumerated.get(f"{op}.event", {}).get("available")
            if available is None or event not in available:
                needs.append(Need(op, f"{op}[event={event},actor={actor}]",
                                  event, variant_id))
            continue

        if unit == "opcode+kind":
            # ABOVE the implemented check, for the same reason the event branch
            # is: the unit is FINER THAN THE OPCODE, so "the adapter implements
            # arm_fault" does not answer "can it arm THIS kind".
            #
            # It was below, and nothing noticed until `arm_fault` was actually
            # implemented on 2026-09-22 — at which point every kind stopped
            # being asked about and `classify` returned an empty bucket set. The
            # C4 and C6 acceptance controls caught it in the same run, which is
            # what they are for: C4 wants a kind outside the cited enumeration
            # bucketed as real-route work, C6 wants a kind INSIDE it bucketed as
            # adapter work so the ceiling can go false. Neither can happen if
            # the opcode short-circuits first.
            kind = step.get("kind")
            needs.append(Need(op, f"{op}[kind={kind}]", kind, variant_id))
            continue

        if op in implemented:
            continue

        needs.append(Need(op, op, None, variant_id))
    return needs


def classify(blocked: dict[str, list[dict]], capmap: dict) -> Classification:
    """Bucket every need across every blocked variant. Nothing is computed here.

    `blocked` is variant id -> its step list. The return says what is known and,
    just as loudly, what is not.
    """
    buckets: dict[str, str] = {}
    unknown: dict[str, str] = {}
    uncovered: dict[str, str] = {}

    classified, unclassified = capmap["classified"], capmap["unclassified"]
    enumerated = capmap["enumerated_values"]

    for variant_id, steps in blocked.items():
        for need in needs_of(variant_id, steps, capmap):
            key = need.tuple_key
            if key in buckets or key in unknown or key in uncovered:
                continue
            # A tuple decided by an enumerated constant is settled by the
            # enumeration itself: membership in a closed, cited list is an
            # enumeration, not a resemblance. Only the op-level entries below
            # need the map's judgement.
            if key != need.op:
                source = (enumerated.get(f"{need.op}.kind")
                          or enumerated.get(f"{need.op}.event"))
                if source is None:
                    uncovered[key] = (
                        f"{need.op} is decided by a tuple the map declares no "
                        "enumerated values for")
                    continue
                # BOTH ANSWERS REACHABLE. A value inside the mediator's cited
                # enumeration means the machinery is there and the gap is
                # adapter work; a value outside it means the real route. If
                # this only ever returned ROUTE the ceiling could never go
                # false, which is the unfalsifiable derivation again wearing a
                # different hat.
                buckets[key] = (ADAPTER_ONLY if need.value in source["available"]
                                else ROUTE)
                continue
            if need.op in unclassified:
                unknown[key] = unclassified[need.op].get(
                    "open_question", "declared unclassified with no reason given")
            elif need.op in classified:
                buckets[key] = classified[need.op]["bucket"]
            else:
                uncovered[key] = (
                    f"{need.op} appears in a blocked variant and the map does "
                    "not mention it at all")
    return Classification(buckets=buckets, unknown=unknown, uncovered=uncovered)
