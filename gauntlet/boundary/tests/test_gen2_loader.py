"""Telling the two generations apart, by shape and never by id.

The payload resolver that used to be duplicated here is gone. T8 landed
`runner.resolve_payload_ref` in 0ba36c8 with a test that checks the digest and
not just the path, plus a sweep asserting every referenced payload in the
package resolves today. Re-implementing it here would have meant two resolvers
that can disagree, which is the shape of defect this harness exists to find.
"""
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from gen2 import loader                                    # noqa: E402


def test_generation_is_read_from_the_variant_not_from_its_id():
    """By SHAPE, never by id range.

    G2-01..G2-12 carry no route at all and the harness derives proxy_strict and
    control from CONTROL_SEEDS; G2-13 onward carry `routes` plural. Deciding on
    "id >= G2-13" would be a rule about one delivery, and the next delivery
    would arrive numbered wherever it liked.
    """
    old = {"name": "main", "request_id": 1, "requests": "main.requests.jsonl"}
    new = {"name": "error_message", "routes": ["proxy_strict", "no_mediation"],
           "schedule_file": "error_message.schedule.json",
           "payload_ref": {"scenario_id": "G2-01"}}

    assert loader.generation_of(old) == 1
    assert loader.generation_of(new) == 2


def test_a_variant_that_mixes_the_two_shapes_is_refused():
    """Half-migrated is the state that produces a confident wrong answer.

    A variant carrying `routes` and an inline `payload` would be driven by the
    generation-2 adapter, which resolves payload_ref, and would silently ignore
    the payload actually written down next to it.
    """
    mixed = {"name": "x", "routes": ["proxy_strict"], "payload": "inline bytes"}

    with pytest.raises(loader.AmbiguousGeneration):
        loader.generation_of(mixed)


def test_every_variant_in_the_package_classifies(monkeypatch):
    """The real package, both deliveries, no variant left undecided.

    A classifier that returns 1 for anything it does not recognise would send
    the whole second generation to the driver that cannot express it, and the
    rows would come back as failures of the candidate rather than of the
    harness. That is the exact reading error the Gate 2 exam threw out 20 rows
    over, so the unknown case has to be loud.
    """
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
    import runner

    counts = {1: 0, 2: 0}
    for entry in runner.load_manifest()["scenarios"]:
        for variant in runner.scenario_of(entry)["variants"]:
            counts[loader.generation_of(variant)] += 1

    assert counts[1] == 21, counts
    assert counts[2] == 74, counts
    assert counts[1] + counts[2] == 95, counts
