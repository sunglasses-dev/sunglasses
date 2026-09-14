"""Every step is checked against ASTRA's frozen field contract before anything runs.

PROFILE_STEPS.md is the confirmed contract for the `profile_steps` array in the
74 reference schedules: 40 step types, each with the fields it must carry. Its
closing paragraph is the rule this file exists to enforce — "Unsupported
operations, missing required fields/barriers or skipped required actions are
INVALID ... they must not silently become successful no-ops".

A step whose required field is absent is not a step this adapter can execute. It
could be executed approximately, and that is the failure: an approximate run
still produces a row, and the row reads like a verdict about the candidate.

The contract's digest is pinned in the adapter, so a schema change is a visible
break rather than a drift.
"""
import json
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
import runner                                              # noqa: E402
from gen2 import adapter, artifacts                        # noqa: E402


def test_the_contract_digest_is_pinned_to_the_document_on_disk():
    """A schema change has to break loudly, not drift.

    If this fails, ASTRA shipped a new contract and the adapter has not been
    read against it. Bumping the constant without reading the diff is the one
    response that defeats the purpose.
    """
    import hashlib
    document = (pathlib.Path.home() / "Desktop" / "SUNGLASSES_ASTRA_REVIEW_2026-09-04"
                / "GATE3_DESIGN_REVIEW_2026-09-13" / "tools_v2" / "PROFILE_STEPS.md")
    assert document.is_file(), f"the frozen contract is not at {document}"
    assert hashlib.sha256(document.read_bytes()).hexdigest() == adapter.PROFILE_STEPS_SHA256


def test_the_contract_covers_every_step_type_the_document_describes():
    """40, said out loud in the document's own prose."""
    assert len(adapter.STEP_CONTRACT) == 40, sorted(adapter.STEP_CONTRACT)


def test_a_step_missing_a_required_field_is_refused():
    """The failure that matters: it would otherwise run approximately."""
    with pytest.raises(adapter.StepContractViolation) as exc:
        adapter.check_step({"op": "send_file", "origin": "client"})

    message = str(exc.value)
    assert "send_file" in message and "path" in message, message


def test_a_step_carrying_an_unknown_field_is_refused():
    """"no additional fields or silent opcode substitutions are part of this version"."""
    with pytest.raises(adapter.StepContractViolation) as exc:
        adapter.check_step({"op": "assert_pending_retired", "id_from": "a.jsonl",
                            "timeout_ms": 3000})
    assert "timeout_ms" in str(exc.value), str(exc.value)


def test_an_unknown_op_is_refused_by_name():
    with pytest.raises(adapter.StepContractViolation) as exc:
        adapter.check_step({"op": "definitely_not_an_op"})
    assert "definitely_not_an_op" in str(exc.value)


def test_an_optional_field_may_be_absent_and_may_be_present():
    """`?` in the table means optional, and both shapes are the contract."""
    adapter.check_step({"op": "release_fault_barrier"})
    adapter.check_step({"op": "release_fault_barrier", "require_discard": True})


def test_every_step_in_all_74_delivered_schedules_conforms():
    """The whole delivery, against the document, today.

    This is the test that earns its keep. It is the difference between an
    adapter that believes the contract and one that has checked it, and if
    ASTRA's schedules and his own document ever disagree this is where it shows
    rather than halfway through a grid run.
    """
    checked = 0
    offending = []
    for entry in runner.load_manifest()["scenarios"]:
        for variant in runner.scenario_of(entry)["variants"]:
            if "routes" not in variant:
                continue
            record = artifacts.of_record(entry, variant)
            for step in record.schedule.get("profile_steps") or []:
                try:
                    adapter.check_step(step)
                except adapter.StepContractViolation as exc:
                    offending.append(f"{entry['id']}.{variant['name']}: {exc}")
                checked += 1

    assert not offending, offending[:5]
    # 340 is measured. The first version of this said 297 because I guessed,
    # and the sweep corrected me, which is the only reason a number belongs in
    # a test at all.
    assert checked == 340, f"expected the delivery's 340 steps, saw {checked}"
