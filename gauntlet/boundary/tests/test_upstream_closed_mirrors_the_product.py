"""The harness may only emit an event the PRODUCT emits, and only as it does.

T8 measured the product on main `1e4e526` and the answer decided this row:

    UPSTREAM_CLOSED       a receipt kind, emitted at sunglasses/proxy/session.py
    REQUEST_RECEIVED      NOT a record. ADMITTED and FRAME_IN carry an id type,
                          not an origin
    DESCRIPTOR_CHANGED    an envelope reason_code in proxy/approvals.py, retired
                          through `_retire()`. Never written as a record
    APPROVAL_INVALIDATED  changes state in proxy/pump.py and emits NOTHING

Verified here by importing `sunglasses.proxy.receipts.EVENTS` rather than by
reading the report, because a citation is a claim until the set says so.

So exactly one of the four gets mirrored. Inventing the other three in
`SUPPORTED_EVENTS` would make the adapter the author of the scenario's meaning,
which is the sentence the whole refusal is built on.
"""
import json
import pathlib
import shutil
import sys
import uuid

import pytest

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[2]
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(REPO))

import runner                                                  # noqa: E402
from gen2 import execute                                       # noqa: E402


PRIVATE_TMP = pathlib.Path("/private/tmp")


@pytest.fixture()
def run_root():
    """Under /private/tmp, because the materialiser refuses anywhere else — and
    it is right to: these runs create pipes, children and a file observer."""
    root = PRIVATE_TMP / f"upstream-closed-{uuid.uuid4().hex[:10]}"
    yield root
    shutil.rmtree(root, ignore_errors=True)


def _receipt_kinds(run_root):
    kinds = []
    for line in (run_root / "proxy.receipts.jsonl").read_text().splitlines():
        if line.strip():
            kinds.append(json.loads(line))
    return kinds


def test_the_product_emits_upstream_closed_and_not_the_other_three():
    """The premise of this whole row, asserted rather than cited."""
    from sunglasses.proxy import receipts

    assert "UPSTREAM_CLOSED" in receipts.EVENTS
    for absent in ("REQUEST_RECEIVED", "DESCRIPTOR_CHANGED",
                   "APPROVAL_INVALIDATED"):
        assert absent not in receipts.EVENTS, (
            f"{absent} IS a product record now; this harness refuses it by name "
            "on the grounds that it is not, and that reason has expired")


def test_the_harness_emits_upstream_closed_when_it_supervised_the_upstream(run_root):
    """Mirrored from `session.py`, including WHEN it may be said.

    The product's own comment is the discipline: UPSTREAM_CLOSED is a claim
    about PROCESSES, made only when something actually supervised them, because
    saying it otherwise "puts a false sentence in the evidence while a child is
    still running". The harness supervises in `_kill_group`, so it may say so
    after that and only for a process that really ended.
    """
    entry = next(e for e in runner.load_manifest()["scenarios"]
                 if e["id"] == "G2-16")
    variant = next(v for v in runner.scenario_of(entry)["variants"]
                   if v["name"] == "wire_name")

    shutil.rmtree(run_root, ignore_errors=True)
    execute.run(entry, variant, route="proxy_strict", run_root=run_root,
                engine_root=REPO, timeout_ms=20000)

    events = _receipt_kinds(run_root)
    closed = [e for e in events if e["kind"] == "UPSTREAM_CLOSED"]
    assert closed, (
        "the harness started an upstream and never recorded it closing: "
        f"{sorted({e['kind'] for e in events})}")
    assert len(closed) == 1, closed

    # It ran at all — otherwise "no UPSTREAM_CLOSED" would be true for a session
    # that never had an upstream, and this row would pass on an empty run.
    assert any(e["kind"] == "UPSTREAM_STARTED" for e in events), events[:3]

    # THE CLAIM IS ABOUT A PROCESS, so it carries what the process did.
    assert closed[0].get("status") is not None, closed[0]
