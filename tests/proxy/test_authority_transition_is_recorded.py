"""The moment authority is revoked is in the evidence, not just its effects.

Every CONSEQUENCE of an invalidation already named its cause: a dropped
notification carries `reason_code`, a settlement becomes DESCRIPTOR_CHANGED, and
the authority accessor returns the reason while stamping the epoch. The
transition itself was silent, which is only visible in the case nobody tests --
revoke while nothing is outstanding, and there are no consequences to carry the
reason, so the stream says nothing at all.

THE ROWS READ THE RECEIPT BACK FROM DISK, AND THE PRODUCT WRITES IT. The first
version of this file had a disk row that wrote its own record with `log.event`
and read that back, so it proved the allowlist and nothing about the writer.
The writer it assumed was `Session._core._emit`, which appends to
`session.events` in memory only; nothing in production copies those to the log.
So in a real session the record never reached disk, and every row here passed
(R120.1, the Sep-17 control lesson: a control that builds the artefact proves
the reader). The durable record is the route's, through `_record`, and the rows
below drive the route and read the chain it wrote.

NO NEW FIELD (R120). `authority_epoch` was a new key on a frozen wire: #172 is
inside v0.6.0, and every 0.6.0 verifier holds a closed key set, so a row
carrying it is UNKNOWN_FIELD there -- a failure. The reason rides in
`reason_code`, which that set already has, and the ORDER of two revokes is the
chain's own `seq`. The kind is new, and a new kind is UNKNOWN_EVENT under
lifecycle on 0.6.0, never an integrity failure (R44).
"""
import json
import pathlib
import types

import pytest

from sunglasses.proxy import pump, receipts, route as route_module
from sunglasses.proxy.route import Route
from sunglasses.receipts import keys, verify

KIND = "APPROVAL_INVALIDATED"

# The proxy's closed key set as v0.6.0 shipped it, written out rather than
# derived, because the point is that it does not move.
FIELDS_060 = frozenset({
    "direction", "kind", "method", "id_type", "id_token", "raw_len",
    "raw_sha256", "accepted", "status", "detector_status",
    "inspection_complete", "decision", "rule_ids", "inspected_bytes",
    "observed_bytes", "elapsed_ms", "worker_pid", "leaf_provenance", "bytes",
    "reason_code", "rule", "budget", "settled", "supervised", "count",
    "cause_kind", "origin", "bound", "redelivering", "method_known",
    "advertised", "supported", "offered", "reason", "terminal",
    "session_id", "server_identity", "config_sha", "budget_version",
    "catalog_version", "contract_version",
})
EVENTS_060 = frozenset({
    "HEADER", "FRAME_IN", "FRAME_OUT", "ADMITTED", "SCAN_STARTED",
    "HOLD_ENTERED", "SCAN_RESULT", "DISCARDED_LATE", "CANCEL_ACCEPTED",
    "RELEASE_AUTHORIZED", "WRITE_ATTEMPT", "WRITE_COMPLETE", "WRITE_STALLED",
    "SETTLED", "UPSTREAM_CLOSED", "SESSION_TORN_DOWN", "WATCHDOG",
    "RECEIPT_IO_ERROR", "NOTIFICATION_DROPPED", "TEARDOWN", "STDERR_BOUNDED",
    "SETTLEMENT_REFUSED",
})


@pytest.fixture
def home(tmp_path):
    home = tmp_path / "sunglasses-home"
    keys.init(home)
    return home


def _log(home):
    return receipts.Log(home / "proxy", run_id="a" * 32,
                        header={"session_id": "a" * 32}, home=home)


def _route(log, **extra):
    return Route(session=pump.Session(), log=log,
                 upstream_write=lambda raw: None, client_write=lambda raw: None,
                 catalog=frozenset(),
                 approvals=types.SimpleNamespace(
                     may_call=lambda *a: "APPROVAL_REQUIRED",
                     invalidate=lambda: None), **extra)


def _disk(log):
    """Every signed row the log put in its segment files, in file order."""
    rows = []
    for segment in sorted(pathlib.Path(log.path).glob("segment-*.chain")):
        for line in segment.read_bytes().splitlines():
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _transitions(log):
    return [r for r in _disk(log) if r.get("event") == KIND]


def _verified(home, log):
    log.close()
    signer = keys.load(home)
    public = keys.public_path(home, signer.fingerprint).read_bytes()
    return verify.verify_log(log.path, public)


# -- (b) the route writes it, and it is on disk ---------------------------------

def test_revoking_authority_with_nothing_outstanding_is_ON_DISK(home):
    """THE ROW THIS CHANGE EXISTS FOR, measured where an auditor reads.

    Nothing is in flight, so there is no drop and no settlement to carry the
    cause. The setter is the one every revoke goes through (list_changed, the
    re-activation, and the reviewer's controls all assign it).
    """
    log = _log(home)
    rt = _route(log)
    rt._invalidated = "DESCRIPTOR_CHANGED"

    rows = _transitions(log)
    assert len(rows) == 1, (
        f"authority was revoked with nothing outstanding and the chain on disk "
        f"holds {[r.get('event') for r in _disk(log)]} -- the transition is in "
        f"session.events and nowhere an auditor can read")
    assert rows[0]["body"].get("reason_code") == "DESCRIPTOR_CHANGED", rows[0]


def test_the_row_carries_no_key_a_060_verifier_does_not_know(home):
    log = _log(home)
    rt = _route(log)
    rt._invalidated = "DESCRIPTOR_CHANGED"
    (row,) = _transitions(log)
    assert set(row["body"]) <= FIELDS_060, sorted(set(row["body"]) - FIELDS_060)


# -- (c) two revokes are two records, ordered by the chain ----------------------

def test_two_revokes_are_two_records_in_seq_order(home):
    """The reason alone cannot order two invalidations; the chain's seq does,
    and it is signed, which a field the writer fills in is not."""
    log = _log(home)
    rt = _route(log)
    rt._invalidated = "DESCRIPTOR_CHANGED"
    rt._invalidated = "DESCRIPTOR_CHANGED"
    seqs = [r["seq"] for r in _transitions(log)]
    assert len(seqs) == 2, seqs
    assert seqs[0] < seqs[1], seqs


def test_clearing_the_flag_is_not_a_revoke(home):
    log = _log(home)
    rt = _route(log)
    rt._invalidated = None
    assert _transitions(log) == []


# -- the re-activation re-assign records only an actual set ---------------------

def _failing_activation(monkeypatch, provenance):
    monkeypatch.setattr(route_module.activation, "activate",
                        lambda *a, **kw: types.SimpleNamespace(
                            activated=False, provenance=provenance,
                            snapshot=None))


def _activating_route(log):
    # A control whose pager is never called: `activate` is replaced below, and
    # `_pager()` only builds the closure it would have been handed.
    control = types.SimpleNamespace(pager=lambda method: lambda cursor: None)
    rt = _route(log, control=control, server_identity="server")
    rt.approvals._record_or_reason = lambda: ({"snapshot_sha256": "s"}, None)
    return rt


def test_a_failed_reactivation_does_not_record_a_second_revoke(home, monkeypatch):
    """`_activate_once` re-assigned the CURRENT value when the failure was not
    DESCRIPTOR_CHANGED, and the setter reads every assignment as a revoke. So a
    route already revoked wrote a second transition that never happened, and
    the epoch was bumped a second time for it (it was already double-counted
    there before any record existed)."""
    log = _log(home)
    rt = _activating_route(log)
    rt._invalidated = "DESCRIPTOR_CHANGED"
    _failing_activation(monkeypatch, "APPROVAL_REQUIRED")
    rt._activate_once()
    assert len(_transitions(log)) == 1, [r["body"] for r in _transitions(log)]
    assert rt._invalidated == "DESCRIPTOR_CHANGED"


def test_a_reactivation_that_finds_the_descriptors_moved_IS_a_revoke(home,
                                                                     monkeypatch):
    """The other direction, or the guard passes by recording nothing."""
    log = _log(home)
    rt = _activating_route(log)
    _failing_activation(monkeypatch, "DESCRIPTOR_CHANGED")
    rt._activate_once()
    rows = _transitions(log)
    assert len(rows) == 1, rows
    assert rows[0]["body"].get("reason_code") == "DESCRIPTOR_CHANGED"
    assert rt._invalidated == "DESCRIPTOR_CHANGED"


def test_a_failed_first_activation_revokes_nothing(home, monkeypatch):
    log = _log(home)
    rt = _activating_route(log)
    _failing_activation(monkeypatch, "APPROVAL_REQUIRED")
    rt._activate_once()
    assert _transitions(log) == []
    assert rt._invalidated is None


# -- (a) the frozen wire reads it -----------------------------------------------

def test_no_new_key_on_the_frozen_wire():
    assert "authority_epoch" not in receipts.PERMITTED_FIELDS
    assert receipts.PERMITTED_FIELDS == FIELDS_060
    assert verify.PROXY_FIELDS == FIELDS_060


def test_the_060_key_set_reads_the_record_and_integrity_holds(home):
    log = _log(home)
    rt = _route(log)
    rt._invalidated = "DESCRIPTOR_CHANGED"
    log.event("TEARDOWN")
    report = _verified(home, log)
    assert report.results["chain_integrity"] == "CHAIN_OK", report.results
    assert report.results["lifecycle"] == "PAIRING_UNKEYED", report.results


def test_a_060_verifier_calls_the_kind_unknown_and_integrity_still_holds(
        home, monkeypatch):
    """What an operator on v0.6.0 sees: a lifecycle limit, never a forgery."""
    monkeypatch.setattr(verify, "PROXY_EVENTS", EVENTS_060)
    log = _log(home)
    rt = _route(log)
    rt._invalidated = "DESCRIPTOR_CHANGED"
    log.event("TEARDOWN")
    report = _verified(home, log)
    assert report.results["chain_integrity"] == "CHAIN_OK", report.results
    assert report.results["lifecycle"] == "UNKNOWN_EVENT", report.results


def test_the_verifier_prints_the_count(home):
    log = _log(home)
    rt = _route(log)
    rt._invalidated = "DESCRIPTOR_CHANGED"
    rt._invalidated = "DESCRIPTOR_CHANGED"
    log.event("TEARDOWN")
    report = _verified(home, log)
    assert report.authority_transitions == 2
    assert "authority transitions: 2" in verify.render_log(report)


def test_a_log_with_no_revoke_prints_nothing_new(home):
    """Existing outputs stay byte-identical: the line appears only when there
    is something to count."""
    log = _log(home)
    log.event("TEARDOWN")
    report = _verified(home, log)
    assert report.authority_transitions == 0
    assert "authority transitions" not in verify.render_log(report)


# -- the in-memory event keeps its reason ---------------------------------------

def test_the_session_event_names_the_reason_and_nothing_new():
    session = pump.Session(strict=False)
    session.accept_invalidation("DESCRIPTOR_CHANGED")
    row = next(e for e in session.events if e["kind"] == KIND)
    assert row["reason_code"] == "DESCRIPTOR_CHANGED", row
    assert "authority_epoch" not in row, row
