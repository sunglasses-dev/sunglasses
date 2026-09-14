"""T9's receipts, specified from the rows before the module exists.

Two clauses carry the weight and both are about ORDER rather than content.

T9.R2: RELEASE_AUTHORIZED is fsync'd BEFORE the first original byte leaves.
A receipt written after the bytes are gone is a description of something that
already happened and cannot be relied on: a crash between the release and the
write leaves a payload delivered and no record that it was. The whole value of
an audit trail is that the record exists BEFORE the irreversible act, so the
ordering is the property, not the field.

T9.R4: an append or fsync failure after HOLD_ENTERED stops everything. Once the
log cannot be written, the proxy can no longer honestly say what it did, and
continuing to mediate while unable to record is the failure mode that leaves an
operator with a clean-looking session and no evidence.

T9.R3 is a never-list, so it is tested by trying to push each forbidden thing
through and requiring it absent, in the same shape as the envelope tests.
"""
import json

import pytest

receipts = pytest.importorskip("sunglasses.proxy.receipts",
                               reason="receipts are the slice being specified")

SECRET = "AKIAGATE2SYNTHETIC001"


@pytest.fixture
def log(tmp_path):
    return receipts.Log(tmp_path, run_id="run-abc",
                        header={"session_id": "s1", "server_identity": "fs-1",
                                "config_sha": "c" * 64, "budget_version": "1",
                                "catalog_version": "1", "contract_version": "5.1"})


# ── T9.R1: the header, and one ordered writer ─────────────────────────────

def test_the_header_is_the_first_line_and_carries_the_six_fields(log):
    log.close()
    first = json.loads(log.path.read_text().splitlines()[0])
    assert first["kind"] == "HEADER"
    for field in ("session_id", "server_identity", "config_sha",
                  "budget_version", "catalog_version", "contract_version"):
        assert field in first


def test_the_log_is_opened_before_the_first_frame(tmp_path):
    """R1 says opened BEFORE the first frame. A log created lazily on the first
    event cannot record a failure that happens before it."""
    log = receipts.Log(tmp_path, run_id="run-x", header={"session_id": "s"})
    assert log.path.exists(), "the file was not created at construction"
    log.close()


def test_sequence_numbers_are_monotonic_and_gapless(log):
    for n in range(5):
        log.event("ADMITTED", id_token="t%d" % n)
    log.close()
    rows = [json.loads(line) for line in log.path.read_text().splitlines()]
    assert [row["seq"] for row in rows] == list(range(len(rows)))
    stamps = [row["mono_ns"] for row in rows]
    assert stamps == sorted(stamps)


def test_one_writer_means_concurrent_events_do_not_interleave(log):
    """R1 says ONE ordered writer. Two threads appending to the same file
    without a lock produce torn lines, and a torn line is an unreadable receipt
    which by R5 invalidates the whole log."""
    import threading

    def spam(tag):
        for _ in range(50):
            log.event("ADMITTED", id_token=tag)

    threads = [threading.Thread(target=spam, args=(f"t{n}",)) for n in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    log.close()

    lines = log.path.read_text().splitlines()
    for line in lines:
        json.loads(line)                       # every line parses or this raises
    assert len([x for x in lines if '"ADMITTED"' in x]) == 200


# ── T9.R2: the ordering that makes the record worth having ────────────────

def test_release_is_authorised_and_fsynced_before_any_original_byte(log):
    """The property is the ORDER. A receipt written after the bytes are gone
    describes something that already happened, and a crash in between leaves a
    payload delivered with no record that it was."""
    order = []
    log.on_fsync = lambda: order.append("fsync")
    released = []

    log.authorise_release("t1", write=lambda: (order.append("write"),
                                               released.append(True)))
    assert order == ["fsync", "write"], order
    assert released == [True]
    log.close()

    kinds = [json.loads(x)["kind"] for x in log.path.read_text().splitlines()]
    assert "RELEASE_AUTHORIZED" in kinds


def test_a_failed_fsync_means_the_bytes_never_leave(log):
    """If the authorisation cannot be made durable, the release it authorises
    must not happen. Releasing anyway is the case the ordering exists to
    prevent, arrived at from the other side."""
    def boom():
        raise OSError("disk is gone")

    log.on_fsync = boom
    released = []
    with pytest.raises(receipts.ReceiptIOError):
        log.authorise_release("t1", write=lambda: released.append(True))
    assert released == [], "the payload was released after the receipt failed"


# ── T9.R3: the never-list ─────────────────────────────────────────────────

@pytest.mark.parametrize("field,value", [
    ("payload", SECRET),
    ("matched_text", f"found {SECRET}"),
    ("stderr", f"Traceback: {SECRET}"),
    ("pointer", "/params/arguments/content"),
    ("raw_id", 41),
    ("key", "arguments"),
])
def test_no_forbidden_field_reaches_the_log(log, field, value):
    """R3 is a never-list, so it is tested by pushing each thing at it."""
    log.event("SCAN_RESULT", **{field: value})
    log.close()
    text = log.path.read_text()
    assert SECRET not in text
    assert "/params/arguments/content" not in text


def test_provenance_is_indices_and_hashes_never_names(log):
    """T3.R2. A pointer names the shape of the document, which is information
    about the payload even when the payload itself is absent."""
    log.event("SCAN_RESULT", leaf_provenance=[
        {"index": 0, "depth": 3, "pointer": "/params/arguments/content",
         "bytes": 21, "value_sha256": "a" * 64}])
    log.close()
    row = [json.loads(x) for x in log.path.read_text().splitlines()][-1]
    leaf = row["leaf_provenance"][0]
    assert "pointer" not in leaf and "pointer_sha256" in leaf
    assert leaf["index"] == 0 and leaf["depth"] == 3


def test_only_allowlisted_event_kinds_are_written(log):
    with pytest.raises(ValueError):
        log.event("SOMETHING_I_INVENTED", id_token="t1")


# ── T9.R4: a log that cannot be written stops the session ─────────────────

def test_a_write_failure_after_hold_stops_admission_and_release(log):
    log.event("HOLD_ENTERED", id_token="t1")
    log.fail_writes(OSError("no space"))
    outcome = log.record_or_stop("SCAN_RESULT", id_token="t1")
    assert outcome.stopped is True
    assert outcome.reason == "RECEIPT_IO_ERROR"
    assert outcome.exit_code != 0


def test_the_client_refusal_after_a_receipt_failure_is_bounded_and_not_durable(log):
    """R4: ONE bounded SUNGLASSES_WITHHELD per known pending id, best effort,
    never the original, and never claimed durable."""
    log.event("HOLD_ENTERED", id_token="t1")
    log.fail_writes(OSError("no space"))
    outcome = log.record_or_stop("SCAN_RESULT", id_token="t1")
    refusals = outcome.client_refusals(pending_ids=[41, "42"])
    assert len(refusals) == 2
    for refusal in refusals:
        assert refusal["error"]["data"]["reason_code"] == "RECEIPT_IO_ERROR"
        assert refusal["error"]["message"] == "SUNGLASSES_WITHHELD"
    assert [r["id"] for r in refusals] == [41, "42"]
    assert outcome.durable is False, (
        "a refusal sent when the log is unwritable cannot be claimed durable")


def test_prior_forwarded_state_is_recorded_unknown_not_guessed(log):
    log.event("HOLD_ENTERED", id_token="t1")
    log.fail_writes(OSError("no space"))
    outcome = log.record_or_stop("WRITE_ATTEMPT", id_token="t1")
    assert outcome.prior_state == "UNKNOWN"


# ── T9.R5: the verifier, and what it does NOT claim ───────────────────────

def test_a_well_formed_log_verifies(log):
    """T905. The terminal event is part of being well formed now. A log that
    simply stops does not say how the session ended, and this test used to
    assert that such a log verified."""
    log.event("ADMITTED", id_token="t1")
    log.event("SETTLED", id_token="t1")
    log.event("SESSION_TORN_DOWN")
    log.close()
    assert receipts.verify(log.path).ok


def test_a_log_that_simply_stops_does_not_verify(log):
    """The other side of the same row, because "well formed" is now a claim
    about the ending as well as the rows. Certifying a truncated log describes
    a session whose ending nobody wrote down as one that ended cleanly."""
    log.event("ADMITTED", id_token="t1")
    log.event("SETTLED", id_token="t1")
    log.close()
    outcome = receipts.verify(log.path)
    assert not outcome.ok and outcome.reason == "INCOMPLETE_SESSION"
    assert "terminal" in outcome.detail


@pytest.mark.parametrize("break_it,reason", [
    ("drop_header", "header"),
    ("repeat_seq", "seq"),
    ("reorder_seq", "seq"),
    ("gap_seq", "seq"),
    ("back_in_time", "mono_ns"),
    ("no_terminal", "terminal"),
])
def test_the_verifier_rejects_each_named_defect(tmp_path, break_it, reason):
    path = receipts.write_broken_log(tmp_path, break_it)
    outcome = receipts.verify(path)
    assert not outcome.ok
    assert reason in outcome.detail


def test_admitted_without_settled_is_an_incomplete_session(log):
    log.event("ADMITTED", id_token="t1")
    log.close()
    outcome = receipts.verify(log.path)
    assert not outcome.ok and outcome.reason == "INCOMPLETE_SESSION"


def test_verification_does_not_claim_the_model_received_anything(log):
    """R5's last clause, as an assertion because it is the thing a reader is
    most likely to over-read. The log is unsigned and local: it proves schema,
    order and completion, and says nothing about what any model was shown."""
    log.event("ADMITTED", id_token="t1")
    log.event("SETTLED", id_token="t1")
    log.close()
    outcome = receipts.verify(log.path)
    assert outcome.proves == ("schema", "order", "completion")
    assert outcome.signed is False
    assert outcome.proves_delivery is False


def test_an_invented_event_kind_is_rejected_on_an_otherwise_complete_log(tmp_path):
    """T905. The kinds were never checked, so a row naming an event that does
    not exist verified as well formed.

    The log here is complete in every other way -- header, an admitted item
    settled, a terminal event -- so the ONLY thing wrong with it is the invented
    kind. ASTRA's fixture for this row has no terminal event either, so the
    completion check rejects it first and the kind check is never reached;
    the mutation that deleted the kind check survived his control and this one
    kills it.
    """
    rows = [
        {"seq": 0, "mono_ns": 1, "wall": 1.0, "kind": "HEADER"},
        {"seq": 1, "mono_ns": 2, "wall": 1.0, "kind": "ADMITTED", "id_token": "t1"},
        {"seq": 2, "mono_ns": 3, "wall": 1.0, "kind": "review-invalid-event"},
        {"seq": 3, "mono_ns": 4, "wall": 1.0, "kind": "SETTLED", "id_token": "t1"},
        {"seq": 4, "mono_ns": 5, "wall": 1.0, "kind": "SESSION_TORN_DOWN"},
    ]
    path = tmp_path / "invented.jsonl"
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
    outcome = receipts.verify(path)
    assert not outcome.ok
    assert outcome.reason == "MALFORMED_RECEIPT"
    assert "review-invalid-event" in outcome.detail


def test_the_same_log_with_a_real_kind_verifies(tmp_path):
    """The positive control, or the row above is satisfied by a verifier that
    rejects everything."""
    rows = [
        {"seq": 0, "mono_ns": 1, "wall": 1.0, "kind": "HEADER"},
        {"seq": 1, "mono_ns": 2, "wall": 1.0, "kind": "ADMITTED", "id_token": "t1"},
        {"seq": 2, "mono_ns": 3, "wall": 1.0, "kind": "WATCHDOG"},
        {"seq": 3, "mono_ns": 4, "wall": 1.0, "kind": "SETTLED", "id_token": "t1"},
        {"seq": 4, "mono_ns": 5, "wall": 1.0, "kind": "SESSION_TORN_DOWN"},
    ]
    path = tmp_path / "real.jsonl"
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
    assert receipts.verify(path).ok
