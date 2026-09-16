"""The log, written before the thing it records.

T9. Written against `tests/test_proxy_receipts.py`, committed first.

The ordering in R2 is the whole design. RELEASE_AUTHORIZED is made durable
BEFORE the first original byte leaves, because a receipt written afterwards
describes something that already happened: a crash in the gap leaves a payload
delivered and no record that it was, and an audit trail whose weakest moment is
the irreversible act is not an audit trail.

R4 follows from the same thought. Once the log cannot be written, this component
can no longer honestly say what it did, so it stops rather than continuing to
mediate silently. A clean-looking session with no evidence behind it is worse
than a refused one.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import threading
import time

# T9.R2's allowlist. An event outside it cannot be written, for the same reason
# the client envelope is built by naming fields: a log that accepts any kind is
# a log whose schema is whatever the last caller felt like.
EVENTS = frozenset({
    "HEADER", "FRAME_IN", "FRAME_OUT", "ADMITTED", "SCAN_STARTED",
    "HOLD_ENTERED", "SCAN_RESULT", "DISCARDED_LATE", "CANCEL_ACCEPTED",
    "RELEASE_AUTHORIZED", "WRITE_ATTEMPT", "WRITE_COMPLETE", "WRITE_STALLED",
    "SETTLED", "UPSTREAM_CLOSED", "SESSION_TORN_DOWN", "WATCHDOG",
    "RECEIPT_IO_ERROR", "NOTIFICATION_DROPPED", "TEARDOWN",
})

# T9.R3's never-list, as field names rather than as a hope. Anything not in the
# permitted set for an event is dropped, and these are named so a reader can see
# what was being guarded against.
FORBIDDEN_FIELDS = frozenset({
    "payload", "matched_text", "stderr", "stdout", "exception", "detail",
    "pointer", "raw_id", "key", "text", "content", "body",
})

PERMITTED_FIELDS = frozenset({
    "direction", "kind", "method", "id_type", "id_token", "raw_len",
    "raw_sha256", "accepted", "status", "detector_status",
    "inspection_complete", "decision", "rule_ids", "inspected_bytes",
    "observed_bytes", "elapsed_ms", "worker_pid", "leaf_provenance", "bytes",
    "reason_code", "rule", "budget", "settled", "supervised", "count",
    "session_id", "server_identity", "config_sha", "budget_version",
    "catalog_version", "contract_version",
})


class ReceiptIOError(RuntimeError):
    """The log could not be made durable, so nothing that depends on it may run."""


class Stop:
    __slots__ = ("stopped", "reason", "exit_code", "prior_state", "durable")

    def __init__(self, stopped, reason, exit_code, prior_state, durable):
        self.stopped = stopped
        self.reason = reason
        self.exit_code = exit_code
        self.prior_state = prior_state
        self.durable = durable

    def client_refusals(self, pending_ids):
        """T9.R4. ONE bounded refusal per known pending id, best effort.

        Never the original, and never claimed durable: this is being sent by a
        component that has just discovered it cannot write anything down, so it
        does not get to assert that anything was recorded.
        """
        return [{
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32070, "message": "SUNGLASSES_WITHHELD",
                      "data": {"reason_code": self.reason, "rule": "S3"}},
        } for request_id in pending_ids]


class Verification:
    __slots__ = ("ok", "reason", "detail", "proves", "signed", "proves_delivery")

    def __init__(self, ok, reason=None, detail=""):
        self.ok = ok
        self.reason = reason
        self.detail = detail
        # T9.R5's last clause, carried on the result rather than left to a
        # reader's assumption. This is the field most likely to be over-read.
        self.proves = ("schema", "order", "completion")
        self.signed = False
        self.proves_delivery = False


class Log:
    """One ordered writer, opened before the first frame."""

    def __init__(self, root, *, run_id, header):
        self.root = pathlib.Path(root) / "receipts"
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / f"{run_id}.jsonl"
        self._lock = threading.Lock()
        self._seq = 0
        self._failure = None
        self.on_fsync = None
        # OPENED NOW, not on the first event. A log created lazily cannot record
        # a failure that happens before it, which is exactly the window R1 is
        # closing by saying "opened before the first frame".
        self._handle = self.path.open("a", encoding="utf-8")
        self._write_row(dict(header or {}), kind="HEADER")

    # ── writing ─────────────────────────────────────────────────────────────
    def event(self, kind, **fields):
        if kind not in EVENTS:
            raise ValueError(
                f"{kind!r} is not an allowlisted receipt event; a log that "
                f"accepts any kind has whatever schema the last caller chose")
        return self._write_row(fields, kind=kind)

    def _write_row(self, fields, *, kind):
        with self._lock:
            if self._failure is not None:
                raise ReceiptIOError(str(self._failure))
            row = {
                "seq": self._seq,
                "mono_ns": time.monotonic_ns(),
                "wall": time.time(),
                "kind": kind,
            }
            row.update(self._clean(fields))
            self._handle.write(json.dumps(row, sort_keys=True) + "\n")
            self._handle.flush()
            self._seq += 1
            return row

    def _clean(self, fields):
        """T9.R3. An allowlist, and provenance reduced to indices and hashes."""
        clean = {}
        for name, value in (fields or {}).items():
            if name in FORBIDDEN_FIELDS or name not in PERMITTED_FIELDS:
                continue
            if name == "leaf_provenance":
                clean[name] = [self._leaf(entry) for entry in value or ()]
                continue
            clean[name] = value
        return clean

    @staticmethod
    def _leaf(entry):
        """T3.R2. The pointer is HASHED, never carried.

        A pointer names the shape of the document, which is information about
        the payload even when the payload itself is absent: `/params/arguments/
        content` says a tools/call carried an argument called content.
        """
        out = {"index": entry.get("index"), "depth": entry.get("depth"),
               "bytes": entry.get("bytes"),
               "value_sha256": entry.get("value_sha256")}
        pointer = entry.get("pointer")
        if pointer is not None:
            out["pointer_sha256"] = hashlib.sha256(
                str(pointer).encode("utf-8", "surrogatepass")).hexdigest()
        return out

    # ── T9.R2: durable before irreversible ──────────────────────────────────
    def authorise_release(self, id_token, *, write):
        """Record and fsync the authorisation, THEN let the bytes go.

        If the authorisation cannot be made durable the release does not happen,
        which is the same rule seen from the other side: there must be no moment
        where the payload is gone and the record is not there.
        """
        self.event("RELEASE_AUTHORIZED", id_token=id_token)
        self._fsync()
        return write()

    def _fsync(self):
        try:
            if self.on_fsync is not None:
                self.on_fsync()
            else:
                os.fsync(self._handle.fileno())
        except Exception as failed:
            self._failure = failed
            raise ReceiptIOError(f"the receipt could not be made durable: {failed}")

    # ── T9.R4 ───────────────────────────────────────────────────────────────
    def fail_writes(self, error):
        """Test seam: make every later append fail the way a full disk does."""
        self._failure = error

    def record_or_stop(self, kind, **fields):
        """Write it, or stop the session and say what is now unknown."""
        try:
            self.event(kind, **fields)
        except ReceiptIOError:
            return Stop(True, "RECEIPT_IO_ERROR", exit_code=1,
                        # Anything already forwarded cannot be confirmed from a
                        # log we can no longer read back or extend, and guessing
                        # would be the invention this whole table exists to stop.
                        prior_state="UNKNOWN", durable=False)
        return Stop(False, None, 0, None, True)

    def close(self):
        with self._lock:
            if not self._handle.closed:
                self._handle.close()


# ── T9.R5 ──────────────────────────────────────────────────────────────────
def verify(path):
    """Schema, order and completion. Nothing about delivery."""
    lines = [line for line in pathlib.Path(path).read_text().splitlines() if line]
    if not lines:
        return Verification(False, "INCOMPLETE_SESSION", "no header")

    rows = []
    for line in lines:
        try:
            rows.append(json.loads(line))
        except ValueError:
            return Verification(False, "MALFORMED_RECEIPT", "a line is not JSON")

    if rows[0].get("kind") != "HEADER":
        return Verification(False, "MALFORMED_RECEIPT", "missing header")

    seen = set()
    previous_seq, previous_mono = -1, -1
    for row in rows:
        seq = row.get("seq")
        if seq in seen:
            return Verification(False, "MALFORMED_RECEIPT", f"repeated seq {seq}")
        if seq != previous_seq + 1:
            return Verification(False, "MALFORMED_RECEIPT",
                                f"seq {seq} is out of order or leaves a gap")
        if row.get("mono_ns", 0) < previous_mono:
            return Verification(False, "MALFORMED_RECEIPT",
                                "mono_ns goes backwards")
        seen.add(seq)
        previous_seq, previous_mono = seq, row.get("mono_ns", 0)

    admitted = {row.get("id_token") for row in rows if row["kind"] == "ADMITTED"}
    settled = {row.get("id_token") for row in rows if row["kind"] == "SETTLED"}
    if admitted - settled:
        return Verification(False, "INCOMPLETE_SESSION",
                            "an ADMITTED item has no terminal SETTLED")
    return Verification(True)


def write_broken_log(root, how):
    """Build a log with exactly one named defect, for the verifier's tests."""
    path = pathlib.Path(root) / "broken.jsonl"
    base = [{"seq": 0, "mono_ns": 1, "wall": 1.0, "kind": "HEADER"},
            {"seq": 1, "mono_ns": 2, "wall": 1.0, "kind": "ADMITTED",
             "id_token": "t1"},
            {"seq": 2, "mono_ns": 3, "wall": 1.0, "kind": "SETTLED",
             "id_token": "t1"}]
    if how == "drop_header":
        base = base[1:]
        base[0]["seq"] = 0
        base[1]["seq"] = 1
    elif how == "repeat_seq":
        base[2]["seq"] = 1
    elif how == "reorder_seq":
        base[1], base[2] = base[2], base[1]
    elif how == "gap_seq":
        base[2]["seq"] = 5
    elif how == "back_in_time":
        base[2]["mono_ns"] = 1
    elif how == "no_terminal":
        base = base[:2]
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in base) + "\n")
    return path
