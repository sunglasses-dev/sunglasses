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
import re
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
    # T902, T9.R2. Required by the row and missing from the allowlist, so the
    # one event that says the stderr cap was applied could not be written.
    "STDERR_BOUNDED",
    # R-179-R6/R5_NOATTEMPT_REFUSAL. A typed refusal is only typed if the log
    # will take it: `Log.event` raises ValueError on a kind that is not here,
    # so a refusal written through `Route._record` and missing from this list
    # is an exception on a fault path rather than a receipt.
    "SETTLEMENT_REFUSED",
})

# T9.R5. The events that END a session. A log that stops without one of these
# is not a clean short session; it is a session whose ending is unknown, and a
# verifier that returns ok for it certifies the absence of evidence.
TERMINAL_EVENTS = frozenset({"SESSION_TORN_DOWN", "TEARDOWN"})

# T903. The VALUES, not only the field names. An allowlist of names says which
# fields may appear and nothing about what may be inside them, so every one of
# these carried peer-chosen text straight into the evidence.
_ID_TOKEN = re.compile(r"\A[0-9a-f]{16}\Z")
_RULE_ID = re.compile(r"\AGLS-[A-Z0-9-]{1,60}\Z")

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
    # R-CLOSE-KIND, and this line is the difference between the change working
    # and only LOOKING like it works. The kind reaches `session.events` as soon
    # as a Cause carries it, but this list is what the DURABLE receipt keeps:
    # a field missing here is dropped on the way to disk, silently, and every
    # in-memory assertion would still pass. Measured before it was added --
    # a SETTLED row written with `cause_kind` came back without it.
    "cause_kind", "origin", "bound", "redelivering", "method_known",
    "advertised", "supported", "offered", "reason", "terminal",
    "session_id", "server_identity", "config_sha", "budget_version",
    "catalog_version", "contract_version",
})



def _check_value(name, value):
    """T903. What may be INSIDE a permitted field.

    The allowlist above says which names may appear. Five of them were carrying
    whatever the peer chose: a method, a status, a reason code, a rule id and
    an id token all arrived from the wire and were written into the evidence
    verbatim. A receipt is read as a record of what happened, so text an
    attacker picked appears there as fact.

    Each of these has a vocabulary or a grammar that WE define, so each is
    checked against it and a value outside is refused rather than trimmed. The
    refusal is a ValueError because the caller has a bug or the peer has an
    attack, and neither should produce a quietly shortened receipt.
    """
    if value is None:
        return
    if name == "reason_code":
        from .envelope import REASONS
        if value not in REASONS:
            raise ValueError(f"reason_code {value!r} is not in the frozen catalog")
    elif name == "status":
        from .envelope import STATUSES
        if value not in STATUSES:
            raise ValueError(f"status {value!r} is not a worker status")
    elif name == "method":
        from .selector import KNOWN_METHODS
        if value not in KNOWN_METHODS:
            raise ValueError(f"method {value!r} is not a method this proxy knows")
    elif name == "rule_ids":
        if not isinstance(value, (list, tuple)):
            raise ValueError("rule_ids is not a list")
        for rule_id in value:
            if not isinstance(rule_id, str) or not _RULE_ID.match(rule_id):
                raise ValueError(f"rule id {rule_id!r} is not an engine rule id")
    elif name == "id_token":
        # R-T903-1 (T9, 2026-09-14 10:24). The MINTED grammar, not merely a
        # string. `session._item_token` produces sixteen lowercase hex
        # characters, and requiring that is what refuses a peer-supplied id
        # passed under this field name -- which is the actual risk it carries,
        # because a raw JSON-RPC id is peer text and a receipt is read as a
        # record of what happened. A structural check would keep out ASTRA's
        # `{'raw': ...}` and let a chosen string through.
        if not isinstance(value, str) or not _ID_TOKEN.match(value):
            raise ValueError(
                f"id_token {value!r} is not a token this proxy mints; the token "
                f"is OURS, and anything else arriving under its name was "
                f"chosen by somebody else")
    elif name == "rule":
        from .envelope import RULES
        if value not in RULES:
            raise ValueError(f"rule {value!r} is not one of S1 to S7")


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
        # T906. Built by the single constructor, like every other refusal. A
        # second hand-rolled copy of the wire object is the thing envelope.py
        # exists to prevent, and this one is written by the component that has
        # just lost its log, which is the worst place to be improvising a
        # shape.
        from .envelope import withheld

        return [withheld(
            request_id=request_id, reason_code=self.reason, rule="S3",
            accepted=False, status="not_run", inspection_complete=False,
            inspected_utf8_bytes=0, observed_content_bytes=0, elapsed_ms=0,
            rule_ids=(), catalog=frozenset()) for request_id in pending_ids]

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

    def __init__(self, root, *, run_id, header, home=None):
        self.root = pathlib.Path(root) / "receipts"
        self.root.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._failure = None
        self.on_fsync = None
        self._handle = None
        # #172, T9 rulings 11 and 24b. Once the user has run `receipts init` the
        # signed chain IS the log: one chain per run, in the directory beside
        # where its jsonl would have been. The key lives in the sunglasses home
        # and nowhere else; `--state-root` moves the log, never the key. With no
        # key nothing below is imported and the jsonl is what it always was.
        self._chain = _chain_for(self.root / run_id, home)
        self.path = (self.root / run_id if self._chain is not None
                     else self.root / f"{run_id}.jsonl")
        if self._chain is None:
            # OPENED NOW, not on the first event. A log created lazily cannot
            # record a failure that happens before it, which is exactly the
            # window R1 is closing by saying "opened before the first frame".
            self._handle = self.path.open("a", encoding="utf-8")
        self._write_row(dict(header or {}), kind="HEADER")

    # ── writing ─────────────────────────────────────────────────────────────
    def event(self, kind, /, **fields):
        """T901. `kind` is POSITIONAL ONLY, so a caller passing a field of that
        name lands it in `fields` instead of colliding with the discriminator.
        It used to raise TypeError out of the logging path, which is a receipt
        that cannot be written because of what someone tried to record in it.
        The discriminator then wins over the field, in `_write_row`.
        """
        if kind not in EVENTS:
            raise ValueError(
                f"{kind!r} is not an allowlisted receipt event; a log that "
                f"accepts any kind has whatever schema the last caller chose")
        return self._write_row(fields, kind=kind)

    def _write_row(self, fields, *, kind, seal=None):
        if self._chain is not None:
            return self._chain_row(fields, kind=kind, seal=seal)
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
            # T901. The EVENT decides the kind. A `kind` field describes the
            # frame, not the record, and letting it through would let a caller
            # relabel the row it is writing.
            row["kind"] = kind
            try:
                self._handle.write(json.dumps(row, sort_keys=True) + "\n")
                self._handle.flush()
            except OSError as failure:
                # T904. The write itself failing is the case this class exists
                # for, and only a PREVIOUSLY recorded failure was being turned
                # into a ReceiptIOError. A raw OSError escaping here goes
                # straight past `record_or_stop` and out of the caller, so the
                # session never stops and nobody is told the log is gone.
                self._failure = failure
                raise ReceiptIOError(str(failure)) from failure
            self._seq += 1
            return row

    def _chain_row(self, fields, *, kind, seal):
        """The same allowlisted fields, as one chain record. The chain keeps
        the order and the time: `t_mono_ns` is the proxy's clock, an integer,
        and the wall clock is the writer's. Any failure to append, including a
        value the wire refuses, is a receipt failure (R4): it is remembered, and
        every later write stops the session through `record_or_stop`."""
        body = self._clean(fields)
        with self._lock:
            if self._failure is not None:
                raise ReceiptIOError(str(self._failure))
            try:
                self._chain.write([{"event": kind, "body": body,
                                    "t_mono_ns": time.monotonic_ns()}], seal=seal)
            except Exception as failure:
                self._failure = failure
                raise ReceiptIOError(
                    f"the signed receipt could not be written: "
                    f"{type(failure).__name__}") from failure
            self._seq += 1
            return dict(body, seq=self._seq - 1, kind=kind)

    def _clean(self, fields):
        """T9.R3. An allowlist, and provenance reduced to indices and hashes."""
        clean = {}
        for name, value in (fields or {}).items():
            if name in FORBIDDEN_FIELDS or name not in PERMITTED_FIELDS:
                continue
            if name == "leaf_provenance":
                clean[name] = [self._leaf(entry) for entry in value or ()]
                continue
            _check_value(name, value)
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
        if self._chain is not None:
            # Signed as well as durable: a `release` checkpoint seals the
            # authorisation, and the writer fsyncs a checkpoint before it
            # returns, so the signature is on disk before the first byte leaves.
            self._write_row({"id_token": id_token}, kind="RELEASE_AUTHORIZED",
                            seal="release")
        else:
            self.event("RELEASE_AUTHORIZED", id_token=id_token)
        self._fsync()
        return write()

    def _fsync(self):
        try:
            if self.on_fsync is not None:
                self.on_fsync()
            elif self._handle is not None:
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
            if self._chain is not None:
                # WIRE_SPEC: sign at each observed session close, so a session
                # that ended leaves nothing unsigned behind it. A chain that has
                # already failed is not written again.
                if self._failure is None:
                    try:
                        self._chain.close()
                    except Exception as failure:
                        self._failure = failure
                self._chain = _CLOSED
                return
            if not self._handle.closed:
                self._handle.close()


class _Closed:
    """A chained log after `close()`: nothing more is written to it."""

    def write(self, events, *, seal=None):
        raise ReceiptIOError("the receipt log is closed")

    def close(self):
        pass


_CLOSED = _Closed()


def _chain_for(directory, home):
    """The run's chain writer when the user has a key, else None.

    Whether a key exists is one directory listing, so an install without one
    imports none of the signing code. A key that exists and cannot sign is not
    a reason to write unsigned rows (R21, R24b): it is a receipt failure, raised
    here before the session opens, naming the cause and the command that clears
    it."""
    if home is None:
        from ..firewall import sunglasses_home
        home = sunglasses_home()
    home = pathlib.Path(home)
    if not any((home / "keys").glob("receipt-*.ed25519")):
        return None
    from ..receipts import chain, optin
    try:
        signer = optin.signer(home)
    except optin.KeyUnusable as unusable:
        raise ReceiptIOError(str(unusable)) from None
    return chain.Chain(directory, signer, producer="proxy")


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

    # T905. The KINDS were never checked. A row naming an event that does not
    # exist passed the verifier, so a log could carry anything at all under a
    # made-up name and be certified as well formed.
    for row in rows:
        if row.get("kind") not in EVENTS:
            return Verification(
                False, "MALFORMED_RECEIPT",
                f"{row.get('kind')!r} is not an allowlisted receipt event")

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
    # T905. A log that simply stops has no terminal event, and returning ok for
    # it certifies the absence of evidence: a header alone, or a header and an
    # UPSTREAM_CLOSED, describes a session whose ending nobody wrote down. That
    # is precisely the shape a truncated or abandoned log has.
    if not any(row["kind"] in TERMINAL_EVENTS for row in rows):
        return Verification(False, "INCOMPLETE_SESSION",
                            "the log has no terminal event, so how the session "
                            "ended was never recorded")
    return Verification(True)


def write_broken_log(root, how):
    """Build a log with exactly one named defect, for the verifier's tests."""
    path = pathlib.Path(root) / "broken.jsonl"
    base = [{"seq": 0, "mono_ns": 1, "wall": 1.0, "kind": "HEADER"},
            {"seq": 1, "mono_ns": 2, "wall": 1.0, "kind": "ADMITTED",
             "id_token": "a1b2c3d4e5f60718"},
            {"seq": 2, "mono_ns": 3, "wall": 1.0, "kind": "SETTLED",
             "id_token": "a1b2c3d4e5f60718"},
            {"seq": 3, "mono_ns": 4, "wall": 1.0, "kind": "SESSION_TORN_DOWN"}]
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
        base = base[:2]        # ADMITTED with no SETTLED and no ending
    path.write_text("\n".join(json.dumps(row, sort_keys=True) for row in base) + "\n")
    return path
