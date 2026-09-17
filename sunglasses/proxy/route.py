"""The client direction, and the thing that finally calls the parts.

Written against `tests/test_proxy_route.py`, committed first from the rows.

Every decision here was already built and none of it was wired. The selector
knows the channel and the two accountings, the worker validates, the policy
settles, the envelope carries only what T4.R7 names, the receipt log makes a
release durable before the bytes move. This module is the order they happen in,
and the order IS the security property: a proxy whose parts each pass their own
tests while nothing drives them forwards every payload it was installed to
hold. That was found in this lane on 2026-09-13 at five components.

So the shape below is deliberately boring. One entry point, one pass per frame,
and every exit either releases the ORIGINAL bytes or writes an envelope, never
both and never neither. The original bytes are forwarded rather than a
re-serialisation, because a proxy that rebuilds the frame it forwards is a
proxy that can change it, and the client sent the bytes it sent.

The gates fail closed. No approval store means no approval. A receipt that
cannot be written stops the release rather than being mentioned afterwards. A
worker result that cannot be believed is S3 SCAN_EXCEPTION and never a verdict,
because "not obviously bad" is not a scan.
"""
from __future__ import annotations

import hashlib
import json
import uuid

from . import envelope, framing, inspection, policy, receipts, selector, worker

CLIENT = "client"
REQUEST = "request"

REASON_APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
REASON_SCAN_EXCEPTION = "SCAN_EXCEPTION"
REASON_UNINSPECTED_METHOD = "UNINSPECTED_METHOD"
REASON_RECEIPT_IO_ERROR = "RECEIPT_IO_ERROR"
REASON_CLEAN = "CLEAN"

RULE_ADMISSION = "S1"
RULE_RESOURCE = "S3"
RULE_APPROVAL = "S4"
RULE_PROTOCOL = "S5"


class Route:
    """One MCP client on stdin, one mediated server on the other side."""

    def __init__(self, *, session, log, upstream_write, client_write,
                 scan=None, catalog=None, approvals=None,
                 descriptor_sha_for=None):
        self.session = session
        self.log = log
        self.upstream_write = upstream_write
        self.client_write = client_write
        # The real adapter by default. A route whose scan has to be supplied
        # is a route that does nothing on its own, and the default being a test
        # double is how a suite goes green over a product that never scanned.
        self.scan = scan if scan is not None else inspection.scan
        self.catalog = (frozenset(catalog) if catalog is not None
                        else inspection.trusted_catalog())
        self.approvals = approvals
        self.descriptor_sha_for = descriptor_sha_for or (lambda name: None)

    # ── one frame from the client ──────────────────────────────────────────

    def client_frame(self, raw):
        if self.session.closed_with():
            return
        frame = framing.parse_frame(raw, origin=CLIENT)
        if not self._record("FRAME_IN", direction="client_to_upstream",
                            raw_len=frame.bytes,
                            raw_sha256=hashlib.sha256(raw).hexdigest()):
            return
        if not frame.ok:
            self._refuse_unparsed(frame)
            return

        message = frame.message
        method = message.get("method")
        if method is None:
            # A response arriving from the client correlates to an upstream
            # REQUEST, which T2.R15 never let through, so there is nothing it
            # can be an answer to.
            self._close(framing.MALFORMED_CLIENT, RULE_PROTOCOL, None)
            return

        if "id" in message:
            self._client_request(raw, message, method)
        else:
            self._client_notification(raw, message, method)

    def _withhold_refusal(self, request_id, attempt):
        """The answer to an admission that was REFUSED, and nothing else.

        R-179-R4, and the difference from `_withhold` is the whole point.
        `_withhold` ends with `settle_from(CLIENT, request_id, ...)`, which
        retires whatever is pending under that ID. For an item that WAS
        admitted that is exactly right. For a refusal it is a live grenade: a
        refused attempt and a later admitted attempt share the id, so the
        earlier attempt's answer retired the later attempt's real request --
        ASTRA's XR03_OWNER, where the live item ended neither owed nor
        answerable.

        A refused attempt has nothing of its own to settle here. The pump
        already settled the refused attempt's own core key, under its own
        reserved generation, when it reported the refusal. So this writes the
        client's answer and the receipt, and touches no table.
        """
        cause = attempt.cause if attempt is not None else None
        reason, rule = ((cause.reason, cause.rule) if cause is not None
                        else (REASON_UNINSPECTED_METHOD, RULE_ADMISSION))
        self._record("SETTLED", reason_code=reason, rule=rule, forwarded=False)
        self._to_client(envelope.withheld(
            request_id=request_id, reason_code=reason, rule=rule,
            accepted=False, status="not_run", inspection_complete=False,
            inspected_utf8_bytes=0, observed_content_bytes=0, elapsed_ms=0,
            catalog=self.catalog))

    # ── requests ───────────────────────────────────────────────────────────

    def _client_request(self, raw, message, method):
        request_id = message["id"]

        # R-179-R4. THE ATTEMPT CARRIES ITS OWN ANSWER. `refusal` is a local
        # in this call, so nothing else can read it and no later attempt on the
        # same id can overwrite it -- which is what three rounds of a table
        # keyed by the id kept producing.
        refusal = []
        admitted = []
        if not self.session.admit_request(request_id, method=method,
                                          origin="client",
                                          on_refusal=refusal.append,
                                          on_attempt=admitted.append):
            closed = self.session.closed_with()
            if closed:
                self._answer_close(closed, request_id)
            else:
                self._withhold_refusal(request_id, refusal[0] if refusal
                                       else None)
            return
        # R-179-R5. THE ATTEMPT THIS CALL OWNS, as a LOCAL and never on the
        # instance. Parking it on `self` looks equivalent and is the same bug
        # one level up: a second `client_frame` for the same id overwrites it,
        # and an older call resuming mid-write then settles the NEWER attempt's
        # item. Measured -- the newer request lost its debt and the older one
        # kept it. It travels as a parameter from here to every settlement and
        # every release token.
        attempt = admitted[0] if admitted else None
        self._record("ADMITTED", id_type=type(request_id).__name__)

        # T2.R14. Zero inspectable leaves is COMPLETE for these shapes only, so
        # they are forwarded without a scan rather than sent to a worker to
        # inspect nothing on a clock that can still expire.
        if selector.zero_leaves_is_complete(method, message):
            self._release(raw, request_id, attempt=attempt)
            return

        # T2.R16 AFTER T2.R14, because a named row beats the fallback: `ping`
        # is advertised by T1.R3 and has no channel of its own, so the selector
        # table has no row for it and asking the fallback first would refuse a
        # method the contract advertises. Everything the selector has no row
        # for and R14 does not name is refused here, which is fail closed and
        # keeps it away from upstream either way.
        if selector.refusal(method, REQUEST, origin=CLIENT) is not None:
            self._withhold(request_id, REASON_UNINSPECTED_METHOD, RULE_ADMISSION,
                           attempt=attempt)
            return

        if method == "tools/call":
            blocked = self._approval_reason(message)
            if blocked is not None:
                # T5.R2. Before any scan, because a call we may not make is not
                # a call whose contents are interesting.
                self._withhold(request_id, blocked, RULE_APPROVAL,
                               attempt=attempt)
                return

        self._inspect(raw, message, method, request_id=request_id,
                      attempt=attempt,
                      is_request=True)

    # ── notifications ──────────────────────────────────────────────────────

    def _client_notification(self, raw, message, method):
        """T2.R13. A notification has no response, whatever we decide about it,
        so the only two outcomes are forwarded or dropped with a receipt."""
        if selector.refusal(method, REQUEST, origin=CLIENT) is not None:
            self._record("SETTLED", reason_code=REASON_UNINSPECTED_METHOD,
                         rule=RULE_ADMISSION, forwarded=False)
            return
        if selector.zero_leaves_is_complete(method, message):
            self._release(raw, None)
            return
        self._inspect(raw, message, method, request_id=None, is_request=False)

    # ── the held path ──────────────────────────────────────────────────────

    def _inspect(self, raw, message, method, *, request_id, is_request,
                 attempt=None):
        channel = selector.channel_for(method, REQUEST)
        params = message.get("params")
        params = params if isinstance(params, (dict, list)) else {}
        held_bytes = selector.content_bytes(params)

        binding = {
            "digest": hashlib.sha256(raw).hexdigest(),
            "channel": channel,
            "generation": 1,
            "invocation_token": uuid.uuid4().hex,
        }
        # T9.R2 names `kind` on this event and on FRAME_IN/OUT, and it cannot
        # be passed: `Log.event(self, kind, **fields)` takes the EVENT in a
        # parameter of that name, so `kind="request"` is a TypeError rather
        # than a field. Reported rather than worked around in receipts.py,
        # which is under review.
        if not self._record("HOLD_ENTERED"):
            return
        if not self._record("SCAN_STARTED", method=method):
            return

        # The INSPECTED SURFACE, not the frame. T2's client rows all name
        # `params`, and handing the scan the whole message would inspect our
        # own envelope and the id we are correlating on.
        result = self.scan(params, channel=channel, binding=binding,
                           content_bytes=held_bytes)
        try:
            worker.validate(result, binding=binding,
                            held_content_bytes=held_bytes,
                            catalog=self.catalog)
        except worker.Invalid:
            # T4.R2. A result we cannot believe is a fact about the scan, never
            # a verdict about the message, and reading an incoherent allow as
            # allow is how a scan that found the thing forwards it anyway.
            self._settle_withheld(request_id, REASON_SCAN_EXCEPTION,
                                  RULE_RESOURCE, attempt=attempt)
            return

        # T4.R4(7) takes a DESCRIPTOR of the held message, not the message.
        # Handing it the raw frame makes `direction` and `is_request` absent,
        # the direction test false, and every outbound secret settles as the
        # weaker PROHIBITED_CONTENT while still looking blocked.
        # A REQUEST IS A FRAME WITH AN `id` MEMBER, and `null` is a value that
        # member can hold. This read `request_id is not None`, so a tools/call
        # carrying `"id": null` -- which the caller reached through
        # `if "id" in message` and treated as a request in every other respect
        # -- was described here as a notification, and an engine secret heading
        # out in it settled as the weaker PROHIBITED_CONTENT. The kind is
        # decided by the caller that already knows it, not re-derived from a
        # value that cannot tell absent from null.
        held = {"direction": REQUEST,
                "is_request": is_request,
                "method": method}
        settlement = policy.settle(result, held=held,
                                   held_content_bytes=held_bytes)
        self._record("SCAN_RESULT", accepted=settlement.accepted,
                     status=settlement.status,
                     inspection_complete=settlement.inspection_complete,
                     rule_ids=[r for r in settlement.rule_ids
                               if r in self.catalog],
                     inspected_bytes=result.get("inspected_utf8_bytes", 0),
                     observed_bytes=result.get("observed_content_bytes", 0))

        if settlement.reason == REASON_CLEAN:
            self._release(raw, request_id, attempt=attempt)
            return
        self._settle_withheld(request_id, settlement.reason, settlement.rule,
                              attempt=attempt, settlement=settlement,
                              result=result)

    # ── the two exits ──────────────────────────────────────────────────────

    def _release(self, raw, request_id, *, attempt=None):
        """T9.R2. The authorisation is durable BEFORE the first original byte
        leaves, so there is no moment where the payload is gone and the record
        of letting it go is not there."""
        try:
            self.log.authorise_release(self._token(request_id, attempt),
                                       write=lambda: self.upstream_write(raw))
        except receipts.ReceiptIOError:
            self._receipt_failure(request_id)
            return
        self._record("WRITE_COMPLETE", bytes=len(raw))
        self._record("SETTLED", reason_code=REASON_CLEAN, rule=RULE_ADMISSION,
                     forwarded=True)

    def _settle_withheld(self, request_id, reason, rule, *, attempt=None,
                         settlement=None,
                         result=None):
        if request_id is None:
            # T2.R13. Dropped with a receipt, and no acknowledgement, because a
            # notification has no response to put one in.
            self._record("SETTLED", reason_code=reason, rule=rule,
                         forwarded=False)
            return
        self._withhold(request_id, reason, rule, attempt=attempt,
                       settlement=settlement,
                       result=result)

    def _withhold(self, request_id, reason, rule, *, attempt=None,
                  settlement=None, result=None, budget=None):
        # R-179-R5/(3). CLAIM THE ITEM BEFORE THE ANSWER IS WRITTEN. A withheld
        # request is never forwarded, so a response carrying its id is
        # unsolicited -- but only if the item has stopped being pending by the
        # time that response arrives. Claiming after the write left a window in
        # which upstream could answer a request it had never seen.
        if attempt is not None and attempt.request_id == request_id:
            self.session.claim_for_local_answer(attempt.token)
        result = result or {}
        body = envelope.withheld(
            request_id=request_id,
            reason_code=reason,
            rule=rule,
            budget=budget,
            accepted=bool(settlement.accepted) if settlement else False,
            status=settlement.status if settlement else "not_run",
            inspection_complete=(bool(settlement.inspection_complete)
                                 if settlement else False),
            inspected_utf8_bytes=result.get("inspected_utf8_bytes", 0),
            observed_content_bytes=result.get("observed_content_bytes", 0),
            elapsed_ms=result.get("elapsed_ms", 0),
            rule_ids=settlement.rule_ids if settlement else (),
            catalog=self.catalog)
        self._to_client(body)
        # T6.R1. The held item is settled here and not merely answered, so the
        # correlation table releases the id. Leaving it pending makes the next
        # legitimate use of that id look like a duplicate and closes the
        # session on the client for our own bookkeeping.
        # R-179-R5/(2). By the OWNED token. `settle_from` recomputed the
        # current generation, so an older withheld attempt resuming after a
        # newer one was admitted on the same id popped the newer entry and
        # settled ITS generation: the new request lost its debt. A stale token
        # settles nothing and says so.
        if attempt is not None and attempt.request_id == request_id:
            self.session.settle_attempt(attempt.token, reason, rule)
        else:
            # NO ATTEMPT, NO SETTLEMENT. Every caller of `_withhold` now
            # carries the attempt it is answering, so reaching this line means
            # an answer is being written for an item nobody owns -- and the old
            # fallback settled it BY ID, which is the defect this round exists
            # to remove. A typed refusal says so instead of guessing which
            # generation was meant. R-179-R5.
            self._record("SETTLED", reason_code=reason, rule=rule,
                         forwarded=False)
        self._record("SETTLED", reason_code=reason, rule=rule, forwarded=False)

    def _refuse_unparsed(self, frame):
        """T7.R3. One error where JSON-RPC allows one, with a null id because
        there is no id we can trust, then the session closes. A frame we could
        not parse is not a frame we may resynchronise after."""
        self._to_client(envelope.withheld(
            request_id=None, reason_code=frame.reason, rule=frame.rule,
            budget=frame.budget, accepted=False, status="not_run",
            inspection_complete=False, inspected_utf8_bytes=0,
            observed_content_bytes=0, elapsed_ms=0, catalog=self.catalog))
        self._close(frame.reason, frame.rule, frame.budget)

    def _answer_close(self, closed, request_id):
        reason, rule = closed
        self._to_client(envelope.withheld(
            request_id=None, reason_code=reason, rule=rule, accepted=False,
            status="not_run", inspection_complete=False,
            inspected_utf8_bytes=0, observed_content_bytes=0, elapsed_ms=0,
            catalog=self.catalog))

    def _receipt_failure(self, request_id):
        """T9.R4. Best effort, bounded, and never claimed durable, because it is
        being sent by something that has just discovered it cannot write
        anything down."""
        if request_id is None:
            return
        self._to_client(envelope.withheld(
            request_id=request_id, reason_code=REASON_RECEIPT_IO_ERROR,
            rule=RULE_RESOURCE, accepted=False, status="not_run",
            inspection_complete=False, inspected_utf8_bytes=0,
            observed_content_bytes=0, elapsed_ms=0, catalog=self.catalog))

    # ── plumbing ───────────────────────────────────────────────────────────

    def _approval_reason(self, message):
        """No store is no approval. A gate that opens when its authority is
        missing is not a gate."""
        if not self.approvals:
            return REASON_APPROVAL_REQUIRED
        params = message.get("params")
        name = params.get("name") if isinstance(params, dict) else None
        return self.approvals.may_call(name, self.descriptor_sha_for(name))

    def _close(self, reason, rule, budget):
        # pump.Session owns the teardown and exposes it privately. A public
        # close belongs on Session and is owed, and it is not added here
        # because that module is under review and this is not the change to
        # put in front of it.
        self.session._close(reason, "the client frame could not be trusted",
                            rule=rule, budget=budget)

    def _to_client(self, body):
        self.client_write((json.dumps(body, separators=(",", ":")) + "\n")
                          .encode("utf-8"))
        self._record("FRAME_OUT", direction="upstream_to_client",
                     raw_len=len(json.dumps(body)))

    def _record(self, event, **fields):
        """Every receipt goes through here so a log that cannot be written
        stops the session rather than being noticed later.

        The parameter is `event` and not `kind` because `kind` is one of the
        allowlisted FIELDS, and a signature that shadows a field name makes the
        call that passes it a TypeError rather than a receipt.
        """
        stop = self.log.record_or_stop(event, **fields)
        return not stop.stopped

    def _token(self, request_id, attempt=None):
        """R-179-R5/(2). ID AND GENERATION.

        Hashing the id alone gave two attempts on one id the same release
        token, so a receipt could not say which attempt a release belonged to
        -- the same id-only key as everything else this round, in the one place
        that is supposed to be evidence.
        """
        owned = (attempt.token if attempt is not None
                 and attempt.request_id == request_id else request_id)
        return hashlib.sha256(repr(owned).encode()).hexdigest()[:16]
