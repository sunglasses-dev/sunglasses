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
import pathlib
import uuid

from . import (activation, bounds, envelope, framing, inspection, policy,
               receipts, selector, snapshot, worker)

CLIENT = "client"
UPSTREAM = "upstream"
REQUEST = "request"
RESULT = "result"

REASON_APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
REASON_SCAN_EXCEPTION = "SCAN_EXCEPTION"
REASON_UNINSPECTED_METHOD = "UNINSPECTED_METHOD"
REASON_UNSUPPORTED_CONTENT = "UNSUPPORTED_CONTENT"
REASON_REQUEST_CANCELLED = "REQUEST_CANCELLED"
REASON_DESCRIPTOR_CHANGED = "DESCRIPTOR_CHANGED"
REASON_RECEIPT_IO_ERROR = "RECEIPT_IO_ERROR"
REASON_CLEAN = "CLEAN"


class _NoId:
    """The absence of an id, which is NOT the id `null`.

    T1.R2 makes null a legal JSON-RPC id, so `{"id": null, "method": ...}` is a
    REQUEST owed exactly one response, while a frame with no `id` member at all
    is a notification owed none. Both arrive in Python as None, and using None
    for the second meant every null-id call was settled as a notification: no
    refusal, no answer, and a client left waiting on a request the contract
    says it must be answered. A sentinel keeps the two apart.
    """

    def __repr__(self):
        return "<no id>"


NO_ID = _NoId()


def _typed(request_id):
    """T6.R6's identity, for the sets this module keeps: the JSON type is part
    of it, so `"1"` and `1` are different held items here too."""
    return (type(request_id).__name__, request_id)

RULE_ADMISSION = "S1"
RULE_RESOURCE = "S3"
RULE_APPROVAL = "S4"
RULE_PROTOCOL = "S5"


class Route:
    """One MCP client on stdin, one mediated server on the other side."""

    def __init__(self, *, session, log, upstream_write, client_write,
                 scan=None, catalog=None, approvals=None,
                 descriptor_sha_for=None, control=None, server_identity=None):
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
        # R-168-R6/F2. THE CLIENTS THIS ROUTE STILL OWES A FRAME, by id.
        #
        # RETIREMENT IS NOT ANSWERING, and that distinction is the finding. On
        # the release paths the pump has already retired the record when
        # authorisation fails, so the session has nothing owed to retain and
        # the client -- who has received no bytes at all -- is owed an answer
        # nobody is holding. An id leaves this set when a frame is actually
        # WRITTEN for it, which is the only event that means answered.
        self._paying = False
        # T2.R6's re-list runs through this. None means no control channel is
        # wired, and a tools/list is then refused rather than forwarded: the
        # client asked us, and handing its request to the server unread is the
        # one answer this row never permits.
        self.control = control
        self.server_identity = server_identity
        self.page_scan = self._scan_page
        self._approved_tools = {}
        self._activated = False
        self._activated_sha = None
        # T5.R4 and T6.R5, the two things that can retire a held item while its
        # answer is still in flight. Kept on the session because ONE authority
        # decides whether a result may be released, and a check that lives in
        # the middle of the release path is a check the next release path
        # forgets to make.
        self._cancelled = set()
        self._invalidated_reason = None

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

    # ── the upstream direction ─────────────────────────────────────────────

    def pump_upstream(self, stream):
        """Every frame the client is allowed to see, and nothing else.

        This is the half people mean by mediation. A request carries what the
        user asked for; a RESULT carries whatever the server decided to say
        back, which is where an injection arrives from a poisoned document or a
        compromised server. Inspecting only the outbound direction reads the
        letters you send and none of the letters you receive.
        """
        for raw in self.session.read_upstream(stream,
                                              inspect=self._inspect_result,
                                              gate=(self._release_gate,
                                                    self._release_frame,
                                                    self._release_record)):
            self._release_inbound(raw)

    def _release_inbound(self, raw):
        """AR08. T9.R2 applies in BOTH directions.

        A frame going to the client is as irreversible as one going upstream:
        once the model has read it, no later receipt can unsay it. The outbound
        release was authorised and made durable before its bytes moved and this
        one was not, so half the wire had an audit trail and half did not, and
        the half without it is the half that carries what a compromised server
        said.
        """
        try:
            self.log.authorise_release(self._token("inbound"),
                                       write=lambda: self.client_write(raw))
        except receipts.ReceiptIOError:
            # T9.R4. A release that cannot be recorded does not happen, and the
            # session stops rather than continuing to mediate with nothing
            # written down.
            #
            # R-168-R6/F2. THE COMMENT THAT USED TO SIT HERE WAS FALSE, and
            # the reviewer measured it: it said the party that knows whose
            # answer it is had already sent the bounded error, and on these
            # executions nobody had. `_release_frame` only pays when the BUILD
            # fails; authorisation failing here happens after a successful
            # build, with the record already retired, and the client had
            # received nothing at all.
            #
            # The refusal is keyed on ownership rather than on this call
            # failing, so the frame that already crossed is not answered twice
            # and a notification -- which owns no id -- borrows nobody's.
            self._record("SETTLED", reason_code=REASON_RECEIPT_IO_ERROR,
                         rule=RULE_RESOURCE, forwarded=False)
            self._pay_bounded_refusals()
            return
        self._answered_for(raw)
        self._record("WRITE_COMPLETE", bytes=len(raw))

    def _release_barrier(self, request_id):
        """The ONE question asked before any held answer is released.

        Cancellation and invalidation both retire an item while its answer is
        still in flight, and both were checked nowhere. Asking them here, once,
        is the difference between a rule and a habit: a second release path
        added later inherits the check instead of forgetting it.
        """
        # R-168-R4a. READ FROM THE SESSION, which is the one place authority
        # lives and the one place it is written under a lock. A route-local
        # copy read here and written there is two sources for one fact, which
        # is how this lane spent three rounds.
        _, invalidated = self.session.authority_state()
        if request_id is not NO_ID and self.session.cancellation_accepted(
                request_id, origin=CLIENT):
            return REASON_REQUEST_CANCELLED
        if invalidated:
            return REASON_DESCRIPTOR_CHANGED
        return None

    @property
    def _invalidated(self):
        return self._invalidated_reason

    @_invalidated.setter
    def _invalidated(self, reason):
        """Setting this attribute IS accepting the authority (R-168-R4a).

        A property rather than a method because the attribute is what the
        reviewer's controls assign -- `rt._invalidated = 'DESCRIPTOR_CHANGED'`
        is how an invalidation is driven in four of them -- and an acceptance
        that only happens when someone remembers to call a method is an
        acceptance that a later caller will forget. Recording it here means
        every way of setting it, ours or a control's, bumps the epoch the
        reader validates against.
        """
        self._invalidated_reason = reason
        if reason is not None:
            self.session.accept_invalidation(reason)

    def _release_gate(self, request_id):
        """R-168-R3/R4a. The release barrier, asked again AT THE HANDOFF.

        THE NAME IS LOAD-BEARING. Reviewer controls wrap this attribute to
        drive a close from inside the decision (XC01 does exactly that and
        measures whether the settlement owner blocks the close while it runs).
        Renaming it to `_release_decision` when the frame building moved out
        turned three of those rows from PASS into ERROR -- an instrument broken
        by a rename, which is the same lesson as the `_handoff` signature.
        This returns a DECISION only; `_release_frame` builds the frame.

        `_release_barrier` is asked once in `_inspect_result`, which runs
        BEFORE the scan -- and the scan is where the time goes. A cancellation
        or a descriptor invalidation that completed during it was therefore
        being judged against a question asked before it happened, and the
        original crossed anyway. ASTRA's instrument pauses the reader on the
        yield line itself and completes the action there; on the previous head
        the original (or, with a finding, the PROHIBITED_CONTENT refusal)
        still went to the client instead of REQUEST_CANCELLED or
        DESCRIPTOR_CHANGED.

        Returns None to let the crossing through unchanged, or the bytes that
        replace it. `b""` is a legitimate answer meaning nothing crosses.

        Called by the pump INSIDE the settlement critical section, so the
        decision and the discharge of the obligation are one step. It builds a
        frame and writes a receipt; it does not settle in the core, because the
        item was settled when it left `_pending` and T6.R1 allows exactly one
        answer -- this REPLACES the frame, it does not add one.
        """
        if request_id is NO_ID:
            return None
        # R-168-R6/F1. THE ADAPTER, and the name is why it is still here. This
        # attribute is wrapped by reviewer controls and its calls are COUNTED
        # (XE02_rederive_writer asserts exactly two), so the decision it
        # returns had to become reachable from somewhere that is not a call to
        # it -- the retirement re-derives after a writer lands during the
        # fallible frame build, which is a third derivation that may not be a
        # third gate call. The policy moved to the session, where every input
        # it reads already lives; this is not a copy of it.
        #
        # XB04 lives there now with the rest: a recorded S3 fault is terminal
        # and no authority overrides it, so a cancellation arriving after a
        # scan fault cannot replace SCAN_EXCEPTION on the wire while the core
        # keeps it in the receipt.
        return self.session.release_decision(request_id, origin=CLIENT)

    def _release_frame(self, request_id, reason):
        """The frame for a decision already taken, built OUTSIDE the owner.

        This is where the receipt is written, and that is why it is out here:
        a failed write answers by calling `Session._close`, which takes the
        settlement lock the reader was holding while it decided. XB06 reached
        that deadlock with the log's fail-writes seam.

        R-168-R5. XB06 PASSING MEANS NO DEADLOCK, NOT ONE ANSWER DELIVERED.
        With the deadlock gone the receipt failure took the answer with it:
        the write below closes the session, the reader hands over nothing, and
        `_release_inbound` refuses to release anything it cannot authorise --
        so the client got zero frames for a request it is still blocked on
        (XD03). The bounded refusal is sent from HERE because this is the
        frame's owner and the only party that still knows whose answer it was:
        `_release_inbound` holds bytes with no id, and a second bounded error
        raised down there would be the second answer T6.R1 forbids.

        Best effort and never claimed durable, which is all a component that
        has just lost its log may claim.
        """
        # R-168-R7. PURE, AND IT KEEPS ITS NAME. Reviewer controls wrap this
        # attribute to drive a writer during preparation (XE02_frame_cancel,
        # XE02_rederive_writer), so it stays the thing called once per build --
        # but building is all it does now. A superseded decision leaves no
        # trace in the receipt stream, because it is not a settlement: the item
        # settles once, `_release_record` writes that once, and a reader
        # counting SETTLED rows per item counts what the wire carried.
        frame, _, _ = self._withhold_result(request_id, reason, RULE_APPROVAL,
                                            record=False)
        return frame if frame is not None else b""

    def _release_record(self, request_id, reason):
        """The FALLIBLE half, once, after the decision can no longer move.

        R-168-R7. Called by the pump when the obligation has been retired under
        `_authority_lock`, so the answer this records is the answer that
        crosses. It is the half that can fail, and a failure here is covered by
        the ownership payer: the id is still unanswered on the wire until its
        frame reaches the sink, whatever the record did.

        Returns False when the receipt could not be written, in which case
        nothing may cross -- the client's one answer is then the bounded
        refusal the payer has already sent.
        """
        return self._record("SETTLED", reason_code=reason, rule=RULE_APPROVAL,
                            forwarded=False)

    def _inspect_result(self, raw, message):
        """None to deliver the original, or (replacement, reason, rule).

        Called by the pump BEFORE it settles, so whatever this returns is the
        item's first and only outcome.
        """
        # `"id" in message` and not `.get`, because null IS an id: a result
        # correlated to a null-id request is a response, and reading it as a
        # notification loses the client's one answer.
        request_id = message["id"] if "id" in message else NO_ID
        is_response = request_id is not NO_ID
        method = (self.session.expected_method(request_id, origin=CLIENT)
                  if is_response else message.get("method"))
        if not method:
            return None

        if method == "notifications/tools/list_changed":
            # T5.R4. The descriptors moved, so every undelivered result of this
            # generation is now an answer from a server nobody approved.
            self._invalidated = REASON_DESCRIPTOR_CHANGED
            self._activated = False
            self._approved_tools = {}
            if self.approvals:
                try:
                    self.approvals.invalidate()
                except Exception:
                    pass

        retired = self._release_barrier(request_id)
        if retired is not None and is_response:
            return self._withhold_result(request_id, retired, RULE_APPROVAL)

        surface, channel = self._surface(message, method)
        if surface is None:
            return None

        # T2.R14 BEFORE everything else, exactly as in the client direction.
        # A ping result has zero inspectable leaves and no channel of its own,
        # so scanning it means handing a worker nothing to read on a channel
        # that does not exist, and every rule is scoped to a channel.
        if selector.zero_leaves_is_complete(method, surface):
            return None

        if channel is None:
            # The selector has no row for this result. Fail closed: a scan on
            # a null channel runs no rule at all and reports a clean pass.
            return self._withhold_result(request_id,
                                         REASON_UNINSPECTED_METHOD,
                                         RULE_ADMISSION)

        # T2.R4, R9 and R11. Binary content is UNSUPPORTED and the WHOLE
        # message is withheld. Skipping the blob and inspecting the rest
        # reports a clean scan of a message we did not read.
        if selector.unsupported(method, surface) is not None:
            return self._withhold_result(request_id,
                                         REASON_UNSUPPORTED_CONTENT,
                                         RULE_RESOURCE)

        held_bytes = selector.content_bytes(surface)
        binding = {"digest": hashlib.sha256(raw).hexdigest(),
                   "channel": channel,
                   "generation": 1,
                   "invocation_token": uuid.uuid4().hex}
        if not self._record("SCAN_STARTED", method=method):
            return self._withhold_result(request_id, REASON_RECEIPT_IO_ERROR,
                                         RULE_RESOURCE)

        result = self.scan(surface, channel=channel, binding=binding,
                           content_bytes=held_bytes)
        try:
            worker.validate(result, binding=binding,
                            held_content_bytes=held_bytes,
                            catalog=self.catalog)
        except worker.Invalid:
            return self._withhold_result(request_id, REASON_SCAN_EXCEPTION,
                                         RULE_RESOURCE)

        # An inbound result is not an outbound call, so T4.R4(7)'s direction
        # test is false here and a finding settles PROHIBITED_CONTENT. Saying
        # SECRET on an arriving message would describe an exfiltration that did
        # not happen.
        held = {"direction": RESULT, "is_request": False, "method": method}
        settlement = policy.settle(result, held=held,
                                   held_content_bytes=held_bytes)
        self._record("SCAN_RESULT", accepted=settlement.accepted,
                     status=settlement.status,
                     inspection_complete=settlement.inspection_complete,
                     rule_ids=[r for r in settlement.rule_ids
                               if r in self.catalog])
        # THE BARRIER IS ASKED AGAIN, and the second asking is the point.
        #
        # It was asked once, before the scan, and never after -- so a
        # cancellation or a `list_changed` that landed WHILE the scan ran was
        # not seen, and the original crossed. That is the one window where it
        # matters: the scan is the part that takes time, so it is where a
        # descriptor change or a cancel is most likely to arrive, and an answer
        # released after either one is an answer nobody is entitled to any
        # more. Asked here, after the scan returns and before anything is
        # handed back to the pump.
        retired = self._release_barrier(request_id)
        if retired is not None and is_response:
            return self._withhold_result(request_id, retired, RULE_APPROVAL)

        if settlement.reason == REASON_CLEAN:
            # T2.R5, CB06. The ENTIRE original, its own id and its own code.
            # An error is a real answer and rewriting it into ours loses what
            # the server said.
            return None
        return self._withhold_result(request_id, settlement.reason,
                                     settlement.rule, settlement=settlement,
                                     result=result)

    def _surface(self, message, method):
        """The inspected surface and its channel, per T2's result rows."""
        for member in ("result", "error", "params"):
            if member in message:
                surface = message[member]
                if not isinstance(surface, (dict, list)):
                    return None, None
                return surface, selector.channel_for(method, RESULT)
        return None, None

    def _withhold_result(self, request_id, reason, rule, *, settlement=None,
                         result=None, record=True):
        """One answer in the client's own typed id, or nothing at all when the
        thing withheld was a notification.

        R-168-R7. `record=False` builds the BYTES and writes nothing. The
        result direction re-derives its answer when authority moves during
        preparation, so the build may run more than once for one item -- and a
        SETTLED row per build is a second terminal for an item that settles
        once. The caller records separately, after the decision is final.
        """
        if record:
            self._record("SETTLED", reason_code=reason, rule=rule,
                         forwarded=False)
        if request_id is NO_ID:
            return (None, reason, rule)
        result = result or {}
        body = envelope.withheld(
            request_id=request_id, reason_code=reason, rule=rule,
            accepted=bool(settlement.accepted) if settlement else False,
            status=settlement.status if settlement else "not_run",
            inspection_complete=(bool(settlement.inspection_complete)
                                 if settlement else False),
            inspected_utf8_bytes=result.get("inspected_utf8_bytes", 0),
            observed_content_bytes=result.get("observed_content_bytes", 0),
            elapsed_ms=result.get("elapsed_ms", 0),
            rule_ids=settlement.rule_ids if settlement else (),
            catalog=self.catalog)
        return ((json.dumps(body, separators=(",", ":")) + "\n").encode("utf-8"),
                reason, rule)

    # ── requests ───────────────────────────────────────────────────────────

    def _client_request(self, raw, message, method):
        request_id = message["id"]

        if not self.session.admit_request(request_id, method=method,
                                          origin="client"):
            closed = self.session.closed_with()
            if closed:
                self._answer_close(closed, request_id)
            else:
                self._withhold(request_id, REASON_UNINSPECTED_METHOD,
                               RULE_ADMISSION)
            return
        self._record("ADMITTED", id_type=type(request_id).__name__)

        # T2.R14. Zero inspectable leaves is COMPLETE for these shapes only, so
        # they are forwarded without a scan rather than sent to a worker to
        # inspect nothing on a clock that can still expire.
        if selector.zero_leaves_is_complete(method, message):
            self._release(raw, request_id)
            return

        if method == "tools/list":
            # T2.R6. The client's frame is NOT forwarded. One client request
            # becomes up to sixty four of ours and is answered once, here.
            self._client_list(request_id)
            return

        # T2.R16 AFTER T2.R14, because a named row beats the fallback: `ping`
        # is advertised by T1.R3 and has no channel of its own, so the selector
        # table has no row for it and asking the fallback first would refuse a
        # method the contract advertises. Everything the selector has no row
        # for and R14 does not name is refused here, which is fail closed and
        # keeps it away from upstream either way.
        if selector.refusal(method, REQUEST, origin=CLIENT) is not None:
            self._withhold(request_id, REASON_UNINSPECTED_METHOD, RULE_ADMISSION)
            return

        if method == "tools/call":
            blocked = self._approval_reason(message)
            if blocked is not None:
                # T5.R2. Before any scan, because a call we may not make is not
                # a call whose contents are interesting.
                self._withhold(request_id, blocked, RULE_APPROVAL)
                return

        # AR09, T8.R2. The content bound is a bound on CONTENT, not on the
        # direction it happens to be travelling. It was applied to results and
        # not to calls, so a client request carrying more than the cap went to
        # the worker and then to the server: the limit that exists to stop an
        # unbounded scan was reachable by sending the bytes the other way.
        #
        # Refused BEFORE inspection, because the point of the bound is that the
        # scan never runs on that much input.
        over = bounds.check_content(
            selector.content_bytes(message.get("params") or {}))
        if over:
            self._withhold(request_id, over.reason, over.rule,
                           budget=over.budget)
            return

        self._inspect(raw, message, method, request_id=request_id)

    # ── T2.R6, T2.R7 and T5: the list flow ─────────────────────────────────

    def _client_list(self, request_id):
        """Re-list in our own namespace, scan every page, then decide."""
        if self.control is None:
            self._withhold(request_id, REASON_APPROVAL_REQUIRED, RULE_APPROVAL)
            return
        outcome = activation.activate(
            self.approvals,
            list_pages=self._pager(),
            scan=self.page_scan,
            server_identity=self.server_identity or getattr(
                self.approvals, "server_id", None))

        if not outcome.activated:
            # T5.R2. The provenance travels: APPROVAL_REQUIRED describes a
            # server nobody approved, DESCRIPTOR_CHANGED one that moved, and a
            # scan reason describes what its descriptors carried. Collapsing
            # them would tell an operator the wrong thing to do next.
            self._withhold(request_id, outcome.provenance or
                           REASON_APPROVAL_REQUIRED, RULE_APPROVAL)
            return

        found = outcome.snapshot
        # T2.R7's gate, and it is defence in depth rather than a second
        # decision: a successful activation has already committed this exact
        # sha as the active snapshot, so this can only refuse if the store
        # moved between the two calls. The mutation that removes it is
        # therefore equivalent on every reachable path, which is written down
        # here rather than left as an open survivor in a mutation report.
        blocked = self.approvals.may_deliver_list(found.sha256)
        if blocked is not None:
            self._withhold(request_id, blocked, RULE_APPROVAL)
            return

        self._approved_tools = dict(found.tools)
        self._to_client({"jsonrpc": "2.0", "id": request_id,
                         "result": {"tools": self._tools_of(found)}})
        # T6.R1. Delivering the answer is not settling the item. Left pending,
        # the teardown still owes this id a refusal and the client receives a
        # SECOND answer to a request it has already had answered, which is the
        # one thing the row forbids in either direction.
        self.session.settle_from(CLIENT, request_id, REASON_CLEAN,
                                 RULE_APPROVAL)
        self._record("SETTLED", reason_code=REASON_CLEAN, rule=RULE_APPROVAL,
                     forwarded=False)

    def _pager(self):
        from .control import ControlTimeout

        pager = self.control.pager("tools/list")

        def request(cursor):
            try:
                return pager(cursor)
            except ControlTimeout:
                # A server that stops answering is not a short tool list. The
                # collector reads this as an unusable page and refuses, and
                # T8.R13 never activates a prefix.
                return None
        return request

    @staticmethod
    def _tools_of(found):
        tools = []
        for page in found.pages:
            tools.extend(page.get("tools") or [])
        return tools

    def _scan_page(self, page):
        """T5.R3(c). Every page, on the api_response channel it arrived on."""
        binding = {"digest": hashlib.sha256(
                       json.dumps(page, sort_keys=True).encode()).hexdigest(),
                   "channel": selector.API_RESPONSE,
                   "generation": 1,
                   "invocation_token": uuid.uuid4().hex}
        held = selector.content_bytes(page)
        result = self.scan(page, channel=selector.API_RESPONSE,
                           binding=binding, content_bytes=held)
        try:
            worker.validate(result, binding=binding, held_content_bytes=held,
                            catalog=self.catalog)
        except worker.Invalid:
            return {"accepted": False, "status": "exception",
                    "inspection_complete": False, "decision": "review",
                    "findings": [], "check_pin": "error"}
        return dict(result, check_pin=self._pin_outcome(page))

    def _pin_outcome(self, page):
        """T1.R1's helper adaptation for `check_pin`, over one page of tools.

        The adapter converts the helper's own return into an explicit outcome
        rather than reading None as "nothing to say": None from an applicable
        helper is `clean`, a deny is `deny`, an ask is `ask`, and an exception
        is `error`. T5.R3(c) then requires clean for every tool, so an ask
        holds the activation rather than passing it.

        The name is QUALIFIED before the call, per T1.R1: `check_pin` ignores
        anything that is not `mcp__<server>__<tool>`, so handing it a bare wire
        name would make every tool non-applicable and return None, and reading
        THAT as clean is the exact misreading the row names.
        """
        from .. import firewall

        try:
            pins = firewall.load_pins(self._pin_path())
            worst = "clean"
            for tool in page.get("tools") or []:
                name = tool.get("name")
                if not isinstance(name, str):
                    return "error"
                # The SAME id the store pinned under. Qualifying with a
                # different one makes every lookup miss and every tool read as
                # unpinned, which is an "ask" that looks exactly like a server
                # nobody has seen before.
                qualified = "mcp__%s__%s" % (self._server_short(), name)
                decision = firewall.check_pin(qualified, tool, pins)
                if decision is None:
                    continue
                action = getattr(decision, "action", None)
                if action == "deny":
                    return "deny"
                worst = "ask"
            return worst
        except Exception:
            return "error"

    def _server_short(self):
        return str(getattr(self.approvals, "server_id", None)
                   or self.server_identity or "server")[:8]

    def _pin_path(self):
        root = getattr(self.approvals, "root", None)
        return pathlib.Path(root or ".") / "pins.json"

    # ── notifications ──────────────────────────────────────────────────────

    def _client_notification(self, raw, message, method):
        """T2.R13. A notification has no response, whatever we decide about it,
        so the only two outcomes are forwarded or dropped with a receipt."""
        if selector.refusal(method, REQUEST, origin=CLIENT) is not None:
            self._record("SETTLED", reason_code=REASON_UNINSPECTED_METHOD,
                         rule=RULE_ADMISSION, forwarded=False)
            return
        if method == "notifications/cancelled":
            # T6.R5. Honoured, not merely forwarded. The id is retired BEFORE
            # any release, the client gets its one answer now, and the late
            # result is discarded rather than delivered to a caller that has
            # already been told the request is over.
            self._cancel(message)
            return
        if selector.zero_leaves_is_complete(method, message):
            self._release(raw, NO_ID)
            return
        self._inspect(raw, message, method, request_id=NO_ID)

    def _cancel(self, message):
        params = message.get("params")
        target = params.get("requestId") if isinstance(params, dict) else None
        if target is None and not (isinstance(params, dict)
                                   and "requestId" in params):
            return
        self._cancelled.add(_typed(target))
        # R-168-R4a. Accepted in the session, under ITS lock, so a reader
        # parked at the handoff sees the epoch move and re-derives. The writer
        # never waits on that reader.
        self.session.accept_cancellation(target, origin=CLIENT)
        self._record("CANCEL_ACCEPTED", id_type=type(target).__name__)
        if self.session.is_settling(target, origin=CLIENT):
            # R-168-R3. The item has left `_pending` and its answer is in the
            # reader's hands, NOT the client's. Settling it here would be the
            # second answer T6.R1 forbids, and returning early -- which is what
            # the `expects` test below used to do -- treated it as already
            # delivered and let the original cross. The cancellation is
            # recorded (above) and stays AUTHORITATIVE: `_release_gate` turns
            # the crossing into this client's one answer at the handoff.
            return
        if not self.session.expects(target, origin=CLIENT):
            return
        # session.cancel TOMBSTONES the id, which is the part that matters:
        # without it the late result arrives for an id nothing is waiting on,
        # the pump reads that as unsolicited and closes MALFORMED_UPSTREAM, and
        # the client is told its cancelled request failed on a protocol fault.
        # T6.R5 calls a late answer to a cancelled id DISCARDED_LATE, and the
        # session stays serviceable.
        self.session.cancel(target, origin=CLIENT)
        body = envelope.withheld(
            request_id=target, reason_code=REASON_REQUEST_CANCELLED,
            rule=RULE_ADMISSION, accepted=False, status="cancelled",
            inspection_complete=False, inspected_utf8_bytes=0,
            observed_content_bytes=0, elapsed_ms=0, catalog=self.catalog)
        self._to_client(body)
        self._record("SETTLED", reason_code=REASON_REQUEST_CANCELLED,
                     rule=RULE_ADMISSION, forwarded=False)

    # ── the held path ──────────────────────────────────────────────────────

    def _inspect(self, raw, message, method, *, request_id):
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
                                  RULE_RESOURCE)
            return

        # T4.R4(7) takes a DESCRIPTOR of the held message, not the message.
        # Handing it the raw frame makes `direction` and `is_request` absent,
        # the direction test false, and every outbound secret settles as the
        # weaker PROHIBITED_CONTENT while still looking blocked.
        held = {"direction": REQUEST,
                "is_request": request_id is not NO_ID,
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
            self._release(raw, request_id)
            return
        self._settle_withheld(request_id, settlement.reason, settlement.rule,
                              settlement=settlement, result=result)

    # ── the two exits ──────────────────────────────────────────────────────

    def _release(self, raw, request_id):
        """T9.R2. The authorisation is durable BEFORE the first original byte
        leaves, so there is no moment where the payload is gone and the record
        of letting it go is not there."""
        try:
            self.log.authorise_release(self._token(request_id),
                                       write=lambda: self.upstream_write(raw))
        except receipts.ReceiptIOError:
            self._receipt_failure(request_id)
            return
        self._record("WRITE_COMPLETE", bytes=len(raw))
        self._record("SETTLED", reason_code=REASON_CLEAN, rule=RULE_ADMISSION,
                     forwarded=True)

    def _settle_withheld(self, request_id, reason, rule, *, settlement=None,
                         result=None):
        if request_id is NO_ID:
            # T2.R13. Dropped with a receipt, and no acknowledgement, because a
            # notification has no response to put one in.
            self._record("SETTLED", reason_code=reason, rule=rule,
                         forwarded=False)
            return
        self._withhold(request_id, reason, rule, settlement=settlement,
                       result=result)

    def _withhold(self, request_id, reason, rule, *, settlement=None,
                  result=None, budget=None):
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
        self.session.settle_from(CLIENT, request_id, reason, rule)
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
        if request_id is NO_ID:
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
        self._activate_once()
        # The descriptor sha comes from the snapshot this session ACTIVATED,
        # not from an argument a caller supplies. T5.R2 admits a call when the
        # tool's descriptor matches the approved one, and a sha handed in from
        # outside would let the caller answer the question being asked.
        known = self._approved_tools.get(name) if name else None
        return self.approvals.may_call(name,
                                       known or self.descriptor_sha_for(name))

    def _activate_once(self):
        """T5.R3's activation, run on the first admission rather than at the
        literal first frame.

        The row says at session start. Doing it on the first call that needs it
        is equivalent for the property that matters, since no call is admitted
        before a committed activation either way, and it avoids listing a
        server for a client that only ever pings. The deviation is written here
        rather than left for a reader to infer from the absence of a call in
        serve.py.
        """
        if self.control is None or not self.approvals:
            return
        if self._activated and self._activated_sha == self._record_sha():
            # Activated already, against the record that is still on disk.
            return
        # T5.R3 says at session start AND whenever the approval record changes
        # on disk. Both halves matter and both were missing. Without the retry,
        # a session that started before a human approved anything never
        # notices the approval and refuses for ever. Without the re-read, a
        # record edited underneath us keeps admitting calls against a snapshot
        # nobody approved any more, which is the revocation doing nothing.
        self._activated = True
        self._activated_sha = self._record_sha()
        self._approved_tools = {}
        outcome = activation.activate(
            self.approvals, list_pages=self._pager(), scan=self.page_scan,
            server_identity=self.server_identity or getattr(
                self.approvals, "server_id", None))
        if outcome.activated:
            self._approved_tools = dict(outcome.snapshot.tools)
        else:
            self._invalidated = (outcome.provenance
                                 if outcome.provenance == REASON_DESCRIPTOR_CHANGED
                                 else self._invalidated)

    def _record_sha(self):
        """What the approval record on DISK says right now.

        Read every time rather than cached, because the whole point of a
        revocation is that it happens without asking us.
        """
        try:
            record, bad = self.approvals._record_or_reason()
        except Exception:
            return None
        if bad or record is None:
            return None
        return record.get("snapshot_sha256")

    def _close(self, reason, rule, budget):
        # pump.Session owns the teardown and exposes it privately. A public
        # close belongs on Session and is owed, and it is not added here
        # because that module is under review and this is not the change to
        # put in front of it.
        self.session._close(reason, "the client frame could not be trusted",
                            rule=rule, budget=budget)

    def _answered_for(self, raw):
        """Clear the id a released frame answers, if it answers one.

        A notification carries none, and `b""` is the reader saying nothing
        crosses -- neither is an answer and neither clears anybody.
        """
        if not raw:
            return
        try:
            message = json.loads(raw)
        except ValueError:
            return
        if isinstance(message, dict) and "id" in message:
            self._answered(message["id"])

    def _to_client(self, body):
        if isinstance(body, dict) and body.get("id") is not None:
            self._answered(body["id"])
        self.client_write((json.dumps(body, separators=(",", ":")) + "\n")
                          .encode("utf-8"))
        self._record("FRAME_OUT", direction="upstream_to_client",
                     raw_len=len(json.dumps(body)))

    def _answered(self, request_id):
        """A frame for this id has actually reached the sink."""
        self.session.answered_on_the_wire(request_id)

    def _pay_bounded_refusals(self):
        """One bounded RECEIPT_IO_ERROR to every client still owed a frame.

        R-168-R6/F2. T9.R4's answer, finally given on every path rather than
        one. A receipt failure anywhere -- the scan events, the first
        settlement, the release authorisation, the fsync inside it -- used to
        end with the session closed and, for most of those sites, ZERO frames
        for a client still blocked on its request. The close could not help:
        the record had already been retired, so there was no obligation to
        retain, and `_release_inbound` will not release what it cannot
        authorise.

        NOT A BLANKET REFUSAL ON EVERY FAILURE, which the reviewer names as the
        wrong fix. It pays what is OWED and nothing else, so a failure to
        record completion AFTER a frame has crossed pays nobody
        (XE03_receipt_WRITE_COMPLETE_*), and an id paid once is never paid
        twice however many later writes fail.

        Written straight to the sink: no receipt, no authorisation, never
        claimed durable. It is being sent by a component that has just
        discovered it cannot write anything down.
        """
        if self._paying:
            # `_to_client` records, a record fails, and the failure lands back
            # here. The flag makes the second pass a drop rather than a
            # recursion -- and these frames go out through `client_write`
            # directly for the same reason.
            return
        self._paying = True
        try:
            for request_id in self.session.unanswered_clients():
                self.session.answered_on_the_wire(request_id)
                self.client_write(
                    (json.dumps(envelope.withheld(
                        request_id=request_id,
                        reason_code=REASON_RECEIPT_IO_ERROR,
                        rule=RULE_RESOURCE, accepted=False, status="not_run",
                        inspection_complete=False, inspected_utf8_bytes=0,
                        observed_content_bytes=0, elapsed_ms=0,
                        catalog=self.catalog), separators=(",", ":"))
                     + "\n").encode("utf-8"))
        finally:
            self._paying = False

    def _record(self, event, **fields):
        """Every receipt goes through here so a log that cannot be written
        stops the session rather than being noticed later.

        The parameter is `event` and not `kind` because `kind` is one of the
        allowlisted FIELDS, and a signature that shadows a field name makes the
        call that passes it a TypeError rather than a receipt.
        """
        stop = self.log.record_or_stop(event, **fields)
        if stop.stopped:
            # RS08 and RS09. The docstring above has said this since the slice
            # that wrote it and the code only ever RETURNED the fact. A log
            # that cannot be written is a session that is mediating with
            # nothing written down, and T9.R4 does not let that continue: a
            # caller who checks the return value stops one step, and every
            # caller who does not carries on with no record at all.
            #
            # `_close` is idempotent on the session, so the first failed
            # receipt decides the cause and the ones that follow it -- there
            # are always several, because a failed log fails every write --
            # cannot relabel it.
            # R-168-R6/F2. PAY FIRST, then close. The close records what the
            # SESSION still owes; this pays what the CLIENT is still owed, and
            # on the release paths those are not the same set -- the record is
            # retired by then and the client has had nothing.
            self._pay_bounded_refusals()
            self.session._close(
                REASON_RECEIPT_IO_ERROR,
                "the receipt log could not be written, so the session cannot "
                "say what it did",
                rule=RULE_RESOURCE)
        return not stop.stopped

    @staticmethod
    def _token(request_id):
        return hashlib.sha256(repr(request_id).encode()).hexdigest()[:16]
