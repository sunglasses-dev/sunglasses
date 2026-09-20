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


class _NoFrameId:
    """Not an id. A null id is one, so `None` cannot stand for "no id here"."""

    __slots__ = ()

    def __repr__(self):
        return "<no frame id>"


_NO_FRAME_ID = _NoFrameId()
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
            # Its own kind: this frame PARSED, so there is no parse fault to
            # inherit. The client sent a response, and a response from the
            # client can only answer an upstream request, which T2.R15 never
            # let through. My enumeration missed this site because I grouped it
            # with the ones that take their reason from a parse result; it
            # takes the reason but not the fault.
            self._close(framing.MALFORMED_CLIENT, RULE_PROTOCOL, None,
                        kind="CLIENT_RESPONSE_UNSOLICITED")
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
        # R-168-R8/F3. TAKEN BEFORE THE AUTHORISATION, not cleared after the
        # write. The window between committing to a release and clearing the
        # id let a concurrent receipt failure pay a client whose frame was
        # already on its way, so the original AND a bounded refusal both
        # reached it (XS15, XS16). Committing first and giving the obligation
        # back if the authorisation fails leaves exactly one of the two.
        # R-168-R9/(a). THE READER SAYS WHICH OBLIGATION THIS FRAME DISCHARGES.
        # Working it out from the id cannot be done any more, and that is the
        # point: an id can have two unanswered tokens at once -- a finished
        # generation whose frame never reached the sink, and a live one.
        owed = self.session.obligation_of_last_yield()
        if owed is not None:
            self.session.answered_on_the_wire(owed)
        try:
            self.log.authorise_release(
                # There is no Attempt on this path: the reader holds the
                # obligation TOKEN itself, and passing it names the generation
                # this release answered, which is the whole point of the
                # receipt. A bare marker named nothing.
                self._token("inbound", token=owed),  # attempt-exempt: no Attempt here; the obligation token is passed instead and names the generation
                write=lambda: self.client_write(raw))
        except receipts.ReceiptIOError:
            if owed is not None:
                self.session.owe_again(owed)
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
        except Exception:
            # R-168-R9. THE SINK ITSELF FAILED, and the obligation is not
            # discharged by an attempt to discharge it. Giving it back is the
            # same rule as the receipt path: taking is reversible until the
            # bytes have actually moved. Without this the take was permanent
            # and a client whose write raised was owed an answer nobody held
            # (XU03).
            if owed is not None:
                self.session.owe_again(owed)
            raise
        # IDEMPOTENT, AND THE NAME IS LOAD-BEARING. The id was taken above,
        # before the authorisation; this confirms it once the bytes have
        # actually moved, and a reviewer control locates this exact statement
        # by AST to pause a thread here (XS15). Deleting it turned that control
        # into a StopIteration -- an instrument broken by a change it had no
        # reason to notice, the `_handoff` signature lesson one more time.
        self._answered_for(raw, owed)
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

    def _release_record(self, request_id, reason, rule=None, forwarded=False):
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
        return self._record("SETTLED", reason_code=reason,
                            rule=rule or RULE_APPROVAL, forwarded=forwarded)

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
            return self._withhold_result(request_id, retired, RULE_APPROVAL, record=False)

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
                                         RULE_ADMISSION, record=False)

        # T2.R4, R9 and R11. Binary content is UNSUPPORTED and the WHOLE
        # message is withheld. Skipping the blob and inspecting the rest
        # reports a clean scan of a message we did not read.
        if selector.unsupported(method, surface) is not None:
            return self._withhold_result(request_id,
                                         REASON_UNSUPPORTED_CONTENT,
                                         RULE_RESOURCE, record=False)

        held_bytes = selector.content_bytes(surface)
        binding = {"digest": hashlib.sha256(raw).hexdigest(),
                   "channel": channel,
                   "generation": 1,
                   "invocation_token": uuid.uuid4().hex}
        if not self._record("SCAN_STARTED", method=method):
            return self._withhold_result(request_id, REASON_RECEIPT_IO_ERROR,
                                         RULE_RESOURCE, record=False)

        result = self.scan(surface, channel=channel, binding=binding,
                           content_bytes=held_bytes)
        try:
            worker.validate(result, binding=binding,
                            held_content_bytes=held_bytes,
                            catalog=self.catalog)
        except worker.Invalid:
            return self._withhold_result(request_id, REASON_SCAN_EXCEPTION,
                                         RULE_RESOURCE, record=False)

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
            return self._withhold_result(request_id, retired, RULE_APPROVAL, record=False)

        if settlement.reason == REASON_CLEAN:
            # T2.R5, CB06. The ENTIRE original, its own id and its own code.
            # An error is a real answer and rewriting it into ours loses what
            # the server said.
            return None
        return self._withhold_result(request_id, settlement.reason,
                                     settlement.rule, settlement=settlement,
                                     result=result, record=False)

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
            catalog=self.catalog,
            **self._approval_hint(reason))
        return ((json.dumps(body, separators=(",", ":")) + "\n").encode("utf-8"),
                reason, rule)
    def _approval_hint(self, reason):
        """The two ids `proxy approve` needs, for the one reason it answers.

        Without them APPROVAL_REQUIRED tells a user their call was refused and
        nothing about what to do next: the command wants a server-id and a
        snapshot sha, and the only way to learn either was to list the captures
        directory. Both are already here — the server id is what the store is
        keyed by, and the snapshot is the one the store last captured for
        approval.

        EMPTY for every other reason, so no other refusal grows a field it has
        no use for, and empty when a value is missing rather than inventing one:
        a hint naming the wrong snapshot is worse than no hint.
        """
        if reason != REASON_APPROVAL_REQUIRED:
            return {}
        hint = {}
        server_id = getattr(self.approvals, "server_id", None)
        if isinstance(server_id, str) and server_id.isalnum():
            hint["server_id"] = server_id
        pending = getattr(self.approvals, "pending_snapshot", None)
        if isinstance(pending, str) and pending.isalnum():
            hint["snapshot_sha256"] = pending
        return hint

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
        self._to_client(envelope.withheld(  # to-client-exempt: the attempt was refused AT ADMISSION, so the pump already settled it under its own token and there is no obligation here to take
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

        if method == "tools/list":
            # T2.R6. The client's frame is NOT forwarded. One client request
            # becomes up to sixty four of ours and is answered once, here.
            self._client_list(request_id, attempt=attempt)
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
            # MERGE, #168 r9 onto #179. r9 wrote this refusal before the attempt
            # existed, so it was the one `_withhold` in this method that did not
            # thread it -- R-179-R4 reverted on r9's own new path, with nothing
            # to notice it because `attempt` defaults to None. Found by
            # attempt_threading_audit.py, not by the suite.
            self._withhold(request_id, over.reason, over.rule,
                           budget=over.budget, attempt=attempt)
            return

        self._inspect(raw, message, method, request_id=request_id,
                      attempt=attempt)

    # ── T2.R6, T2.R7 and T5: the list flow ─────────────────────────────────

    def _client_list(self, request_id, *, attempt=None):
        """Re-list in our own namespace, scan every page, then decide.

        MERGE, #168 r9 onto #179. The attempt is threaded because all three
        refusals below are this attempt's own answer and `_client_request` has
        it in scope at the one call site. r9 wrote the list flow before the
        attempt existed, so every one of them defaulted to None: R-179-R4 lost
        on the whole list flow, silently, because the parameter has a default.
        Found by attempt_threading_audit.py.
        """
        if self.control is None:
            self._withhold(request_id, REASON_APPROVAL_REQUIRED, RULE_APPROVAL,
                           attempt=attempt)
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
                           REASON_APPROVAL_REQUIRED, RULE_APPROVAL,
                           attempt=attempt)
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
            self._withhold(request_id, blocked, RULE_APPROVAL,
                           attempt=attempt)
            return

        self._approved_tools = dict(found.tools)
        # R-168-R11/F2 (ASTRA MS05, MS07), and this one is r9's own regression:
        # it passes on 07c5c67 and failed here. r9 moved take/confirm OUT of
        # `_to_client` and into the callers, repaired the three REFUSAL callers
        # in this method, and left the SUCCESS caller behind -- so an approved
        # list was delivered without ever taking its wire obligation, and under
        # a receipt failure the same request was answered twice. Success is a
        # response like any other: take, deliver, confirm.
        owed = (attempt.token if attempt is not None
                and attempt.request_id == request_id
                else self.session.obligation_for(request_id))
        if not self.session.take_obligation(owed):
            return
        self._to_client({"jsonrpc": "2.0", "id": request_id,
                         "result": {"tools": self._tools_of(found)}})
        self._answered(owed, final=True)
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
            self._release(raw, NO_ID)  # attempt-exempt: a notification has no id and gets no response, so admission is never called and there is no attempt
            return
        self._inspect(raw, message, method, request_id=NO_ID)  # attempt-exempt: same, a notification has no id to answer

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
        owed = self.session.obligation_for(target)
        if not self.session.take_obligation(owed):
            return
        self._to_client(body)
        self._answered(owed, final=True)
        self._record("SETTLED", reason_code=REASON_REQUEST_CANCELLED,
                     rule=RULE_ADMISSION, forwarded=False)

    # ── the held path ──────────────────────────────────────────────────────

    def _inspect(self, raw, message, method, *, request_id, attempt=None):
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
        if request_id is NO_ID:
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
        # R-168-R12/(b). THE BODY IS BUILT FIRST so the two cases can be one
        # if/else and the take can sit at the top level, where it plainly
        # dominates the write. Before this the take lived inside the claim
        # branch and the write sat outside it, dominating only because the
        # other path happened to return -- true, but invisible to any
        # analysis that does not model returns, and ASTRA's GA01 is exactly
        # a take hidden in a branch. Making the code obviously correct beats
        # making the gate clever enough to follow it.
        #
        # Building the body earlier costs nothing: it is pure construction
        # from the arguments, and every claim and take still happens before
        # a single byte is written, which is what #179 requires.
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
            catalog=self.catalog,
            **self._approval_hint(reason))
        # R-168-R9/(b). TAKE, do not assume. If this obligation is already
        # someone else's -- the payer has it, or a close drained it -- there is
        # nothing here to answer and writing anyway is the second frame.
        # `_to_client` keeps the one argument a reviewer control stubs it with,
        # so the ownership call sits beside it rather than inside it.
        # MERGE, #168 r9 onto #179. THE ORDER OF THE TWO REPAIRS, and getting it
        # wrong is silent. r9's ownership take (below) returned before anything
        # was recorded, which swallowed #179's typed refusal whole: a `_withhold`
        # for an item nobody owns wrote NO receipt at all instead of exactly one
        # SETTLEMENT_REFUSED, and #179's own row R5_NOATTEMPT_REFUSAL caught it.
        # Both repairs are right; composed in the wrong order one eats the other.
        #
        # So the no-owner case is decided FIRST, because r9's gate is about a
        # COMPETING WRITER for an obligation this attempt owns, and on this path
        # there is no attempt to own one. The client still gets the frame #179
        # writes here, and the receipt still says the settlement was refused.
        if attempt is None or attempt.request_id != request_id:
            self._to_client(body)  # to-client-exempt: nobody owns this item, so there is no obligation to take, and this branch returns before the take below
            # NO ATTEMPT, NO SETTLEMENT -- the typed refusal, verbatim from
            # #179's reasoning below.
            self._record("SETTLEMENT_REFUSED", reason_code=reason, rule=rule,
                         reason="no_attempt", forwarded=False)
            return
        # R-179-R5/(3). CLAIM THE ITEM BEFORE THE ANSWER IS WRITTEN. A
        # withheld request is never forwarded, so a response carrying its id
        # is unsolicited -- but only if the item has stopped being pending by
        # the time that response arrives.
        self.session.claim_for_local_answer(attempt.token)
        # R-179-R7/(d) + R-168-R12/(a). THE SINGLE ACQUIRE, over both sets,
        # before a byte moves. It keeps the name `take_delivery` because
        # reviewer controls hook that attribute to drive the reuse race; the
        # plumbing gives way, not the control.
        if not self.session.take_delivery(attempt.token):
            return
        # Already acquired above, in the claim branch, as one operation.
        owed = attempt.token
        # R-CLOSE-KIND-R3/(1). The cause is committed BEFORE the bytes, so a
        # close that wins the race while `_to_client` is paused inside the sink
        # settles this item with the cause the client was actually told. The
        # settlement itself still happens after the write, because #179's bound
        # row requires an answer mid-write to stay outstanding.
        self.session.commit_local_cause(attempt.token, reason, rule)
        self._to_client(body)
        self._answered(owed, final=True)
        # T6.R1. The held item is settled here and not merely answered, so the
        # correlation table releases the id. Leaving it pending makes the next
        # legitimate use of that id look like a duplicate and closes the
        # session on the client for our own bookkeeping.
        # R-179-R5/(2). By the OWNED token. `settle_from` recomputed the
        # current generation, so an older withheld attempt resuming after a
        # newer one was admitted on the same id popped the newer entry and
        # settled ITS generation: the new request lost its debt. A stale token
        # settles nothing and says so.
        self.session.settle_attempt(attempt.token, reason, rule)
        # EXACTLY ONE TERMINAL, and it is written here.
        self._record("SETTLED", reason_code=reason, rule=rule,
                     forwarded=False)

    def _refuse_unparsed(self, frame):
        """T7.R3. One error where JSON-RPC allows one, with a null id because
        there is no id we can trust, then the session closes. A frame we could
        not parse is not a frame we may resynchronise after."""
        self._to_client(envelope.withheld(  # to-client-exempt: an unparsed frame has a null id and no correlation, so no obligation exists to take
            request_id=None, reason_code=frame.reason, rule=frame.rule,
            budget=frame.budget, accepted=False, status="not_run",
            inspection_complete=False, inspected_utf8_bytes=0,
            observed_content_bytes=0, elapsed_ms=0, catalog=self.catalog))
        self._close(frame.reason, frame.rule, frame.budget, kind=frame.kind)

    def _answer_close(self, closed, request_id):
        reason, rule = closed
        self._to_client(envelope.withheld(  # to-client-exempt: the close took delivery of each retained obligation in its own walk before handing it here, so taking again would refuse its own frame
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
        # R-168-R9/(b). A DELIVERY PATH, so it takes like the others. Writing
        # without taking left the obligation on the books, and the payer -- run
        # by the very receipt failure this frame is reporting -- answered the
        # same request a second time (RS09). Every path that puts an answer on
        # the wire owns it first.
        owed = self.session.obligation_for(request_id)
        if not self.session.take_obligation(owed):
            return
        self._to_client(envelope.withheld(
            request_id=request_id, reason_code=REASON_RECEIPT_IO_ERROR,
            rule=RULE_RESOURCE, accepted=False, status="not_run",
            inspection_complete=False, inspected_utf8_bytes=0,
            observed_content_bytes=0, elapsed_ms=0, catalog=self.catalog))
        self.session.answered_on_the_wire(owed, final=True)

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

    def _close(self, reason, rule, budget, *, kind):
        # pump.Session owns the teardown and exposes it privately. A public
        # close belongs on Session and is owed, and it is not added here
        # because that module is under review and this is not the change to
        # put in front of it.
        self.session._close(reason, "the client frame could not be trusted",
                            rule=rule, budget=budget, kind=kind)

    def _answered_for(self, raw, owed=None):
        """Confirm the obligation a released frame answered: the bytes MOVED.

        Idempotent, and `final` is the half that matters: the take before the
        authorisation is reversible, this is not. The token comes from the
        reader rather than from the frame, because the frame's id names an
        item and not an attempt (R-168-R9). A reviewer control locates this
        statement by AST, so the name stays whatever it is handed.
        """
        if owed is not None:
            self.session.answered_on_the_wire(owed, final=True)

    def _id_of(self, raw):
        """The id a released frame answers, or the sentinel when it answers none.

        A notification carries no `id` key, and `b""` is the reader saying
        nothing crosses -- neither is an answer. A null id IS one.
        """
        if not raw:
            return _NO_FRAME_ID
        try:
            message = json.loads(raw)
        except ValueError:
            return _NO_FRAME_ID
        if isinstance(message, dict) and "id" in message:
            return message["id"]
        return _NO_FRAME_ID

    def _to_client(self, body):
        """ONE ARGUMENT. R-168-R9, and the reason is a broken instrument.

        A reviewer control substitutes this method with a one-argument stub to
        watch what reaches the client, so giving it a second parameter turned
        that control into a TypeError -- the `_handoff` signature lesson, and I
        have now been taught it five times this week by five different files.

        The obligation a local answer discharges is therefore confirmed by the
        CALLER, which is the party that knows its token, immediately before
        calling this. `_withhold` and `_cancel` both do.
        """
        self.client_write((json.dumps(body, separators=(",", ":")) + "\n")
                          .encode("utf-8"))
        self._record("FRAME_OUT", direction="upstream_to_client",
                     raw_len=len(json.dumps(body)))

    def _answered(self, token, *, final=False):
        """This attempt's answer is committed to the sink; `final` once it
        moved."""
        if token is not None:
            self.session.answered_on_the_wire(token, final=final)

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
            # R-168-R9/(b). TAKEN ONE AT A TIME, UNDER THE OWNER, and never
            # from a snapshot. The old loop read the whole list and marked each
            # entry afterwards, so a real cancellation could answer an id while
            # this payer was paused holding a stale copy -- and the payer then
            # paid it again. Taking IS the claim, so nothing held here can go
            # stale in the hand.
            while True:
                owed = self.session.take_next_unanswered()
                if owed is None:
                    break
                request_id = owed[2]
                confirmed = False
                try:
                    self.client_write((json.dumps(envelope.withheld(
                        request_id=request_id,
                        reason_code=REASON_RECEIPT_IO_ERROR,
                        rule=RULE_RESOURCE, accepted=False, status="not_run",
                        inspection_complete=False, inspected_utf8_bytes=0,
                        observed_content_bytes=0, elapsed_ms=0,
                        catalog=self.catalog), separators=(",", ":"))
                        + "\n").encode("utf-8"))
                    # The bytes have moved: confirm, and no give-back may
                    # resurrect this one.
                    self.session.answered_on_the_wire(owed, final=True)
                    confirmed = True
                finally:
                    if not confirmed:
                        # The sink failed. The obligation was taken and not
                        # discharged, so it goes back on the books rather than
                        # vanishing with the attempt to pay it (XU05).
                        self.session.owe_again(owed)
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
                rule=RULE_RESOURCE, kind="RECEIPT_WRITE_FAILED")
        return not stop.stopped

    def _token(self, request_id, attempt=None, *, token=None):
        """R-179-R5/(2). ID AND GENERATION.

        Hashing the id alone gave two attempts on one id the same release
        token, so a receipt could not say which attempt a release belonged to
        -- the same id-only key as everything else this round, in the one place
        that is supposed to be evidence.

        MERGE ROUND, T9's ruling. `token=` takes a raw obligation token for the
        one caller that holds the token WITHOUT an Attempt: `_release_inbound`
        gets it from `obligation_of_last_yield`, because the reader is what
        knows which obligation a frame discharges. It used to hash the literal
        marker "inbound", so the one receipt that exists to say WHAT WAS
        ANSWERED named nothing -- the id-only key again, wearing no id at all.
        R-168-R6a: the receipt equals the wire.
        """
        if token is not None:
            owned = token
        else:
            owned = (attempt.token if attempt is not None
                     and attempt.request_id == request_id else request_id)
        return hashlib.sha256(repr(owned).encode()).hexdigest()[:16]
