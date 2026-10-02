"""The harness may only emit an event the PRODUCT emits, and only as it does.

T8 measured the product on main `1e4e526` and the answer decided this row:

    UPSTREAM_CLOSED       a receipt kind, emitted at sunglasses/proxy/session.py
    REQUEST_RECEIVED      NOT a record. ADMITTED and FRAME_IN carry an id type,
                          not an origin
    DESCRIPTOR_CHANGED    an envelope reason_code in proxy/approvals.py, retired
                          through `_retire()`. Never written as a record
    APPROVAL_INVALIDATED  changes state in proxy/pump.py and emits NOTHING
                          (true on 1e4e526; #263 made it a durable record,
                          written by `Route._invalidated` when the upstream's
                          tools/list_changed arrives, so it is mirrored too)

Verified here by importing `sunglasses.proxy.receipts.EVENTS` rather than by
reading the report, because a citation is a claim until the set says so.

So two of the four are mirrored now. Inventing the other two in
`SUPPORTED_EVENTS` would make the adapter the author of the scenario's meaning,
which is the sentence the whole refusal is built on.
"""
import io
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


def test_the_product_records_two_of_the_four_and_not_the_other_two():
    """The premise of this whole row, asserted rather than cited."""
    from sunglasses.proxy import receipts

    assert "UPSTREAM_CLOSED" in receipts.EVENTS
    assert "APPROVAL_INVALIDATED" in receipts.EVENTS
    for absent in ("REQUEST_RECEIVED", "DESCRIPTOR_CHANGED"):
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


# ── APPROVAL_INVALIDATED, mirrored after #263 ────────────────────────────────
#
# No delivered variant can drive a relist through this adapter yet (G2-19's
# two list_changed variants need `answer_relist`, which it refuses whole), so
# the control drives `passthrough.serve` directly with an upstream that says
# exactly one thing. The record has to appear on the upstream's list_changed
# and on nothing else, or the mirror is either missing or inventing.

from proxy import passthrough                                  # noqa: E402

LIST_CHANGED = {"jsonrpc": "2.0", "method": "notifications/tools/list_changed"}
OTHER_NOTE = {"jsonrpc": "2.0", "method": "notifications/message",
              "params": {"level": "info", "data": "hello"}}


def _serve_once(tmp_path, *, upstream_says=None, client_says=None):
    """One run: the upstream writes its line(s) (if any), then waits for EOF."""
    says = ([] if not upstream_says else
            upstream_says if isinstance(upstream_says, list) else [upstream_says])
    lines = "".join(json.dumps(m) + "\n" for m in says)
    upstream = [sys.executable, "-c",
                "import sys\n"
                f"lines = {lines!r}\n"
                "if lines:\n"
                "    sys.stdout.write(lines); sys.stdout.flush()\n"
                "sys.stdin.read()\n"]
    client = (json.dumps(client_says) + "\n").encode() if client_says else b""
    out = io.BytesIO()
    receipts = tmp_path / "receipts.jsonl"
    passthrough.serve(upstream, [sys.executable, "-c", "pass"],
                      receipts=receipts, stdin=io.BytesIO(client), stdout=out)
    events = [json.loads(l) for l in receipts.read_text().splitlines()
              if l.strip()]
    return events, out.getvalue()


def test_the_upstreams_list_changed_is_recorded_as_the_product_records_it(tmp_path):
    events, delivered = _serve_once(tmp_path, upstream_says=LIST_CHANGED)
    revoked = [e for e in events if e["kind"] == "APPROVAL_INVALIDATED"]
    assert len(revoked) == 1, [e["kind"] for e in events]
    # The product's reason, not a harness word for it.
    assert revoked[0]["reason_code"] == "DESCRIPTOR_CHANGED", revoked[0]
    # The notification itself still reaches the client: the record is added,
    # nothing is taken away.
    assert json.loads(delivered.decode().splitlines()[0]) == LIST_CHANGED
    # It crossed the boundary first, so the record follows real ingress.
    ingress = [e["seq"] for e in events if e["kind"] == "RPC_INGRESS"
               and "list_changed" in e.get("raw", "")]
    assert ingress and ingress[0] < revoked[0]["seq"], events
    # ONCE PER SESSION. Measured on the product (real Route.pump_upstream,
    # signed chain read from disk): 1, 2 and 3 list_changed each leave exactly
    # 1 durable APPROVAL_INVALIDATED, because an invalidated session drops later
    # notifications before they reach the setter. A mirror that records every
    # repeat says something the product never wrote.
    again = tmp_path / "twice"
    again.mkdir()
    events, _ = _serve_once(again, upstream_says=[LIST_CHANGED, LIST_CHANGED])
    kinds = [e["kind"] for e in events]
    assert kinds.count("APPROVAL_INVALIDATED") == 1, kinds
    # And the once is spent by list_changed only: another notification first
    # must not use it up.
    later = tmp_path / "other_first"
    later.mkdir()
    events, _ = _serve_once(later, upstream_says=[OTHER_NOTE, LIST_CHANGED])
    kinds = [e["kind"] for e in events]
    assert kinds.count("APPROVAL_INVALIDATED") == 1, kinds


def test_no_revoke_record_without_the_upstreams_list_changed(tmp_path):
    """The other half, so the mirror cannot quietly fire on every note."""
    for kwargs in ({"upstream_says": OTHER_NOTE},
                   {"client_says": LIST_CHANGED},
                   {}):
        run = tmp_path / str(len(list(tmp_path.iterdir())))
        run.mkdir()
        events, _ = _serve_once(run, **kwargs)
        assert not [e for e in events if e["kind"] == "APPROVAL_INVALIDATED"], (
            kwargs, [e["kind"] for e in events])



# ── the other half of the revoke: an invalidated session forwards nothing ───
#
# MEASURED on the product (real Route.pump_upstream, `T10_MIRROR_DROPS` receipt,
# measure_drops.py): after the first upstream list_changed every LATER upstream
# notification is dropped, whatever its method, and exactly 1 frame is ever
# delivered (1/1/1 for 1, 2 and 3 list_changed). The drop is an in-session
# NOTIFICATION_DROPPED (supported=True, reason_code=DESCRIPTOR_CHANGED), which is
# in `receipts.EVENTS`. Notifications BEFORE the list_changed are delivered, and
# only the upstream's side is gated: nothing here touches the client's own
# notifications (a cancellation still has to reach the upstream).
#
# A mirror that records the revoke and keeps forwarding says "this session is
# revoked" and then behaves as if it were not, which is worse than saying nothing.

PROGRESS = {"jsonrpc": "2.0", "method": "notifications/progress",
            "params": {"progressToken": "t", "progress": 1}}
CANCELLED = {"jsonrpc": "2.0", "method": "notifications/cancelled",
             "params": {"requestId": 7}}


def _methods(delivered):
    return [json.loads(line)["method"]
            for line in delivered.decode().splitlines() if line.strip()]


def test_the_product_premise_for_the_drop_is_asserted_not_cited():
    from sunglasses.proxy import receipts

    assert "NOTIFICATION_DROPPED" in receipts.EVENTS


@pytest.mark.parametrize("later", [[LIST_CHANGED], [LIST_CHANGED, LIST_CHANGED],
                                   [OTHER_NOTE], [PROGRESS], [CANCELLED],
                                   [OTHER_NOTE, PROGRESS, LIST_CHANGED]],
                         ids=["lc", "lc-lc", "message", "progress", "cancelled",
                              "message-progress-lc"])
def test_after_the_revoke_no_later_upstream_notification_is_forwarded(tmp_path, later):
    """The control that fails when forwarding returns. 1/1/1 on the product."""
    events, delivered = _serve_once(tmp_path, upstream_says=[LIST_CHANGED, *later])
    assert _methods(delivered) == ["notifications/tools/list_changed"], (
        f"{len(_methods(delivered))} frames crossed an invalidated session: "
        f"{_methods(delivered)}")
    # Not silently: each one is on the record, with the product's reason.
    dropped = [e for e in events if e["kind"] == "NOTIFICATION_DROPPED"]
    assert len(dropped) == len(later), [e["kind"] for e in events]
    assert all(e["reason_code"] == "DESCRIPTOR_CHANGED" and e["supported"] is True
               for e in dropped), dropped
    # After the revoke record, never before it.
    revoked = next(e for e in events if e["kind"] == "APPROVAL_INVALIDATED")
    assert all(e["seq"] > revoked["seq"] for e in dropped), events


def test_nothing_is_dropped_before_the_revoke(tmp_path):
    """So the drop cannot be a mirror that swallows notifications from the start."""
    events, delivered = _serve_once(tmp_path,
                                    upstream_says=[OTHER_NOTE, PROGRESS, LIST_CHANGED])
    assert _methods(delivered) == ["notifications/message",
                                   "notifications/progress",
                                   "notifications/tools/list_changed"]
    assert not [e for e in events if e["kind"] == "NOTIFICATION_DROPPED"], events
    alone = tmp_path / "alone"
    alone.mkdir()
    events, delivered = _serve_once(alone, upstream_says=[OTHER_NOTE])
    assert _methods(delivered) == ["notifications/message"]
    assert not [e for e in events if e["kind"] == "NOTIFICATION_DROPPED"], events


class _After:
    """A client stdin that says nothing until the harness has written the revoke,
    then sends one notification, then hangs up. The only way to put a CLIENT frame
    strictly after the invalidation without racing the pump."""

    def __init__(self, receipts, line):
        self._receipts, self._line, self._sent = receipts, line, False

    def read(self, _n):
        import time
        if self._sent:
            return b""
        deadline = time.time() + 10
        while time.time() < deadline:
            if self._receipts.exists() and "APPROVAL_INVALIDATED" in \
                    self._receipts.read_text():
                self._sent = True
                return self._line
            time.sleep(0.02)
        # HANG UP, never raise. An exception here dies inside the pump thread,
        # the upstream's stdin is then never closed, and `serve` blocks forever:
        # a broken mirror would hang the suite instead of failing it (measured on
        # the drop-from-start mutant, which ate the 30 minutes it was given).
        # Hanging up lets the test fail on its own assertion, in 10 s.
        self._sent = True
        return b""


def test_the_drop_is_the_upstreams_direction_only(tmp_path):
    """A client notification sent after the revoke still reaches the upstream.
    The product's gate is on `pump_upstream`; dropping this side too would eat a
    cancellation, which is the frame that has to get through."""
    seen = tmp_path / "upstream_stdin.txt"
    client_note = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    upstream = [sys.executable, "-c",
                "import sys, time\n"
                f"sys.stdout.write({json.dumps(LIST_CHANGED) + chr(10)!r}); sys.stdout.flush()\n"
                f"open({str(seen)!r}, 'w').write(sys.stdin.read())\n"]
    receipts = tmp_path / "receipts.jsonl"
    out = io.BytesIO()
    passthrough.serve(upstream, [sys.executable, "-c", "pass"], receipts=receipts,
                      stdin=_After(receipts, (json.dumps(client_note) + "\n").encode()),
                      stdout=out)
    events = [json.loads(l) for l in receipts.read_text().splitlines() if l.strip()]
    assert json.loads(seen.read_text().splitlines()[0]) == client_note, seen.read_text()
    assert not [e for e in events if e["kind"] == "NOTIFICATION_DROPPED"], events
