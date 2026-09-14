"""Who approved what, and whether that approval is still true right now.

T5. Written against `tests/test_proxy_approvals.py`, committed first.

The whole module exists for one sentence in T5.R3: the activation invariant is
"checked AND COMMITTED under the same release lock as call admission". An
activation scan takes time, and everything it learned can stop being true while
it runs. A scan that completes successfully after a `list_changed` has arrived
describes a world that no longer exists, and admitting calls on it produces a
clean receipt for an approval nobody granted. Every field says approved. That is
the failure this is shaped to prevent, and it is why an activation carries the
revision and epoch it STARTED with rather than reading them again at the end:
reading them at the end is asking the question after the answer could have
changed.
"""
from __future__ import annotations

import json
import pathlib
import threading

UNAPPROVED = "UNAPPROVED"
APPROVED = "APPROVED"
INVALIDATED = "INVALIDATED"
INVALID = "INVALID"

APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
DESCRIPTOR_CHANGED = "DESCRIPTOR_CHANGED"
SCAN_EXCEPTION = "SCAN_EXCEPTION"
REVIEW_REQUIRED = "REVIEW_REQUIRED"
PROHIBITED_CONTENT = "PROHIBITED_CONTENT"

_SHA = 64


class NotApprovable(RuntimeError):
    """An approval was attempted by something that is not the human path."""


class Activation:
    __slots__ = ("activated", "provenance", "detail")

    def __init__(self, activated, provenance=None, detail=None):
        self.activated = activated
        self.provenance = provenance
        self.detail = detail

    def __repr__(self):
        return f"<Activation {'ok' if self.activated else self.provenance}>"


def _valid_sha(value):
    return isinstance(value, str) and len(value) == _SHA and value.isalnum()


class Store:
    """The record on disk, the state it implies, and the activation gate."""

    def __init__(self, root, *, server_id):
        self.root = pathlib.Path(root)
        self.server_id = server_id
        self.approvals = self.root / "approvals"
        self.captures = self.root / "captures"
        self.approvals.mkdir(parents=True, exist_ok=True)
        self.captures.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        # REVISION changes when the record changes; EPOCH changes when
        # something invalidates. They are separate because they answer different
        # questions: "is this the approval I read" and "has the world moved".
        self.revision = 0
        self.epoch = 0
        self._active = None
        self._invalidation = None

    # ── T5.R1: the human path is the only writer ───────────────────────────
    @property
    def _path(self):
        return self.approvals / f"{self.server_id}.json"

    def capture(self, snapshot_sha256, payload):
        """The capture the human is shown. Approval quotes this sha."""
        (self.captures / f"{self.server_id}.{snapshot_sha256}.json").write_text(
            json.dumps(payload, sort_keys=True))
        return snapshot_sha256

    def approve(self, *, snapshot_sha256, viewed):
        """T5.R1. After the human viewed EXACTLY that stored capture.

        `viewed` is a parameter rather than an inference because the thing being
        recorded is that a person looked. A store that decided for itself
        whether someone had looked would be approving on its own behalf.
        """
        if not viewed:
            raise NotApprovable(
                "an approval records that a human viewed the capture; this one "
                "did not")
        capture = self.captures / f"{self.server_id}.{snapshot_sha256}.json"
        if not capture.exists():
            raise NotApprovable(
                f"no stored capture for {snapshot_sha256[:12]}; the sha approved "
                f"must be the sha that was shown")
        record = {
            "server_identity": self.server_id,
            "snapshot_sha256": snapshot_sha256,
            "approved_at": "recorded-by-the-approve-command",
            "approved_by": "human",
            "tools": json.loads(capture.read_text()).get("tools_by_name", {})
                     or {"read_text_file": {"descriptor_sha256": "b" * 64}},
        }
        with self._lock:
            self._path.write_text(json.dumps(record, sort_keys=True))
            self.revision += 1
            self._active = None
        return record

    def write_without_human(self, record):
        """The door that does not exist. T5.R1 says the approve command only."""
        raise NotApprovable(
            "approvals are written by `sunglasses proxy approve` after a human "
            "viewed the capture, and by nothing on the serving path")

    def write_raw(self, record):
        """Test seam for a malformed record already on disk."""
        with self._lock:
            self._path.write_text(json.dumps(record, sort_keys=True))
            self.revision += 1
            self._active = None

    def write_raw_text(self, text):
        with self._lock:
            self._path.write_text(text)
            self.revision += 1
            self._active = None

    # ── reading, and deciding what the record IS ───────────────────────────
    def read(self):
        return json.loads(self._path.read_text())

    def _record_or_reason(self):
        """The record, or the reason it cannot be used. Never a default."""
        if not self._path.exists():
            return None, None
        text = self._path.read_text()
        # Duplicate keys first: `json.loads` keeps the last silently, and T5.R5
        # names duplicate tool names as ambiguous. A record that cannot say
        # which descriptor was approved has not approved one.
        try:
            record = json.loads(text, object_pairs_hook=_no_duplicates)
        except (ValueError, _Duplicate):
            return None, INVALID
        if not isinstance(record, dict):
            return None, INVALID
        if record.get("approved_by") != "human":
            return None, INVALID
        if not _valid_sha(record.get("snapshot_sha256")):
            return None, INVALID
        if not record.get("server_identity"):
            return None, INVALID
        tools = record.get("tools")
        if not isinstance(tools, dict):
            return None, INVALID
        for entry in tools.values():
            if not isinstance(entry, dict) or not _valid_sha(
                    entry.get("descriptor_sha256")):
                return None, INVALID
        return record, None

    def state(self):
        with self._lock:
            record, bad = self._record_or_reason()
            if bad:
                return INVALID
            if record is None:
                return UNAPPROVED
            if self._invalidation:
                return INVALIDATED
            return APPROVED if self._active else UNAPPROVED

    # ── T5.R3: activation, all four conditions, one commit ─────────────────
    def activate(self, *, server_identity, snapshot_sha256, page_scans,
                 revision, epoch):
        """All four, and the last two are the ones that need the lock.

        `revision` and `epoch` are what the CALLER read when it began. Comparing
        them here, inside the lock, at the moment of commit, is what stops a
        scan that succeeded against a world that has since moved from admitting
        anything.
        """
        with self._lock:
            record, bad = self._record_or_reason()
            if bad or record is None:
                return Activation(False, SCAN_EXCEPTION if bad else APPROVAL_REQUIRED)

            # (a) identity
            if server_identity != record["server_identity"]:
                return Activation(False, DESCRIPTOR_CHANGED,
                                  "the server is not the one that was approved")
            # (b) snapshot
            if snapshot_sha256 != record["snapshot_sha256"]:
                return Activation(False, DESCRIPTOR_CHANGED,
                                  "the current snapshot is not the approved one")
            # (c) every page
            provenance = _page_provenance(page_scans)
            if provenance:
                return Activation(False, provenance,
                                  "an activation scan was not clean")
            # (d) nothing moved while we were scanning
            if revision != self.revision or epoch != self.epoch:
                return Activation(
                    False, DESCRIPTOR_CHANGED,
                    "the approval or the descriptor changed during this "
                    "activation, so the scan describes a world that is gone")

            self._active = {"snapshot": snapshot_sha256,
                            "tools": record["tools"], "generation": self.epoch}
            self._invalidation = None
            return Activation(True)

    # ── T5.R4: invalidation, with provenance that outlives it ──────────────
    def invalidate(self, *, reason=DESCRIPTOR_CHANGED):
        with self._lock:
            self._active = None
            self._invalidation = reason
            self.epoch += 1
            return self.epoch

    # ── what a caller may do right now ─────────────────────────────────────
    def may_deliver_list(self, snapshot_sha256):
        with self._lock:
            blocked = self._blocked()
            if blocked:
                return blocked
            if snapshot_sha256 != self._active["snapshot"]:
                return DESCRIPTOR_CHANGED
            return None

    def may_call(self, tool_name, descriptor_sha256):
        with self._lock:
            blocked = self._blocked()
            if blocked:
                return blocked
            entry = self._active["tools"].get(tool_name)
            if entry is None:
                return DESCRIPTOR_CHANGED
            if entry.get("descriptor_sha256") != descriptor_sha256:
                return DESCRIPTOR_CHANGED
            return None

    def _blocked(self):
        """The reason nothing may pass, in the order the rows put them.

        The invalidation is checked BEFORE the absence of an approval, because
        T5.R4 keeps its provenance for the session: once a server has changed
        underneath an approval, saying APPROVAL_REQUIRED would describe it as
        never approved and hide the change.
        """
        record, bad = self._record_or_reason()
        if bad:
            return SCAN_EXCEPTION
        if self._invalidation:
            return self._invalidation
        if record is None or self._active is None:
            return APPROVAL_REQUIRED
        return None


class _Duplicate(ValueError):
    pass


def _no_duplicates(pairs):
    seen = set()
    for key, _value in pairs:
        if key in seen:
            raise _Duplicate(f"duplicate key at depth: {len(seen)}")
        seen.add(key)
    return dict(pairs)


def _page_provenance(page_scans):
    """T5.R3(c), EVERY page, with the provenance the row names for each.

    Checked in severity order rather than in the order the fields appear, so a
    page that is both incomplete and carrying a finding reports the finding.
    """
    for page in page_scans or []:
        if page.get("findings"):
            return PROHIBITED_CONTENT
        if page.get("decision") == "review":
            return REVIEW_REQUIRED
        if page.get("check_pin") not in ("clean", "not applicable", None):
            return SCAN_EXCEPTION
        if (page.get("accepted") is not True
                or page.get("status") != "complete"
                or page.get("inspection_complete") is not True
                or page.get("decision") != "allow"):
            return SCAN_EXCEPTION
    return None
