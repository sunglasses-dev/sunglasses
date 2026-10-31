"""Who approved what, and whether that approval is still true right now.

Written against `tests/test_proxy_approvals.py`.

The whole module exists for one sentence in contract row 5.3: the activation invariant is
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
import os
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
    __slots__ = ("activated", "provenance", "detail", "rule_ids")

    def __init__(self, activated, provenance=None, detail=None, rule_ids=()):
        self.activated = activated
        self.provenance = provenance
        self.detail = detail
        # THE IDS THE REFUSAL IS MADE OF. `_page_provenance` already holds the
        # findings when it decides PROHIBITED_CONTENT and used to drop them, so
        # an operator asking why a listing was refused got the reason code and
        # nothing else. A block that names no rule cannot be audited.
        self.rule_ids = list(rule_ids)

    def __repr__(self):
        return f"<Activation {'ok' if self.activated else self.provenance}>"


_HEX = frozenset("0123456789abcdefABCDEF")


def _valid_sha(value):
    """HEX, not merely alphanumeric.

    `isalnum` accepts `z` * 64, which is the right length and the right shape
    and is not a sha256 of anything. A record carrying one has not named a
    snapshot, and comparing it to a real digest can only ever be false, so it
    would sit there refusing every call for a reason nobody could read.
    """
    return (isinstance(value, str) and len(value) == _SHA
            and all(c in _HEX for c in value))


def _record_of(text):
    """The record in `text`, or the reason it is not one. The one validation: the Store and the
    read-only listings below all use it, so none of them can call a record approved that the
    Store would refuse."""
    # Duplicate keys first: `json.loads` keeps the last silently, and contract row 5.5
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


def current_folder():
    """The working directory, or None when it can no longer be read (the folder was deleted)."""
    try:
        return os.getcwd()
    except OSError:
        return None


def folder_text(folder):
    """A folder as a line may print it: never a name with a control character in it."""
    if not isinstance(folder, str) or not folder:
        return "unknown (recorded before folders were kept)"
    return folder if folder.isprintable() else "(a folder whose name has control characters)"


def other_folders(root, command_stem, here, limit=3):
    """Folders, other than `here`, that hold an approval for the same command and arguments.

    Read only. Printable folder names only, and at most `limit` of them: this feeds a line on
    the proxy's own stderr, which a person reads.
    """
    if not command_stem:
        return []
    found = []
    try:
        paths = sorted((pathlib.Path(root) / "approvals").glob("*.json"))
    except OSError:
        return []
    for path in paths:
        try:
            record, bad = _record_of(path.read_text())
        except (OSError, ValueError):   # ValueError: bytes that are not text
            continue
        if bad or record.get("command_stem") != command_stem:
            continue
        folder = record.get("folder")
        if (isinstance(folder, str) and folder.isprintable() and folder != here
                and folder not in found):
            found.append(folder)
        if len(found) >= limit:
            break
    return found


def _label(name):
    """A file name as a line may print it, shortened: never one with a control character in it."""
    name = name[:12]
    return name if name.isprintable() else "(a name with control characters)"


def approval_rows(root):
    """Every approval under `root`, read only: server, folder, snapshot and tool count.

    Looks and never writes or creates anything. A record that cannot be read, or that the Store
    would refuse, becomes a row that says so rather than a row that says APPROVED, and a folder
    that cannot be listed becomes one row saying so, so a listing never reads as "no approvals"
    over something it could not open. Only a folder that is not there is no approvals.
    """
    directory = pathlib.Path(root) / "approvals"
    try:
        names = sorted(name for name in os.listdir(directory) if name.endswith(".json"))
    except FileNotFoundError:
        return []
    except OSError:
        return [{"server": "(the approvals folder)", "state": "UNREADABLE", "folder": None,
                 "snapshot": None, "tools": None}]
    rows = []
    for name in names:
        server = _label(name[:-len(".json")])
        try:
            record, bad = _record_of((directory / name).read_text())
        except OSError:
            rows.append({"server": server, "state": "UNREADABLE", "folder": None,
                         "snapshot": None, "tools": None})
            continue
        except ValueError:   # bytes that are not text: not a record, as far as a listing goes
            rows.append({"server": server, "state": INVALID, "folder": None,
                         "snapshot": None, "tools": None})
            continue
        if bad:
            rows.append({"server": server, "state": INVALID, "folder": None,
                         "snapshot": None, "tools": None})
            continue
        rows.append({"server": server, "state": "APPROVED",
                     "folder": folder_text(record.get("folder")),
                     "snapshot": record["snapshot_sha256"][:12],
                     "tools": len(record["tools"])})
    return rows


class Store:
    """The record on disk, the state it implies, and the activation gate."""

    def __init__(self, root, *, server_id, command_stem=None):
        self.root = pathlib.Path(root)
        self.server_id = server_id
        # The identity without its folder: the same server started from another folder shares
        # it, which is how a refusal can say "approved, but from over there".
        self.command_stem = command_stem
        # The folder the proxy was started from, read once: it is the folder the identity was
        # made from, and it is still the right answer when that folder is deleted later.
        self.folder = current_folder()
        self.pending_snapshot = None
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

    # ── contract row 5.1: the human path is the only writer ───────────────────────────
    @property
    def _path(self):
        return self.approvals / f"{self.server_id}.json"

    def capture(self, snapshot_sha256, payload):
        """The capture the human is shown. Approval quotes this sha.

        It also records the folder the proxy was started from, because the server identity
        includes it: an approval is bound to that folder, and `proxy approve` and `doctor`
        say which one. The folder is not part of the sha a human approves.
        """
        if self.folder:
            payload = {**payload, "folder": self.folder}
        if self.command_stem:
            payload["command_stem"] = self.command_stem
        (self.captures / f"{self.server_id}.{snapshot_sha256}.json").write_text(
            json.dumps(payload, sort_keys=True))
        # REMEMBERED so a refusal can name it. `proxy approve` needs this sha,
        # and until it appeared in the APPROVAL_REQUIRED payload the only way to
        # learn it was to list this directory. In memory only and deliberately
        # so: the file on disk is the record, this is just the last thing we
        # showed, and it must not outlive the process that showed it.
        self.pending_snapshot = snapshot_sha256
        return snapshot_sha256

    def approve(self, *, snapshot_sha256, viewed):
        """After the human viewed EXACTLY that stored capture.

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
        # T504. RE-HASH what is on disk. The filename is a claim, not evidence:
        # anything that can write into the captures directory could otherwise
        # name a file after a sha whose contents it chose, and the approval
        # would record a human having viewed something they never saw.
        stored = json.loads(capture.read_text())
        # T504. A capture that CLAIMS tools must also carry the sha it was
        # taken under, and that sha must be the one being approved. The
        # filename is a claim rather than evidence: anything able to write into
        # the captures directory could otherwise name a file after a sha whose
        # contents it chose, and the record would say a human approved
        # descriptors they never saw.
        #
        # A capture claiming NO tools needs nothing re-derived, because there
        # is no descriptor in it to have been substituted. Approving it records
        # a true statement about a server with no tools.
        if stored.get("tools_by_name") and stored.get("sha256") != snapshot_sha256:
            raise NotApprovable(
                "the stored capture names descriptors but does not carry the "
                "sha it was taken under, so what a human viewed cannot be "
                "established")
        record = {
            "server_identity": self.server_id,
            "snapshot_sha256": snapshot_sha256,
            "approved_at": "recorded-by-the-approve-command",
            "approved_by": "human",
            # T505. NO FALLBACK. This used to invent `read_text_file` with a
            # made-up digest whenever the capture had no tools, which is an
            # approval record for a tool no human ever saw, written by us. An
            # empty tool list is a true statement about a server with no tools.
            "tools": stored.get("tools_by_name") or {},
        }
        if isinstance(stored.get("folder"), str):
            record["folder"] = stored["folder"]
        if isinstance(stored.get("command_stem"), str):
            record["command_stem"] = stored["command_stem"]
        with self._lock:
            self._path.write_text(json.dumps(record, sort_keys=True))
            # contract row 5.1 and T505. The record names which descriptors a human
            # approved, so anything that can rewrite it can approve on their
            # behalf.
            os.chmod(self._path, 0o600)
            self._write_pins(stored)
            self.revision += 1
            self._active = None
        return record

    def _write_pins(self, stored):
        """Approving PINS the descriptors, which is what approving means.

        Contract row 5.3(c) wants `check_pin` clean for every tool, and the helper's own
        trust-on-first-use path says so in its message: an unpinned tool asks,
        and approving is the act that pins it. Without this the two halves
        deadlock, because activation needs a clean pin and nothing ever writes
        one, so a human could approve a server for ever and never open the
        gate.

        The hash comes from the DESCRIPTORS in the capture, not from the
        snapshot's own digest: `check_pin` compares what a live descriptor
        hashes to, so a pin recorded under a different hash function would
        mismatch on the very next call and read as a tampered tool.
        """
        from .. import firewall

        # The two invariants of the approving-pins ruling.
        #
        # 1. The pins come from THIS capture, the one whose sha the record
        #    names. `stored` is the re-read file `approve` validated, so a
        #    second capture sitting in the directory (every `list_changed`
        #    writes one) is not reachable from here.
        # 2. A pin is only ever written for a tool the RECORD names. `pages`
        #    and `tools_by_name` are separate keys and nothing in the file
        #    format makes them agree, so a page could carry a descriptor the
        #    human's record never listed. Pinning it would make `check_pin`
        #    read clean for a tool nobody approved, which is an open gate with
        #    a clean receipt attached.
        approved_names = set(stored.get("tools_by_name") or {})
        tools = {}
        for page in stored.get("pages") or []:
            for tool in (page or {}).get("tools") or []:
                name = tool.get("name")
                if not isinstance(name, str) or name not in approved_names:
                    continue
                qualified = "mcp__%s__%s" % (self.server_id[:8], name)
                tools[qualified] = {"sha256": firewall.descriptor_hash(tool)}
        if not tools:
            return
        path = self.root / "pins.json"
        path.write_text(json.dumps({"tools": tools}, sort_keys=True))
        os.chmod(path, 0o600)

    def write_without_human(self, record):
        """The door that does not exist. Contract row 5.1 says the approve command only."""
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
        # `exists()` answers False on ANY OSError, so a
        # record in a directory that cannot be listed read as no record at
        # all: an approved server shown as never approved. Only "not there"
        # is absent; every other failure to look is unreadable.
        try:
            os.lstat(self._path)
        except FileNotFoundError:
            return None, None
        except OSError:
            return None, INVALID
        try:
            text = self._path.read_text()
        except OSError:
            # T507. An unreadable record is not an absent one. Letting the
            # OSError escape turns a hold into a crash in whatever was asking,
            # and contract row 5.5 says this state holds rather than decides.
            return None, INVALID
        return _record_of(text)

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

    # ── contract row 5.3: activation, all four conditions, one commit ─────────────────
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
                # T503. A reactivation that fails must not leave the PREVIOUS
                # admission standing. The whole point of re-activating is that
                # the world may have changed, and an activation that says no
                # while the old one keeps admitting calls has decided nothing.
                self._active = None
                return Activation(False, SCAN_EXCEPTION if bad else APPROVAL_REQUIRED)

            # (a) identity
            if server_identity != record["server_identity"]:
                self._retire(DESCRIPTOR_CHANGED)
                return Activation(False, DESCRIPTOR_CHANGED,
                                  "the server is not the one that was approved")
            # (b) snapshot
            if snapshot_sha256 != record["snapshot_sha256"]:
                self._retire(DESCRIPTOR_CHANGED)
                return Activation(False, DESCRIPTOR_CHANGED,
                                  "the current snapshot is not the approved one")
            # (c) every page
            provenance, rule_ids = _page_provenance(page_scans)
            if provenance:
                self._active = None
                return Activation(False, provenance,
                                  "an activation scan was not clean",
                                  rule_ids=rule_ids)
            # (d) nothing moved while we were scanning
            if revision != self.revision or epoch != self.epoch:
                self._retire(DESCRIPTOR_CHANGED)
                return Activation(
                    False, DESCRIPTOR_CHANGED,
                    "the approval or the descriptor changed during this "
                    "activation, so the scan describes a world that is gone")

            self._active = {"snapshot": snapshot_sha256,
                            "tools": record["tools"], "generation": self.epoch}
            self._invalidation = None
            return Activation(True)

    def _retire(self, reason):
        """Drop the admission AND remember why.

        Clearing `_active` alone makes the next call read as APPROVAL_REQUIRED,
        which describes a server nobody ever approved and hides that this one
        changed underneath an approval that existed. The provenance outlives
        the activation on purpose.
        """
        # Only a generation that EXISTED can be invalidated. contract row 5.4 names the
        # state "INVALIDATED (from gen N)", so claiming it where nothing was
        # ever activated reports a server that changed underneath an approval
        # it never had. That one stays UNAPPROVED.
        had_generation = self._active is not None
        self._active = None
        if had_generation:
            self._invalidation = reason

    # ── contract row 5.4: invalidation, with provenance that outlives it ──────────────
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
            # T502. The activation happened against a record that may have been
            # edited since, and a revocation is precisely an edit made without
            # asking us. Comparing the active snapshot to what is on disk NOW
            # is what makes revoking mean anything; without it the cached
            # activation outlives the approval that justified it.
            record, bad = self._record_or_reason()
            if bad or record is None:
                return SCAN_EXCEPTION if bad else APPROVAL_REQUIRED
            if record.get("snapshot_sha256") != self._active["snapshot"]:
                self._active = None
                return DESCRIPTOR_CHANGED
            entry = self._active["tools"].get(tool_name)
            if entry is None:
                return DESCRIPTOR_CHANGED
            if entry.get("descriptor_sha256") != descriptor_sha256:
                return DESCRIPTOR_CHANGED
            return None

    def _blocked(self):
        """The reason nothing may pass, in the order the rows put them.

        The invalidation is checked BEFORE the absence of an approval, because
        contract row 5.4 keeps its provenance for the session: once a server has changed
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
    """EVERY page, with the provenance contract row 5.3(c) names for each.

    Checked in severity order rather than in the order the fields appear, so a
    page that is both incomplete and carrying a finding reports the finding.

    Returns `(provenance, rule_ids)`. The ids are the ones on the page that
    DECIDED the refusal, not a union over every page: an operator needs to know
    which tool's description was prohibited, and merging them would name rules
    from pages that were clean.
    """
    if not page_scans:
        # T501. No pages is no evidence, and an activation with no evidence is
        # a snapshot nobody scanned. An empty list read as "nothing wrong" is
        # the vacuous pass this row exists to refuse.
        return SCAN_EXCEPTION, []
    for page in page_scans or []:
        if page.get("findings"):
            ids = sorted({f.get("rule_id") for f in page["findings"]
                          if f.get("rule_id")})
            return PROHIBITED_CONTENT, ids
        if page.get("decision") == "review":
            return REVIEW_REQUIRED, []
        if page.get("check_pin") != "clean":
            # contract row 5.3(c) wants the helper's pin outcome CLEAN for every tool.
            # None is "the helper never ran" and "not applicable" is "it
            # declined to answer"; neither is a clean pin, and treating them as
            # one activates on a check that did not happen.
            return SCAN_EXCEPTION, []
        if (page.get("accepted") is not True
                or page.get("status") != "complete"
                or page.get("inspection_complete") is not True
                or page.get("decision") != "allow"):
            return SCAN_EXCEPTION, []
    return None, []
