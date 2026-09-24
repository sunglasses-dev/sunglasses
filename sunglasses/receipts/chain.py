"""The receipt chain writer (spec §3-4). WHEN to seal is the producer's policy
(T9's A/B ruling); this module only guarantees what every policy relies on.

ONE WRITER AT A TIME. Every write holds `flock(LOCK_EX)` on the directory's
LOCK file around read-tail -> append -> (checkpoint) -> fsync, and re-reads the
tail on every hold: a long-lived writer never trusts the head it remembers.

NEVER SIGN WHAT YOU DID NOT WRITE. A checkpoint vouches for every record
before it, so the writer seals only an unsigned suffix it wrote itself, in this
process, ending at exactly the bytes it left. Anything else at the tail -- a
crashed writer's rows, another writer's rows, a torn line, bytes that do not
decode -- closes the segment UNTOUCHED, and a new segment opens whose genesis
names the old segment's last checkpoint and what was seen after it, as an
observation, never a vouch. The verifier still reports the old tail unverified.

NOTHING IS WRITTEN UNTIL EVERYTHING ENCODES. A batch is encoded and signed in
memory first, so a float or an over-long field refuses the whole batch and the
file is byte-identical afterwards.

DURABILITY. A data row is one unbuffered write. A checkpoint is fsynced with
its directory before the next record is written (WIRE_SPEC: the checkpoint at
100 is required before record 101).
"""
from __future__ import annotations

import contextlib
import dataclasses
import fcntl
import os
import pathlib
import secrets
import time

try:
    from . import wire
except ImportError:
    import wire                        # type: ignore[no-redef]

GENESIS = "genesis"
CHECKPOINT = "checkpoint"
SEGMENT_GLOB = "segment-*.chain"
PRODUCER_FIELDS = {"event", "body", "t_mono_ns"}
_CHUNK = 1 << 16


@dataclasses.dataclass
class _Tail:
    path: pathlib.Path
    chain_id: str | None
    seq: int              # of the last complete record
    head: str | None      # its hash
    size: int
    unsigned: int         # complete records after the last checkpoint
    torn: int             # bytes after the last LF
    damaged: bool         # a line that does not decode strictly
    last_checkpoint: tuple | None   # (seq, hash)


class Chain:
    def __init__(self, directory, signer, *, producer: str, interval: int = 100,
                 max_records: int = 1_000_000, max_bytes: int = 256 << 20,
                 clock=time.time_ns):
        if signer is None:
            raise ValueError("no key: no chain is written (spec §2)")
        self._dir = pathlib.Path(directory)
        self._signer = signer
        self._producer = producer
        self._interval = interval
        self._max_records = max_records
        self._max_bytes = max_bytes
        self._clock = clock
        # (path, size, head) at the end of OUR last write, while the unsigned
        # suffix there is ours. Anything else on disk is not ours to seal.
        self._mine = None

    # -- public ---------------------------------------------------------------

    def write(self, events, *, seal: str | None = None) -> None:
        events = [self._checked(event) for event in events]
        with self._locked():
            tail = self._continuable(self._read_tail())
            pieces, after = self._plan(tail, events, seal)
            if (tail.seq + 1 + after.records + 1 > self._max_records     # +1: the close
                    or tail.size + after.size > self._max_bytes):
                if tail.seq > 1:                  # a fresh segment takes it anyway
                    self._append(tail.path, self._plan(tail, [], "close")[0])
                    closed = self._read_tail()
                    tail = self._open_segment(previous=closed)
                    pieces, after = self._plan(tail, events, seal)
            self._append(tail.path, pieces)
            self._mine = ((tail.path, tail.size + after.size, after.head)
                          if after.unsigned else None)

    def seal(self, purpose: str) -> None:
        self.write([], seal=purpose)

    def close(self) -> None:
        self.seal("close")

    # -- the tail ---------------------------------------------------------------

    def _continuable(self, tail: _Tail | None) -> _Tail:
        if tail is None:
            return self._open_segment(previous=None)
        if tail.torn or tail.damaged:
            return self._open_segment(previous=tail)
        if tail.unsigned == 0:
            return tail
        if self._mine == (tail.path, tail.size, tail.head):
            return tail
        return self._open_segment(previous=tail)

    def _segments(self):
        return sorted(self._dir.glob(SEGMENT_GLOB))

    def _read_tail(self) -> _Tail | None:
        segments = self._segments()
        if not segments:
            return None
        path = segments[-1]
        with open(path, "rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            first = _first_line(handle)
            buffer, start = b"", size
            while True:
                lines, torn = _split_back(buffer, start == 0)
                found = max((i for i, (_, r) in enumerate(lines)
                             if r is not None and r.get("event") == CHECKPOINT),
                            default=None)      # the LAST checkpoint
                if found is not None or start == 0:
                    break
                step = min(_CHUNK, start)
                start -= step
                handle.seek(start)
                buffer = handle.read(step) + buffer
        try:
            chain_id = wire.decode_strict(first).get("chain_id") if first else None
        except ValueError:
            chain_id = None
        after = lines[found + 1:] if found is not None else lines
        last_line, last = lines[-1] if lines else (None, None)
        checkpoint = None
        if found is not None:
            line, record = lines[found]
            checkpoint = (record["seq"], wire.record_hash(line))
        return _Tail(path=path, chain_id=chain_id,
                     seq=last["seq"] if last else -1,
                     head=wire.record_hash(last_line) if last_line else None,
                     size=size, unsigned=len(after), torn=torn,
                     damaged=not lines or any(r is None for _, r in after),
                     last_checkpoint=checkpoint)

    def _open_segment(self, previous: _Tail | None) -> _Tail:
        segments = self._segments()
        number = int(segments[-1].stem.split("-")[1]) + 1 if segments else 1
        path = self._dir / f"segment-{number:06d}.chain"
        chain_id = secrets.token_hex(16)
        body = {}
        if previous is not None:
            seq, digest = previous.last_checkpoint or (None, None)
            body = {"previous": {"chain_id": previous.chain_id, "seq": seq,
                                 "hash": digest},
                    "observed_unsigned": previous.unsigned}
            if previous.torn:
                body["observed_torn_bytes"] = previous.torn
            if previous.damaged:
                body["observed_undecodable"] = True
        empty = _Tail(path=path, chain_id=chain_id, seq=-1, head=None, size=0,
                      unsigned=0, torn=0, damaged=False, last_checkpoint=None)
        genesis = {"wire": wire.WIRE_VERSION, "chain_id": chain_id,
                   "key_id": self._signer.fingerprint, "seq": wire.GENESIS_SEQ,
                   "prev_hash": wire.NULL_PREDECESSOR, "event": GENESIS,
                   "producer": self._producer, "t_wall_ns": self._clock(),
                   "body": body}
        line = wire.encode(genesis)
        opened = dataclasses.replace(empty, seq=0, head=wire.record_hash(line),
                                     size=len(line), unsigned=1)
        pieces, _ = self._plan(opened, [], GENESIS)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        self._append(path, [(line, False)] + pieces)
        return self._read_tail()

    # -- building and writing --------------------------------------------------

    def _checked(self, event: dict) -> dict:
        extra = set(event) - PRODUCER_FIELDS
        if extra:
            raise ValueError(f"envelope fields are the writer's: {sorted(extra)}")
        if not isinstance(event.get("event"), str) or event["event"] in (GENESIS, CHECKPOINT):
            raise ValueError("event must be a producer event name")
        if not isinstance(event.get("body", {}), dict):
            raise ValueError("body must be an object")
        return event

    def _plan(self, tail: _Tail, events, seal):
        """Every line this write adds, encoded and signed, and where it ends.
        Raises before anything is written."""
        pieces, seq, head, unsigned, size = [], tail.seq, tail.head, tail.unsigned, 0

        def add(record, is_checkpoint):
            nonlocal seq, head, unsigned, size
            line = wire.encode(record)
            pieces.append((line, is_checkpoint))
            seq, head, size = record["seq"], wire.record_hash(line), size + len(line)
            unsigned = 0 if is_checkpoint else unsigned + 1

        def checkpoint(purpose):
            record = {"chain_id": tail.chain_id, "covered_head": head,
                      "covered_seq": seq, "event": CHECKPOINT,
                      "interval": self._interval, "key_id": self._signer.fingerprint,
                      "prev_hash": head, "purpose": purpose, "seq": seq + 1,
                      "wire": wire.WIRE_VERSION}
            signature = self._signer.sign(wire.checkpoint_signing_bytes(record))
            add(dict(record, signature=signature.hex()), True)

        for event in events:
            record = {"wire": wire.WIRE_VERSION, "chain_id": tail.chain_id,
                      "key_id": self._signer.fingerprint, "seq": seq + 1,
                      "prev_hash": head, "event": event["event"],
                      "producer": self._producer, "t_wall_ns": self._clock(),
                      "body": event.get("body", {})}
            if "t_mono_ns" in event:
                record["t_mono_ns"] = event["t_mono_ns"]
            add(record, False)
            if unsigned >= self._interval:
                checkpoint("interval")
        if seal is not None and (unsigned or seal in (GENESIS, "close")):
            checkpoint(seal)
        return pieces, _After(records=len(pieces), size=size, head=head,
                              unsigned=unsigned)

    def _append(self, path, pieces) -> None:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
        try:
            for line, is_checkpoint in pieces:
                _write_all(fd, line)
                if is_checkpoint:
                    os.fsync(fd)
                    _fsync_dir(self._dir)
        finally:
            os.close(fd)

    @contextlib.contextmanager
    def _locked(self):
        self._dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self._dir / "LOCK", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)                   # closing releases the lock


@dataclasses.dataclass
class _After:
    records: int
    size: int
    head: str | None
    unsigned: int


def _write_all(fd, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[os.write(fd, view):]


def _fsync_dir(directory) -> None:
    fd = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _first_line(handle) -> bytes | None:
    handle.seek(0)
    line = handle.readline(1 << 20)
    handle.seek(0, os.SEEK_END)
    return line if line.endswith(b"\n") else None


def _split_back(buffer: bytes, at_start: bool):
    """(line, record-or-None) for each complete line in `buffer`, and the
    torn byte count. A line
    that does not decode strictly is kept with record None, never repaired."""
    cut = buffer.rfind(b"\n") + 1
    torn = len(buffer) - cut
    body = buffer[:cut]
    if not at_start:                   # the first piece may be a partial line
        first_lf = body.find(b"\n")
        if first_lf < 0:
            return [], torn
        body = body[first_lf + 1:]
    lines = []
    for line in body.splitlines(True):
        try:
            lines.append((line, wire.decode_strict(line)))
        except ValueError:
            lines.append((line, None))
    return lines, torn
