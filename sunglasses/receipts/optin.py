"""Whether the user opted into a signed log, and the key that signs it (R21).

The user opts in with `sunglasses receipts init`, which writes the key. From
then on a key that exists but cannot sign is a receipt failure, never a quiet
return to unsigned rows: the log would stop being signed at the moment nobody
is looking. So every way the key can be unusable is named here once, with the
one command that clears it, and the hook, the proxy and `--verify` all say the
same sentence.

Deleting the key is not turning signing off. `sunglasses receipts off` is
the only road back to unsigned rows, and it is written into the hook's chain
as that chain's last word, so "opted in" is: a key, or a hook chain whose last
word is not `receipts off`.

Answering "is there a key" imports nothing. The signing code is imported only
to load a key that is there, so an install without one never loads it; reading
the hook chain's last word needs only the wire format, never the crypto.
"""
from __future__ import annotations

import fcntl
import os
import pathlib
import time

from . import _fs, wire

KEY_DIR = "keys"
KEY_GLOB = "receipt-*.ed25519"
RETIRED_DIR = "retired"
EXTRA = "sunglasses[receipts]"
OFF = "sunglasses receipts off"
OFF_EVENT = "receipts_off"
HOOK_LOG = ("receipts", "hook")
SEGMENT_GLOB = "segment-*.chain"
_TAIL_BYTES = 1 << 16


class KeyUnusable(Exception):
    """The user opted in and the key cannot sign. The message names the cause
    and the command that clears it; it never carries key material."""


def has_key(home) -> bool:
    """R56: a key directory that cannot be listed is not "no key". Whether a
    key is there cannot be known, so the key cannot sign, said by name."""
    home = pathlib.Path(home)
    try:
        return bool(_fs.listing(home / KEY_DIR, KEY_GLOB))
    except _fs.Unlistable as unlistable:
        raise _key_dir_unlistable(home, unlistable) from None


def _key_dir_unlistable(home, unlistable) -> KeyUnusable:
    return KeyUnusable(
        f"the key directory {home / KEY_DIR} cannot be listed "
        f"({type(unlistable.cause).__name__}), so whether the key is there "
        f"cannot be known, and a signed log never turns unsigned on a guess. "
        f"Fix it: chmod 700 {home / KEY_DIR} (or `{OFF}` to stop signing)")


def signer(home):
    """The user's signer. Raises KeyUnusable, naming the cause, when the key is
    there and cannot be used, or when it is gone."""
    home = pathlib.Path(home)
    try:
        from . import keys
    except ImportError:
        raise KeyUnusable(
            f"the signing key in {home / KEY_DIR} needs {EXTRA}, which is not "
            f"installed. Install it: pip install '{EXTRA}' (or `{OFF}` to "
            f"stop signing)") from None
    try:
        path = keys.private_path(home)
        found = keys.load(home)
    except _fs.Unlistable as unlistable:
        raise _key_dir_unlistable(home, unlistable) from None
    except keys.KeyUnsafe:
        raise KeyUnusable(
            f"the signing key {path} is not private to you. Fix it: "
            f"chmod 600 {path} (or `{OFF}` to stop signing)") from None
    except (OSError, ValueError) as failed:
        raise KeyUnusable(
            f"the signing key {path} cannot be read ({type(failed).__name__}). "
            f"Fix it: chmod 600 {path} (or `{OFF}` to stop signing)") from None
    if found is None:
        raise KeyUnusable(
            f"the signing key is gone from {home / KEY_DIR}, and a signed log "
            f"never turns unsigned by itself. Restore the key, or run `{OFF}`")
    return found


def hook_log(home) -> pathlib.Path:
    return pathlib.Path(home).joinpath(*HOOK_LOG)


def opted_in(home) -> bool:
    """A key, or a hook chain whose last word is not `receipts off` (R21).

    Never False on a directory it could not list (R56): an unlistable key
    directory raises KeyUnusable, an unlistable hook chain raises
    _fs.Unlistable, and the caller's receipt-failure path answers."""
    return has_key(home) or _chain_open(hook_log(home))


def _chain_open(directory) -> bool:
    # T9 ruling 56: Path.glob read a chain nobody could list as no chain, so
    # a deleted key under an unlistable chain went quietly unsigned.
    segments = _fs.listing(directory, SEGMENT_GLOB)
    if not segments:
        return False
    # A tail that cannot be read is not an off record: it stays opted in, and
    # the key failure that follows says so, rather than going quietly unsigned.
    # T9 ruling 34: the comment said so and the read let the OSError out, which
    # took the hook down with exit 1 -- the one exit the host lets through.
    try:
        return _last_event(segments[-1]) != OFF_EVENT
    except OSError:
        return True


def _last_event(segment):
    """The event of the last complete record that is not a checkpoint."""
    with open(segment, "rb") as handle:
        size = handle.seek(0, os.SEEK_END)
        handle.seek(max(0, size - _TAIL_BYTES))
        data = handle.read()
    lines = data.split(b"\n")[:-1]              # the last piece is torn or empty
    if size > _TAIL_BYTES:
        lines = lines[1:]                        # the first may be cut in half
    for line in reversed(lines):
        try:
            record = wire.decode_strict(line + b"\n")
        except ValueError:
            return None
        if record.get("event") != "checkpoint":
            return record.get("event")
    return None


def turn_off(home) -> str:
    """`sunglasses receipts off`: record it, then retire the private key.

    With a key that signs, the off record is sealed by a close checkpoint. With
    one that cannot, it is an unsigned row after the last checkpoint, which the
    verifier reports as an unverified tail, because that is what it is. Either
    way the private key moves to keys/retired/ (never deleted) and the public
    key stays, so the chain still verifies. Returns "sealed", "unsigned" or
    "already off"."""
    home = pathlib.Path(home)
    if not opted_in(home):
        return "already off"
    directory = hook_log(home)
    try:
        usable = signer(home)
    except KeyUnusable:
        usable = None
    if usable is not None:
        from . import chain
        chain.Chain(directory, usable, producer="hook").write(
            [{"event": OFF_EVENT, "body": {}}], seal="close")
        done = "sealed"
    else:
        done = "unsigned" if _append_unsigned(directory) else "already off"
    _retire_key(home)
    return done


def _append_unsigned(directory) -> bool:
    """The off record as an unsigned row on the chain's last segment, linked
    to the record before it. Nothing here can sign. False when there is no
    chain to write it on."""
    segments = _fs.listing(directory, SEGMENT_GLOB)
    if not segments:
        return False
    fd = os.open(directory / "LOCK", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)          # the writer's lock (chain.py)
        path = _fs.listing(directory, SEGMENT_GLOB)[-1]
        data = path.read_bytes()
        if not data.endswith(b"\n"):
            raise ValueError(f"{path} ends in a torn record; nothing was appended")
        last_line = data[:-1].rsplit(b"\n", 1)[-1] + b"\n"
        last = wire.decode_strict(last_line)
        record = {"wire": wire.WIRE_VERSION, "chain_id": last["chain_id"],
                  "key_id": last["key_id"], "seq": last["seq"] + 1,
                  "prev_hash": wire.record_hash(last_line), "event": OFF_EVENT,
                  "producer": "hook", "t_wall_ns": time.time_ns(), "body": {}}
        out = os.open(path, os.O_WRONLY | os.O_APPEND)
        try:
            os.write(out, wire.encode(record))
            os.fsync(out)
        finally:
            os.close(out)
    finally:
        os.close(fd)
    return True


def _retire_key(home) -> None:
    retired = home / KEY_DIR / RETIRED_DIR
    for path in _fs.listing(home / KEY_DIR, KEY_GLOB):
        retired.mkdir(mode=0o700, exist_ok=True)
        target = retired / path.name
        n = 1
        while target.exists():
            n += 1
            target = retired / f"{path.name}.{n}"
        os.rename(path, target)
