"""The user's receipt key. T9 RULING 11 Q2.

ONLY `init` MAKES ONE. Loading never creates: a chain with no signer is all
unverified tail, and a file shaped like a chain with nothing able to sign it
invites the word "signed". So no key means no chain is written at all.

WHAT THE KEY PROTECTS, stated where the key is made (the docs repeat it
verbatim): anything that runs as the user can read a 0600 key and sign with it.
The signature protects a history against edits by someone WITHOUT the key, and
against rewriting anything before a checkpoint retained independently. It is
not protection against the user's own compromised account (LC01).

Layout under the home:
    keys/receipt-<fp16>.ed25519      raw 32-byte seed, 0600, in a 0700 dir
    keys/public/<fp>.pub             raw 32 public bytes, never overwritten

No key of ours ships in the package or signs a user's chain.
"""
from __future__ import annotations

import dataclasses
import os
import pathlib
import stat

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

try:
    from . import wire
except ImportError:
    import wire                        # type: ignore[no-redef]

KEY_DIR = "keys"
PUBLIC_DIR = "public"


class KeyExists(Exception):
    """A key or public key is already there. Nothing is overwritten."""


class KeyUnsafe(Exception):
    """The private key is readable by someone other than its owner."""


@dataclasses.dataclass(frozen=True)
class Signer:
    fingerprint: str
    _private: ed25519.Ed25519PrivateKey = dataclasses.field(repr=False)

    def sign(self, message: bytes) -> bytes:
        return self._private.sign(message)

    def verifies(self, message: bytes, signature_hex) -> bool:
        try:
            self._private.public_key().verify(bytes.fromhex(signature_hex), message)
        except (InvalidSignature, ValueError, TypeError):
            return False
        return True


def _key_dir(home) -> pathlib.Path:
    return pathlib.Path(home) / KEY_DIR


def _raw_public(private: ed25519.Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(serialization.Encoding.Raw,
                                             serialization.PublicFormat.Raw)


def private_path(home) -> pathlib.Path | None:
    found = sorted(_key_dir(home).glob("receipt-*.ed25519"))
    return found[0] if found else None


def public_path(home, fingerprint: str) -> pathlib.Path:
    return _key_dir(home) / PUBLIC_DIR / f"{fingerprint}.pub"


def public_key(home, fingerprint: str) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(
        public_path(home, fingerprint).read_bytes())


def _private_dir(path: pathlib.Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o700)


def _write_new(path: pathlib.Path, data: bytes, mode: int) -> None:
    """O_EXCL: a file that exists is never replaced, even in a race."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    except FileExistsError:
        raise KeyExists(str(path)) from None
    try:
        os.fchmod(fd, mode)
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def write_public(home, public_bytes: bytes, *, fingerprint: str) -> pathlib.Path:
    path = public_path(home, fingerprint)
    if path.exists():
        raise KeyExists(str(path))
    if wire.key_fingerprint(public_bytes) != fingerprint:
        raise ValueError("the public key does not have that fingerprint")
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_new(path, bytes(public_bytes), 0o644)
    return path


def init(home) -> str:
    """Make the user's key. Refuses if one exists; returns its fingerprint."""
    if private_path(home) is not None:
        raise KeyExists(str(private_path(home)))
    _private_dir(_key_dir(home))
    private = ed25519.Ed25519PrivateKey.generate()
    public = _raw_public(private)
    fingerprint = wire.key_fingerprint(public)
    seed = private.private_bytes(serialization.Encoding.Raw,
                                 serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())
    _write_new(_key_dir(home) / f"receipt-{fingerprint[:16]}.ed25519", seed, 0o600)
    write_public(home, public, fingerprint=fingerprint)
    return fingerprint


def load(home) -> Signer | None:
    """The user's signer, or None. Never creates anything."""
    path = private_path(home)
    if path is None:
        return None
    info = os.stat(path)
    if stat.S_IMODE(info.st_mode) & 0o077 or info.st_uid != os.getuid():
        raise KeyUnsafe(f"{path} must be 0600 and owned by this user")
    private = ed25519.Ed25519PrivateKey.from_private_bytes(path.read_bytes())
    return Signer(wire.key_fingerprint(_raw_public(private)), private)
